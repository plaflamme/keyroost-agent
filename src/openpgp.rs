use keyroost_openpgp::{
    self as pgp, AlgorithmAttributes, Curve, EccKind, KeyCrt, PW1_OTHER, PW1_SIGN, PublicKey,
};
use keyroost_transport::{OpenPgpSession, OpenPgpStatus, TransportError};
use sha2::Digest;
use ssh_agent_lib::{
    proto::{Identity, PublicCredential},
    secrecy::ExposeSecret,
    ssh_key::{
        Algorithm, HashAlg, Mpint, Signature,
        public::{EcdsaPublicKey, Ed25519PublicKey, KeyData, RsaPublicKey},
        sec1::EncodedPoint,
    },
};

use crate::pinentry::{Applet, Pinentry, SystemPinentry};

const OPENPGP_SLOTS: [KeyCrt; 2] = [KeyCrt::Auth, KeyCrt::Sign];

// RFC 8017 §9.2 DER-encoded DigestInfo prefixes (without the digest bytes).
const SHA256_DIGEST_INFO_PREFIX: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];
const SHA512_DIGEST_INFO_PREFIX: &[u8] = &[
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
];

struct OpenPgpIdentity {
    slot: KeyCrt,
    attrs: AlgorithmAttributes,
    ssh_identity: Identity,
}

impl From<OpenPgpIdentity> for Identity {
    fn from(value: OpenPgpIdentity) -> Self {
        value.ssh_identity
    }
}

#[derive(Clone)]
pub(super) struct OpenPgpSshAgent {
    reader: String,
    pinentry: SystemPinentry,
}

impl OpenPgpSshAgent {
    pub(super) fn new(reader: String, pinentry: SystemPinentry) -> Self {
        Self { reader, pinentry }
    }

    pub(super) fn request_identities(&self) -> Result<Vec<Identity>, crate::Error> {
        let mut session = OpenPgpSession::open(&self.reader)?;
        let status = session.status()?;
        let identities = list_identities(&mut session, &status);
        Ok(identities
            .into_iter()
            .inspect(|id| tracing::info!("found usable OpenPGP identity on slot {:?}", id.slot))
            .map(Into::into)
            .collect())
    }

    pub(super) fn sign(
        &self,
        public_credential: &PublicCredential,
        data: &[u8],
        rsa_sig_hash: Option<HashAlg>,
    ) -> Result<Option<Signature>, crate::Error> {
        let mut session = OpenPgpSession::open(&self.reader)?;
        let status = session.status()?;

        let identity = list_identities(&mut session, &status)
            .into_iter()
            .find(|id| &id.ssh_identity.credential == public_credential);

        let Some(identity) = identity else {
            tracing::debug!("no matching OpenPGP identity for requested public key");
            return Ok(None);
        };

        let prepared = prepare_sign_input(identity.attrs, data, rsa_sig_hash)?;
        let Some(signature) = sign_with_pin(
            &mut session,
            identity.slot,
            &prepared,
            status.full_serial(),
            &self.pinentry,
        )?
        else {
            return Ok(None);
        };

        let signature = encode_signature(identity.attrs, &signature, rsa_sig_hash)?;
        Ok(Some(signature))
    }
}

fn list_identities<'a>(
    session: &'a mut OpenPgpSession,
    status: &'a OpenPgpStatus,
) -> impl Iterator<Item = OpenPgpIdentity> + 'a {
    OPENPGP_SLOTS.iter().filter_map(|&slot| {
        slot_to_ssh_identity(session, status, slot)
            .inspect_err(|e| {
                tracing::warn!("failed to configure slot {slot:?} as OpenPGP identity: {e}");
            })
            .ok()
            .flatten()
    })
}

fn slot_to_ssh_identity(
    session: &mut OpenPgpSession,
    status: &OpenPgpStatus,
    slot: KeyCrt,
) -> Result<Option<OpenPgpIdentity>, crate::Error> {
    let raw_attrs = match slot {
        KeyCrt::Sign => &status.sig_attrs,
        KeyCrt::Auth => &status.aut_attrs,
        KeyCrt::Decrypt => return Ok(None),
    };

    if raw_attrs.is_empty() {
        return Ok(None);
    }

    let attrs = match pgp::parse_algorithm_attributes(raw_attrs) {
        Ok(attrs) => attrs,
        Err(pgp::ParseError::UnsupportedAlgorithm) => return Ok(None),
        Err(err) => return Err(crate::Error::Other(Box::new(err))),
    };

    let public_key = match session.read_public_key(slot) {
        Ok(key) => key,
        Err(
            TransportError::OpenPgpParse(_)
            | TransportError::Apdu {
                sw1: 0x6A,
                sw2: 0x88,
                ..
            },
        ) => return Ok(None),
        Err(err) => return Err(err.into()),
    };

    let Some(credential) = ssh_public_credentials(attrs, public_key)? else {
        return Ok(None);
    };

    let comment = match status.serial() {
        Some(serial) => format!("OpenPGP {serial}:{slot:?}"),
        None => format!("OpenPGP {slot:?}"),
    };

    Ok(Some(OpenPgpIdentity {
        slot,
        attrs,
        ssh_identity: Identity {
            credential,
            comment,
        },
    }))
}

fn ssh_public_credentials(
    attrs: AlgorithmAttributes,
    public_key: PublicKey,
) -> Result<Option<PublicCredential>, crate::Error> {
    let key_data = match (attrs, public_key) {
        (AlgorithmAttributes::Rsa(_), PublicKey::Rsa { modulus, exponent }) => {
            KeyData::Rsa(RsaPublicKey {
                n: Mpint::from_bytes(&modulus)?,
                e: Mpint::from_bytes(&exponent)?,
            })
        }
        (
            AlgorithmAttributes::Ecc {
                kind: EccKind::EdDsa,
                curve: Curve::Ed25519,
                ..
            },
            PublicKey::Ecc { point },
        ) => KeyData::Ed25519(Ed25519PublicKey::try_from(point.as_slice())?),
        (
            AlgorithmAttributes::Ecc {
                kind: EccKind::Ecdsa,
                curve: Curve::NistP256,
                ..
            },
            PublicKey::Ecc { point },
        ) => KeyData::Ecdsa(EcdsaPublicKey::NistP256(EncodedPoint::from_bytes(&point)?)),
        (
            AlgorithmAttributes::Ecc {
                kind: EccKind::Ecdsa,
                curve: Curve::NistP384,
                ..
            },
            PublicKey::Ecc { point },
        ) => KeyData::Ecdsa(EcdsaPublicKey::NistP384(EncodedPoint::from_bytes(&point)?)),
        (
            AlgorithmAttributes::Ecc {
                kind: EccKind::Ecdsa,
                curve: Curve::NistP521,
                ..
            },
            PublicKey::Ecc { point },
        ) => KeyData::Ecdsa(EcdsaPublicKey::NistP521(EncodedPoint::from_bytes(&point)?)),
        _ => return Ok(None),
    };

    Ok(Some(PublicCredential::Key(key_data)))
}

fn prepare_sign_input(
    attrs: AlgorithmAttributes,
    data: &[u8],
    rsa_sig_hash: Option<HashAlg>,
) -> Result<Vec<u8>, crate::Error> {
    match attrs {
        AlgorithmAttributes::Rsa(_) => match rsa_sig_hash {
            Some(HashAlg::Sha256) => {
                let mut digest_info = Vec::with_capacity(SHA256_DIGEST_INFO_PREFIX.len() + 32);
                digest_info.extend_from_slice(SHA256_DIGEST_INFO_PREFIX);
                digest_info.extend_from_slice(&sha2::Sha256::digest(data));
                Ok(digest_info)
            }
            Some(HashAlg::Sha512) => {
                let mut digest_info = Vec::with_capacity(SHA512_DIGEST_INFO_PREFIX.len() + 64);
                digest_info.extend_from_slice(SHA512_DIGEST_INFO_PREFIX);
                digest_info.extend_from_slice(&sha2::Sha512::digest(data));
                Ok(digest_info)
            }
            Some(other) => Err(crate::Error::Other(
                format!("Unsupported RSA hash algorithm {other}").into(),
            )),
            None => Err(crate::Error::Other(
                "Legacy SHA-1 RSA signatures are not supported".into(),
            )),
        },
        AlgorithmAttributes::Ecc {
            kind: EccKind::EdDsa,
            curve: Curve::Ed25519,
            ..
        } => Ok(data.to_vec()),
        AlgorithmAttributes::Ecc {
            kind: EccKind::Ecdsa,
            curve: Curve::NistP256,
            ..
        } => Ok(sha2::Sha256::digest(data).to_vec()),
        AlgorithmAttributes::Ecc {
            kind: EccKind::Ecdsa,
            curve: Curve::NistP384,
            ..
        } => Ok(sha2::Sha384::digest(data).to_vec()),
        AlgorithmAttributes::Ecc {
            kind: EccKind::Ecdsa,
            curve: Curve::NistP521,
            ..
        } => Ok(sha2::Sha512::digest(data).to_vec()),
        AlgorithmAttributes::Ecc { kind, curve, .. } => Err(crate::Error::Other(
            format!("Unsupported OpenPGP signature algorithm: {kind:?} {curve:?}").into(),
        )),
    }
}

fn encode_signature(
    attrs: AlgorithmAttributes,
    signature: &[u8],
    rsa_sig_hash: Option<HashAlg>,
) -> Result<Signature, crate::Error> {
    match attrs {
        AlgorithmAttributes::Rsa(_) => Ok(Signature::new(
            Algorithm::Rsa { hash: rsa_sig_hash },
            signature.to_vec(),
        )?),
        AlgorithmAttributes::Ecc {
            kind: EccKind::EdDsa,
            curve: Curve::Ed25519,
            ..
        } => Ok(Signature::new(Algorithm::Ed25519, signature.to_vec())?),
        AlgorithmAttributes::Ecc {
            kind: EccKind::Ecdsa,
            curve: Curve::NistP256,
            ..
        } => {
            let sig = ecdsa::Signature::<p256::NistP256>::from_slice(signature)
                .or_else(|_| ecdsa::Signature::<p256::NistP256>::from_der(signature))?;
            Ok(Signature::try_from(sig)?)
        }
        AlgorithmAttributes::Ecc {
            kind: EccKind::Ecdsa,
            curve: Curve::NistP384,
            ..
        } => {
            let sig = ecdsa::Signature::<p384::NistP384>::from_slice(signature)
                .or_else(|_| ecdsa::Signature::<p384::NistP384>::from_der(signature))?;
            Ok(Signature::try_from(sig)?)
        }
        AlgorithmAttributes::Ecc {
            kind: EccKind::Ecdsa,
            curve: Curve::NistP521,
            ..
        } => {
            let sig = ecdsa::Signature::<p521::NistP521>::from_slice(signature)
                .or_else(|_| ecdsa::Signature::<p521::NistP521>::from_der(signature))?;
            Ok(Signature::try_from(sig)?)
        }
        AlgorithmAttributes::Ecc { kind, curve, .. } => Err(crate::Error::Other(
            format!("Unsupported OpenPGP signature algorithm: {kind:?} {curve:?}").into(),
        )),
    }
}

trait OpenPgpSigner {
    fn verify_pin(&mut self, pw_ref: u8, pin: &[u8]) -> Result<(), TransportError>;
    fn sign(&mut self, digest_info: &[u8]) -> Result<Vec<u8>, TransportError>;
    fn internal_authenticate(&mut self, auth_input: &[u8]) -> Result<Vec<u8>, TransportError>;
}

impl OpenPgpSigner for OpenPgpSession {
    fn verify_pin(&mut self, pw_ref: u8, pin: &[u8]) -> Result<(), TransportError> {
        Self::verify_pin(self, pw_ref, pin)
    }

    fn sign(&mut self, digest_info: &[u8]) -> Result<Vec<u8>, TransportError> {
        Self::sign(self, digest_info)
    }

    fn internal_authenticate(&mut self, auth_input: &[u8]) -> Result<Vec<u8>, TransportError> {
        Self::internal_authenticate(self, auth_input)
    }
}

fn attempt_sign(
    signer: &mut impl OpenPgpSigner,
    slot: KeyCrt,
    prepared: &[u8],
) -> Result<Vec<u8>, TransportError> {
    match slot {
        KeyCrt::Sign => signer.sign(prepared),
        KeyCrt::Auth => signer.internal_authenticate(prepared),
        KeyCrt::Decrypt => unreachable!(),
    }
}

fn sign_with_pin(
    signer: &mut impl OpenPgpSigner,
    slot: KeyCrt,
    prepared: &[u8],
    serial: Option<u128>,
    pinentry: &impl Pinentry,
) -> Result<Option<Vec<u8>>, crate::Error> {
    let pw_ref = match slot {
        KeyCrt::Sign => PW1_SIGN,
        KeyCrt::Auth => PW1_OTHER,
        KeyCrt::Decrypt => {
            return Err(crate::Error::Other(
                "OpenPGP decrypt slot cannot be used for signing".into(),
            ));
        }
    };

    match attempt_sign(signer, slot, prepared) {
        Ok(sig) => Ok(Some(sig)),
        Err(TransportError::Apdu {
            sw1: 0x69,
            sw2: 0x82,
            ..
        }) => {
            let Some(pin) = pinentry.prompt_pin(Applet::OpenPgp, serial)? else {
                return Ok(None);
            };
            signer.verify_pin(pw_ref, pin.expose_secret().as_bytes())?;
            Ok(Some(attempt_sign(signer, slot, prepared)?))
        }
        Err(err) => Err(err.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        OpenPgpSigner, encode_signature, prepare_sign_input, sign_with_pin, ssh_public_credentials,
    };
    use crate::pinentry::{Applet, Pinentry};
    use keyroost_openpgp::{
        AlgorithmAttributes, Curve, EccKind, KeyCrt, PW1_OTHER, PW1_SIGN, PublicKey, RsaAttributes,
        RsaImportFormat,
    };
    use keyroost_transport::TransportError;
    use ssh_agent_lib::{
        proto::PublicCredential,
        secrecy::SecretBox,
        ssh_key::{Algorithm, HashAlg},
    };
    use std::cell::Cell;

    struct MockPinentry {
        pin: Option<&'static str>,
        prompts: Cell<usize>,
    }

    impl MockPinentry {
        fn new(pin: Option<&'static str>) -> Self {
            Self {
                pin,
                prompts: Cell::new(0),
            }
        }

        fn prompts(&self) -> usize {
            self.prompts.get()
        }
    }

    impl Pinentry for MockPinentry {
        fn prompt_pin(
            &self,
            _applet: Applet,
            _serial: Option<u128>,
        ) -> Result<Option<SecretBox<str>>, crate::Error> {
            self.prompts.set(self.prompts.get() + 1);
            Ok(self
                .pin
                .map(|value| SecretBox::new(value.to_owned().into_boxed_str())))
        }
    }

    struct MockSigner {
        verified: bool,
        verified_refs: Vec<u8>,
        signs: usize,
        authenticates: usize,
        result: Vec<u8>,
        error: Option<fn() -> TransportError>,
    }

    impl MockSigner {
        fn new(verified: bool, result: Vec<u8>) -> Self {
            Self {
                verified,
                verified_refs: Vec::new(),
                signs: 0,
                authenticates: 0,
                result,
                error: None,
            }
        }
    }

    impl OpenPgpSigner for MockSigner {
        fn verify_pin(&mut self, pw_ref: u8, pin: &[u8]) -> Result<(), TransportError> {
            assert_eq!(pin, b"123456");
            self.verified_refs.push(pw_ref);
            self.verified = true;
            Ok(())
        }

        fn sign(&mut self, _digest_info: &[u8]) -> Result<Vec<u8>, TransportError> {
            self.signs += 1;
            if let Some(err) = self.error {
                return Err(err());
            }
            if !self.verified {
                return Err(TransportError::Apdu {
                    label: "PSO:CDS",
                    sw1: 0x69,
                    sw2: 0x82,
                });
            }
            Ok(self.result.clone())
        }

        fn internal_authenticate(&mut self, _auth_input: &[u8]) -> Result<Vec<u8>, TransportError> {
            self.authenticates += 1;
            if let Some(err) = self.error {
                return Err(err());
            }
            if !self.verified {
                return Err(TransportError::Apdu {
                    label: "INTERNAL AUTHENTICATE",
                    sw1: 0x69,
                    sw2: 0x82,
                });
            }
            Ok(self.result.clone())
        }
    }

    #[test]
    fn already_verified_card_signs_without_prompting() {
        let mut signer = MockSigner::new(true, vec![1, 2, 3]);
        let pinentry = MockPinentry::new(Some("123456"));
        let res = sign_with_pin(&mut signer, KeyCrt::Sign, b"digest", Some(1234), &pinentry)
            .unwrap();

        assert_eq!(res, Some(vec![1, 2, 3]));
        assert_eq!(pinentry.prompts(), 0);
        assert_eq!(signer.verified_refs, [] as [u8; 0]);
        assert_eq!(signer.signs, 1);
        assert_eq!(signer.authenticates, 0);

        let mut auth_signer = MockSigner::new(true, vec![4, 5, 6]);
        let auth_pinentry = MockPinentry::new(Some("123456"));
        let auth_res = sign_with_pin(
            &mut auth_signer,
            KeyCrt::Auth,
            b"digest",
            Some(1234),
            &auth_pinentry,
        )
        .unwrap();

        assert_eq!(auth_res, Some(vec![4, 5, 6]));
        assert_eq!(auth_pinentry.prompts(), 0);
        assert_eq!(auth_signer.verified_refs, [] as [u8; 0]);
        assert_eq!(auth_signer.signs, 0);
        assert_eq!(auth_signer.authenticates, 1);
    }

    #[test]
    fn sign_slot_verifies_pw1_sign_and_retries_pso_sign() {
        let mut signer = MockSigner::new(false, vec![1, 2, 3]);
        let pinentry = MockPinentry::new(Some("123456"));
        let res = sign_with_pin(&mut signer, KeyCrt::Sign, b"digest", Some(1234), &pinentry)
            .unwrap();

        assert_eq!(res, Some(vec![1, 2, 3]));
        assert_eq!(pinentry.prompts(), 1);
        assert_eq!(signer.verified_refs, vec![PW1_SIGN]);
        assert_eq!(signer.signs, 2);
        assert_eq!(signer.authenticates, 0);
    }

    #[test]
    fn auth_slot_verifies_pw1_other_and_retries_internal_authenticate() {
        let mut signer = MockSigner::new(false, vec![4, 5, 6]);
        let pinentry = MockPinentry::new(Some("123456"));
        let res = sign_with_pin(&mut signer, KeyCrt::Auth, b"digest", Some(1234), &pinentry)
            .unwrap();

        assert_eq!(res, Some(vec![4, 5, 6]));
        assert_eq!(pinentry.prompts(), 1);
        assert_eq!(signer.verified_refs, vec![PW1_OTHER]);
        assert_eq!(signer.signs, 0);
        assert_eq!(signer.authenticates, 2);
    }

    #[test]
    fn cancelled_pin_returns_none_without_verifying() {
        let mut signer = MockSigner::new(false, vec![7, 8, 9]);
        let pinentry = MockPinentry::new(None);
        let res = sign_with_pin(&mut signer, KeyCrt::Auth, b"digest", Some(1234), &pinentry)
            .unwrap();

        assert_eq!(res, None);
        assert_eq!(pinentry.prompts(), 1);
        assert_eq!(signer.verified_refs, [] as [u8; 0]);
        assert_eq!(signer.signs, 0);
        assert_eq!(signer.authenticates, 1);
    }

    #[test]
    fn non_security_error_propagates_without_prompting() {
        let mut signer = MockSigner::new(false, vec![]);
        signer.error = Some(|| TransportError::Apdu {
            label: "INTERNAL AUTHENTICATE",
            sw1: 0x6A,
            sw2: 0x88,
        });
        let pinentry = MockPinentry::new(Some("123456"));

        let err = sign_with_pin(&mut signer, KeyCrt::Auth, b"digest", Some(1234), &pinentry)
            .unwrap_err();

        assert!(matches!(err, crate::Error::Other(_)));
        assert_eq!(pinentry.prompts(), 0);
        assert_eq!(signer.verified_refs, [] as [u8; 0]);
        assert_eq!(signer.signs, 0);
        assert_eq!(signer.authenticates, 1);
    }

    #[test]
    fn ed25519_credential_and_signature_roundtrip() {
        let attrs = AlgorithmAttributes::Ecc {
            kind: EccKind::EdDsa,
            curve: Curve::Ed25519,
            import_with_public_key: false,
        };
        let cred = ssh_public_credentials(
            attrs,
            PublicKey::Ecc {
                point: vec![0x11; 32],
            },
        )
        .unwrap();
        assert!(matches!(cred, Some(PublicCredential::Key(_))));

        let prepared = prepare_sign_input(attrs, b"hello", None).unwrap();
        assert_eq!(prepared, b"hello");

        let sig = encode_signature(attrs, &[0x22; 64], None).unwrap();
        assert_eq!(sig.algorithm(), Algorithm::Ed25519);
    }

    #[test]
    fn rsa_digest_info_and_signature_encoding() {
        let attrs = AlgorithmAttributes::Rsa(RsaAttributes {
            n_bits: 2048,
            e_bits: 32,
            format: RsaImportFormat::Standard,
        });

        let sha256_input = prepare_sign_input(attrs, b"hello", Some(HashAlg::Sha256)).unwrap();
        assert_eq!(sha256_input.len(), 19 + 32);

        let sha512_input = prepare_sign_input(attrs, b"hello", Some(HashAlg::Sha512)).unwrap();
        assert_eq!(sha512_input.len(), 19 + 64);

        assert!(prepare_sign_input(attrs, b"hello", None).is_err());

        let sig = encode_signature(attrs, &[0xAA; 256], Some(HashAlg::Sha256)).unwrap();
        assert_eq!(
            sig.algorithm(),
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha256)
            }
        );
    }

    #[test]
    fn ecdsa_raw_rs_signature_is_encoded() {
        let attrs = AlgorithmAttributes::Ecc {
            kind: EccKind::Ecdsa,
            curve: Curve::NistP256,
            import_with_public_key: false,
        };

        let prepared = prepare_sign_input(attrs, b"hello", None).unwrap();
        assert_eq!(prepared.len(), 32);

        let mut raw_rs = vec![0x01; 32];
        raw_rs.extend_from_slice(&[0x02; 32]);
        let sig = encode_signature(attrs, &raw_rs, None).unwrap();
        assert_eq!(
            sig.algorithm(),
            Algorithm::Ecdsa {
                curve: ssh_agent_lib::ssh_key::EcdsaCurve::NistP256
            }
        );
    }

    #[test]
    fn ecdh_and_unsupported_curves_are_skipped() {
        let ecdh = AlgorithmAttributes::Ecc {
            kind: EccKind::Ecdh,
            curve: Curve::X25519,
            import_with_public_key: false,
        };
        let res = ssh_public_credentials(
            ecdh,
            PublicKey::Ecc {
                point: vec![0x33; 32],
            },
        )
        .unwrap();
        assert!(res.is_none());
    }
}
