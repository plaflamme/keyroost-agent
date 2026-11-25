use std::sync::{Arc, Mutex};

use keyroost_openpgp::{
    self as pgp, AlgorithmAttributes, Curve, EccKind, KeyCrt, PW1_OTHER, PW1_SIGN, PublicKey,
};
use keyroost_transport::{OpenPgpSession, OpenPgpStatus, TransportError};
use sha2::Digest;
use ssh_agent_lib::{
    proto::{Identity, PublicCredential},
    ssh_key::{
        Algorithm, HashAlg, Mpint, Signature,
        public::{EcdsaPublicKey, Ed25519PublicKey, KeyData, RsaPublicKey},
        sec1::EncodedPoint,
    },
};

use crate::{
    ConnectionMode,
    pin_cache::{PinCache, verify_pin_with_cache},
    pinentry::{Applet, Pinentry, SystemPinentry},
};

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

struct PersistentOpenPgp<S = OpenPgpSession, St = OpenPgpStatus> {
    session: S,
    status: St,
}

struct PersistentSlot<S = OpenPgpSession, St = OpenPgpStatus> {
    state: Arc<Mutex<Option<PersistentOpenPgp<S, St>>>>,
}

impl<S, St> Clone for PersistentSlot<S, St> {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
        }
    }
}

impl<S, St> PersistentSlot<S, St> {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(None)),
        }
    }

    fn with_session<T, E>(
        &self,
        open: impl FnOnce() -> Result<(S, St), E>,
        is_fatal: impl Fn(&E) -> bool,
        f: impl FnOnce(&mut S, &St) -> Result<T, E>,
    ) -> Result<T, E> {
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.is_none() {
            let (session, status) = open()?;
            *guard = Some(PersistentOpenPgp { session, status });
        }
        let persistent = guard.as_mut().expect("persistent session initialized above");
        let result = f(&mut persistent.session, &persistent.status);
        if result.as_ref().err().is_some_and(is_fatal) {
            tracing::debug!("dropping persistent OpenPGP session after transport error");
            *guard = None;
        }
        result
    }

    fn disconnect(&self) {
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.take().is_some() {
            tracing::debug!("disconnected persistent OpenPGP session");
        }
    }
}

#[derive(Clone)]
enum OpenPgpBackend {
    Ephemeral,
    Persistent(PersistentSlot),
}

#[derive(Clone)]
pub(super) struct OpenPgpSshAgent {
    reader: String,
    pinentry: SystemPinentry,
    backend: OpenPgpBackend,
    pin_cache: Option<PinCache>,
}

impl OpenPgpSshAgent {
    pub(super) fn new(
        reader: String,
        pinentry: SystemPinentry,
        connection_mode: ConnectionMode,
        pin_cache: Option<PinCache>,
    ) -> Self {
        let backend = match connection_mode {
            ConnectionMode::Ephemeral => OpenPgpBackend::Ephemeral,
            ConnectionMode::Persistent => OpenPgpBackend::Persistent(PersistentSlot::new()),
        };

        Self {
            reader,
            pinentry,
            backend,
            pin_cache,
        }
    }

    pub(super) fn disconnect(&self) {
        if let OpenPgpBackend::Persistent(slot) = &self.backend {
            slot.disconnect();
        }
    }

    fn with_session<T>(
        &self,
        f: impl FnOnce(&mut OpenPgpSession, &OpenPgpStatus) -> Result<T, crate::Error>,
    ) -> Result<T, crate::Error> {
        match &self.backend {
            OpenPgpBackend::Ephemeral => {
                let mut session = OpenPgpSession::open(&self.reader)?;
                let status = session.status()?;
                f(&mut session, &status)
            }
            OpenPgpBackend::Persistent(slot) => slot.with_session(
                || {
                    let mut session = OpenPgpSession::open(&self.reader)?;
                    // Read status ONCE when the persistent session opens: on Token2 cards,
                    // `status()` performs a cross-applet OTP read which resets OpenPGP PIN state.
                    let status = session.status()?;
                    Ok((session, status))
                },
                crate::Error::is_transport_error,
                f,
            ),
        }
    }

    pub(super) fn request_identities(&self) -> Result<Vec<Identity>, crate::Error> {
        let mode = match self.backend {
            OpenPgpBackend::Ephemeral => ConnectionMode::Ephemeral,
            OpenPgpBackend::Persistent(_) => ConnectionMode::Persistent,
        };
        tracing::debug!(connection_mode = ?mode, "requesting OpenPGP identities");
        self.with_session(|session, status| {
            let identities = list_identities(session, status)?;
            Ok(identities
                .into_iter()
                .inspect(|id| tracing::info!("found usable OpenPGP identity on slot {:?}", id.slot))
                .map(Into::into)
                .collect())
        })
    }

    pub(super) fn sign(
        &self,
        public_credential: &PublicCredential,
        data: &[u8],
        rsa_sig_hash: Option<HashAlg>,
    ) -> Result<Option<Signature>, crate::Error> {
        self.with_session(|session, status| {
            let identity = list_identities(session, status)?
                .into_iter()
                .find(|id| &id.ssh_identity.credential == public_credential);

            let Some(identity) = identity else {
                tracing::debug!("no matching OpenPGP identity for requested public key");
                return Ok(None);
            };

            let prepared = prepare_sign_input(identity.attrs, data, rsa_sig_hash)?;
            let Some(signature) = sign_with_pin(
                session,
                identity.slot,
                &prepared,
                status.full_serial(),
                &self.pinentry,
                self.pin_cache.as_ref(),
            )?
            else {
                return Ok(None);
            };

            let signature = encode_signature(identity.attrs, &signature, rsa_sig_hash)?;
            Ok(Some(signature))
        })
    }
}

fn list_identities(
    session: &mut OpenPgpSession,
    status: &OpenPgpStatus,
) -> Result<Vec<OpenPgpIdentity>, crate::Error> {
    let mut identities = Vec::new();
    for slot in OPENPGP_SLOTS {
        match slot_to_ssh_identity(session, status, slot) {
            Ok(Some(identity)) => identities.push(identity),
            Ok(None) => {}
            Err(err) if err.is_transport_error() => return Err(err),
            Err(err) => {
                tracing::warn!("failed to configure slot {slot:?} as OpenPGP identity: {err}");
            }
        }
    }
    Ok(identities)
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

fn is_openpgp_wrong_pin(err: &TransportError) -> bool {
    matches!(
        err,
        TransportError::OpenPgpPinRejected {
            tries_remaining: Some(1..),
        } | TransportError::Apdu {
            sw1: 0x63,
            sw2: 0xC1..=0xCF,
            ..
        }
    )
}

fn sign_with_pin(
    signer: &mut impl OpenPgpSigner,
    slot: KeyCrt,
    prepared: &[u8],
    serial: Option<u128>,
    pinentry: &impl Pinentry,
    pin_cache: Option<&PinCache>,
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
            if !verify_pin_with_cache(
                Applet::OpenPgp,
                serial,
                true,
                pin_cache,
                pinentry,
                |pin| signer.verify_pin(pw_ref, pin),
                is_openpgp_wrong_pin,
            )? {
                return Ok(None);
            }
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
    use crate::{
        pin_cache::PinCache,
        pinentry::{Applet, Pinentry},
    };
    use keyroost_openpgp::{
        AlgorithmAttributes, Curve, EccKind, KeyCrt, PW1_OTHER, PW1_SIGN, PublicKey, RsaAttributes,
        RsaImportFormat,
    };
    use keyroost_transport::TransportError;
    use ssh_agent_lib::{
        proto::PublicCredential,
        secrecy::{ExposeSecret, SecretBox},
        ssh_key::{Algorithm, HashAlg},
    };
    use std::{cell::Cell, time::Duration};

    fn secret(pin: &str) -> SecretBox<str> {
        SecretBox::from(Box::<str>::from(pin))
    }

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

    type VerifyHandler = fn(&[u8]) -> Result<(), TransportError>;

    struct MockSigner {
        verified: bool,
        verified_refs: Vec<u8>,
        verified_pins: Vec<Vec<u8>>,
        signs: usize,
        authenticates: usize,
        result: Vec<u8>,
        error: Option<fn() -> TransportError>,
        verify_handler: VerifyHandler,
    }

    impl MockSigner {
        fn new(verified: bool, result: Vec<u8>) -> Self {
            Self {
                verified,
                verified_refs: Vec::new(),
                verified_pins: Vec::new(),
                signs: 0,
                authenticates: 0,
                result,
                error: None,
                verify_handler: |pin| {
                    if pin == b"123456" {
                        Ok(())
                    } else {
                        Err(TransportError::OpenPgpPinRejected {
                            tries_remaining: Some(2),
                        })
                    }
                },
            }
        }
    }

    impl OpenPgpSigner for MockSigner {
        fn verify_pin(&mut self, pw_ref: u8, pin: &[u8]) -> Result<(), TransportError> {
            self.verified_refs.push(pw_ref);
            self.verified_pins.push(pin.to_vec());
            (self.verify_handler)(pin)?;
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
        let res = sign_with_pin(
            &mut signer,
            KeyCrt::Sign,
            b"digest",
            Some(1234),
            &pinentry,
            None,
        )
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
            None,
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
        let res = sign_with_pin(
            &mut signer,
            KeyCrt::Sign,
            b"digest",
            Some(1234),
            &pinentry,
            None,
        )
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
        let res = sign_with_pin(
            &mut signer,
            KeyCrt::Auth,
            b"digest",
            Some(1234),
            &pinentry,
            None,
        )
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
        let res = sign_with_pin(
            &mut signer,
            KeyCrt::Auth,
            b"digest",
            Some(1234),
            &pinentry,
            None,
        )
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

        let err = sign_with_pin(
            &mut signer,
            KeyCrt::Auth,
            b"digest",
            Some(1234),
            &pinentry,
            None,
        )
        .unwrap_err();

        assert!(matches!(err, crate::Error::Other(_)));
        assert_eq!(pinentry.prompts(), 0);
        assert_eq!(signer.verified_refs, [] as [u8; 0]);
        assert_eq!(signer.signs, 0);
        assert_eq!(signer.authenticates, 1);
    }

    #[test]
    fn cache_miss_inserts_pin_and_second_sign_hits_cache_and_refreshes_ttl() {
        let cache = PinCache::new(Duration::from_secs(60), None);
        let pinentry = MockPinentry::new(Some("123456"));

        let mut signer1 = MockSigner::new(false, vec![1, 2, 3]);
        let res1 = sign_with_pin(
            &mut signer1,
            KeyCrt::Sign,
            b"digest",
            Some(1234),
            &pinentry,
            Some(&cache),
        )
        .unwrap();

        assert_eq!(res1, Some(vec![1, 2, 3]));
        assert_eq!(pinentry.prompts(), 1);
        assert_eq!(signer1.verified_refs, vec![PW1_SIGN]);
        assert_eq!(
            cache
                .get(Applet::OpenPgp, Some(1234))
                .as_ref()
                .map(ExposeSecret::expose_secret),
            Some("123456")
        );
        let expires_before = cache.expires_at(Applet::OpenPgp, Some(1234)).unwrap();

        std::thread::sleep(Duration::from_millis(2));

        // Second sign on Auth slot reuses the same cached PW1 PIN with 0 prompts.
        let mut signer2 = MockSigner::new(false, vec![4, 5, 6]);
        let res2 = sign_with_pin(
            &mut signer2,
            KeyCrt::Auth,
            b"digest",
            Some(1234),
            &pinentry,
            Some(&cache),
        )
        .unwrap();

        assert_eq!(res2, Some(vec![4, 5, 6]));
        assert_eq!(pinentry.prompts(), 1);
        assert_eq!(signer2.verified_refs, vec![PW1_OTHER]);
        assert_eq!(signer2.verified_pins, vec![b"123456".to_vec()]);
        let expires_after = cache.expires_at(Applet::OpenPgp, Some(1234)).unwrap();
        assert!(expires_after > expires_before);
    }

    #[test]
    fn fresh_prompt_verify_failure_does_not_cache_wrong_pin() {
        let cache = PinCache::new(Duration::from_secs(60), None);
        let pinentry = MockPinentry::new(Some("000000"));
        let mut signer = MockSigner::new(false, vec![1, 2, 3]);

        let err = sign_with_pin(
            &mut signer,
            KeyCrt::Auth,
            b"digest",
            Some(1234),
            &pinentry,
            Some(&cache),
        )
        .unwrap_err();

        assert!(matches!(err, crate::Error::Other(_)));
        assert_eq!(pinentry.prompts(), 1);
        assert_eq!(signer.verified_refs, vec![PW1_OTHER]);
        assert!(cache.get(Applet::OpenPgp, Some(1234)).is_none());
    }

    #[test]
    fn wrong_cached_pin_evicts_reprompts_and_caches_new_pin() {
        let wrong_pin_handlers: [VerifyHandler; 2] = [
            |pin| {
                if pin == b"123456" {
                    Ok(())
                } else {
                    Err(TransportError::OpenPgpPinRejected {
                        tries_remaining: Some(2),
                    })
                }
            },
            |pin| {
                if pin == b"123456" {
                    Ok(())
                } else {
                    Err(TransportError::Apdu {
                        label: "openpgp verify",
                        sw1: 0x63,
                        sw2: 0xC2,
                    })
                }
            },
        ];

        for handler in wrong_pin_handlers {
            let cache = PinCache::new(Duration::from_secs(60), None);
            cache.insert(Applet::OpenPgp, Some(1234), secret("stale1"));

            let pinentry = MockPinentry::new(Some("123456"));
            let mut signer = MockSigner::new(false, vec![9, 8, 7]);
            signer.verify_handler = handler;

            let res = sign_with_pin(
                &mut signer,
                KeyCrt::Auth,
                b"digest",
                Some(1234),
                &pinentry,
                Some(&cache),
            )
            .unwrap();

            assert_eq!(res, Some(vec![9, 8, 7]));
            assert_eq!(pinentry.prompts(), 1);
            assert_eq!(signer.verified_refs, vec![PW1_OTHER, PW1_OTHER]);
            assert_eq!(
                signer.verified_pins,
                vec![b"stale1".to_vec(), b"123456".to_vec()]
            );
            assert_eq!(
                cache
                    .get(Applet::OpenPgp, Some(1234))
                    .as_ref()
                    .map(ExposeSecret::expose_secret),
                Some("123456")
            );
        }
    }

    #[test]
    fn wrong_cached_pin_with_cancelled_reprompt_evicts_and_returns_none() {
        let cache = PinCache::new(Duration::from_secs(60), None);
        cache.insert(Applet::OpenPgp, Some(1234), secret("stale1"));

        let pinentry = MockPinentry::new(None);
        let mut signer = MockSigner::new(false, vec![9, 8, 7]);

        let res = sign_with_pin(
            &mut signer,
            KeyCrt::Sign,
            b"digest",
            Some(1234),
            &pinentry,
            Some(&cache),
        )
        .unwrap();

        assert_eq!(res, None);
        assert_eq!(pinentry.prompts(), 1);
        assert_eq!(signer.verified_refs, vec![PW1_SIGN]);
        assert!(cache.get(Applet::OpenPgp, Some(1234)).is_none());
    }

    #[test]
    fn non_wrong_pin_error_on_cache_hit_evicts_without_reprompting() {
        let fatal_handlers: [VerifyHandler; 5] = [
            |_| {
                Err(TransportError::OpenPgpPinRejected {
                    tries_remaining: Some(0),
                })
            },
            |_| {
                Err(TransportError::OpenPgpPinRejected {
                    tries_remaining: None,
                })
            },
            |_| {
                Err(TransportError::Apdu {
                    label: "openpgp verify",
                    sw1: 0x69,
                    sw2: 0x83,
                })
            },
            |_| {
                Err(TransportError::Apdu {
                    label: "openpgp verify",
                    sw1: 0x63,
                    sw2: 0xC0,
                })
            },
            |_| Err(TransportError::NoOpenPgpApplet),
        ];

        for handler in fatal_handlers {
            let cache = PinCache::new(Duration::from_secs(60), None);
            cache.insert(Applet::OpenPgp, Some(1234), secret("123456"));

            let pinentry = MockPinentry::new(Some("123456"));
            let mut signer = MockSigner::new(false, vec![9, 8, 7]);
            signer.verify_handler = handler;

            let err = sign_with_pin(
                &mut signer,
                KeyCrt::Auth,
                b"digest",
                Some(1234),
                &pinentry,
                Some(&cache),
            )
            .unwrap_err();

            assert!(matches!(err, crate::Error::Other(_)));
            assert_eq!(pinentry.prompts(), 0);
            assert_eq!(signer.verified_refs, vec![PW1_OTHER]);
            assert!(cache.get(Applet::OpenPgp, Some(1234)).is_none());
        }
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

    #[derive(Debug, PartialEq, Eq)]
    enum MockErr {
        App,
        Transport,
    }

    impl MockErr {
        fn is_transport(&self) -> bool {
            matches!(self, Self::Transport)
        }
    }

    struct MockSession {
        id: usize,
        active: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Drop for MockSession {
        fn drop(&mut self) {
            self.active
                .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[test]
    fn persistent_slot_lazily_opens_and_reads_status_once() {
        let slot = super::PersistentSlot::<MockSession, usize>::new();
        let active = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut opens = 0usize;

        let open = |opens: &mut usize| {
            *opens += 1;
            active.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok::<_, MockErr>((
                MockSession {
                    id: *opens,
                    active: std::sync::Arc::clone(&active),
                },
                *opens * 100,
            ))
        };

        let first = slot
            .with_session(
                || open(&mut opens),
                MockErr::is_transport,
                |sess, &status| Ok((sess.id, status)),
            )
            .unwrap();
        let second = slot
            .with_session(
                || open(&mut opens),
                MockErr::is_transport,
                |sess, &status| Ok((sess.id, status)),
            )
            .unwrap();

        assert_eq!(first, (1, 100));
        assert_eq!(second, (1, 100));
        assert_eq!(opens, 1);
        assert_eq!(active.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn persistent_slot_keeps_session_on_non_transport_error() {
        let slot = super::PersistentSlot::<MockSession, usize>::new();
        let active = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut opens = 0usize;

        let mut open_fn = || {
            opens += 1;
            active.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok::<_, MockErr>((
                MockSession {
                    id: opens,
                    active: std::sync::Arc::clone(&active),
                },
                opens,
            ))
        };

        assert_eq!(
            slot.with_session(&mut open_fn, MockErr::is_transport, |s, _| Ok(s.id)),
            Ok(1)
        );
        assert_eq!(
            slot.with_session(&mut open_fn, MockErr::is_transport, |_, _| Err::<usize, _>(
                MockErr::App
            )),
            Err(MockErr::App)
        );
        assert_eq!(
            slot.with_session(&mut open_fn, MockErr::is_transport, |s, _| Ok(s.id)),
            Ok(1)
        );
        assert_eq!(opens, 1);
    }

    #[test]
    fn persistent_slot_drops_and_reopens_session_on_transport_error() {
        let slot = super::PersistentSlot::<MockSession, usize>::new();
        let active = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut opens = 0usize;

        let mut open_fn = || {
            opens += 1;
            active.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok::<_, MockErr>((
                MockSession {
                    id: opens,
                    active: std::sync::Arc::clone(&active),
                },
                opens,
            ))
        };

        assert_eq!(
            slot.with_session(&mut open_fn, MockErr::is_transport, |s, _| Ok(s.id)),
            Ok(1)
        );
        assert_eq!(
            slot.with_session(&mut open_fn, MockErr::is_transport, |_, _| Err::<usize, _>(
                MockErr::Transport
            )),
            Err(MockErr::Transport)
        );
        assert_eq!(active.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(
            slot.with_session(&mut open_fn, MockErr::is_transport, |s, _| Ok(s.id)),
            Ok(2)
        );
        assert_eq!(opens, 2);
    }

    #[test]
    fn persistent_slot_disconnect_and_clone_share_state() {
        let slot1 = super::PersistentSlot::<MockSession, usize>::new();
        let slot2 = slot1.clone();
        let active = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let opens = Cell::new(0usize);

        let open_fn = || {
            let next = opens.get() + 1;
            opens.set(next);
            active.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok::<_, MockErr>((
                MockSession {
                    id: next,
                    active: std::sync::Arc::clone(&active),
                },
                next,
            ))
        };

        assert_eq!(
            slot1.with_session(open_fn, MockErr::is_transport, |s, _| Ok(s.id)),
            Ok(1)
        );
        assert_eq!(
            slot2.with_session(open_fn, MockErr::is_transport, |s, _| Ok(s.id)),
            Ok(1)
        );
        assert_eq!(opens.get(), 1);

        slot2.disconnect();
        assert_eq!(active.load(std::sync::atomic::Ordering::SeqCst), 0);

        assert_eq!(
            slot1.with_session(open_fn, MockErr::is_transport, |s, _| Ok(s.id)),
            Ok(2)
        );
        assert_eq!(opens.get(), 2);
    }
}
