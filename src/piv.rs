use keyroost_piv::{
    KeyAlg, PinPolicy, PublicKey, Slot,
    x509::{SigHash, X509Error},
};
use keyroost_transport::{PivSession, TransportError};
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

struct PivIdentity {
    slot: Slot,
    key_alg: KeyAlg,
    ssh_identity: Identity,
}

impl From<PivIdentity> for Identity {
    fn from(value: PivIdentity) -> Self {
        value.ssh_identity
    }
}

#[derive(Clone)]
pub(super) struct PivSshAgent {
    reader: String,
    slots: Vec<Slot>,
    pinentry: SystemPinentry,
}

impl PivSshAgent {
    // TODO: manually select slots
    pub(super) fn new(reader: String, pinentry: SystemPinentry) -> Self {
        // default signature-related slots
        let sign_slots: &[Slot] = &[
            Slot::Authentication,
            Slot::CardAuthentication,
            Slot::Signature,
        ];

        Self {
            reader,
            pinentry,
            slots: Vec::from_iter([sign_slots, &Slot::retired_all()].concat()),
        }
    }

    pub(super) fn request_identities(&self) -> Result<Vec<Identity>, crate::Error> {
        PivSession::with_transaction(&self.reader, |session| {
            let identities = self.list_identities(session);
            Ok(identities
                .into_iter()
                .inspect(|id| tracing::info!("found usable identity on slot {:?}", id.slot))
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
        PivSession::with_transaction(&self.reader, |session| {
            let piv_identity = self
                .list_identities(session)
                .into_iter()
                .find(|id| &id.ssh_identity.credential == public_credential);

            let Some(piv_identity) = piv_identity else {
                tracing::debug!("not matching PIV identity for requested public key");
                return Ok(None);
            };

            let sig_hash = match keyroost_piv::x509::signature_hash(piv_identity.key_alg) {
                Ok(sig_hash) => sig_hash,
                Err(X509Error::UnsupportedAlgorithm) => return Ok(None),
                Err(other) => return Err(crate::Error::Other(Box::new(other))),
            };

            let prepared = match sig_hash {
                SigHash::Sha256 => sha2::Sha256::digest(data).to_vec(),
                SigHash::Sha384 => sha2::Sha384::digest(data).to_vec(),
                SigHash::Sha512 => sha2::Sha512::digest(data).to_vec(),
                SigHash::None => data.to_vec(),
            };

            let pin_policy = session
                .slot_policy(piv_identity.slot)
                .map(|(pin, _touch)| pin);
            tracing::debug!("slot {:?} PIN policy: {:?}", piv_identity.slot, pin_policy);

            let serial = session.status().ok().and_then(|status| status.serial);

            let Some(signature) = sign_with_policy(
                session,
                piv_identity.slot,
                piv_identity.key_alg,
                &prepared,
                pin_policy,
                serial,
                &self.pinentry,
            )?
            else {
                return Ok(None);
            };

            let signature = match piv_identity.key_alg {
                KeyAlg::EccP256 => {
                    Signature::try_from(ecdsa::Signature::<p256::NistP256>::from_der(&signature)?)?
                }
                KeyAlg::EccP384 => {
                    Signature::try_from(ecdsa::Signature::<p384::NistP384>::from_der(&signature)?)?
                }
                KeyAlg::EccP521 => {
                    Signature::try_from(ecdsa::Signature::<p521::NistP521>::from_der(&signature)?)?
                }

                KeyAlg::Ed25519 => {
                    Signature::new(ssh_agent_lib::ssh_key::Algorithm::Ed25519, signature)?
                }
                KeyAlg::Rsa1024 | KeyAlg::Rsa2048 | KeyAlg::Rsa3072 | KeyAlg::Rsa4096 => {
                    let signature = match rsa_sig_hash {
                        Some(HashAlg::Sha256) => sha2::Sha256::digest(signature).to_vec(),
                        Some(HashAlg::Sha512) => sha2::Sha512::digest(signature).to_vec(),
                        None => signature,
                        Some(other) => {
                            return Err(crate::Error::Other(
                                format!("Unsupported RSA hash algorithm {other}").into(),
                            ));
                        }
                    };
                    Signature::new(Algorithm::Rsa { hash: rsa_sig_hash }, signature)?
                }
                KeyAlg::X25519 => {
                    return Err(crate::Error::Other(
                        "Unsupported signature algorithm X25519".into(),
                    ));
                }
            };

            Ok(Some(signature))
        })
    }

    fn list_identities<'a: 'b, 'b>(
        &'a self,
        session: &'b mut PivSession,
    ) -> impl Iterator<Item = PivIdentity> + 'b {
        self.slots.iter().filter_map(|slot| {
            slot_to_ssh_identity(session, *slot)
                .inspect_err(|e| {
                    tracing::warn!("failed to configure slot {slot:?} as PIV identity: {e}");
                })
                .ok()
                .flatten()
        })
    }
}

fn slot_to_ssh_identity(
    session: &mut PivSession,
    slot: Slot,
) -> Result<Option<PivIdentity>, crate::Error> {
    let Some(cert) = session.read_certificate(slot)? else {
        return Ok(None);
    };

    let (key_alg, public_key) = keyroost_piv::x509_parse::parse_certificate_public_key(&cert)?;

    let comment = if let Some(serial) = session.status().ok().and_then(|status| status.serial) {
        format!("PIV {serial}:{slot:?}")
    } else {
        format!("PIV {slot:?}")
    };
    Ok(Some(PivIdentity {
        slot,
        key_alg,
        ssh_identity: Identity {
            credential: ssh_public_credentials(key_alg, public_key)?,
            comment,
        },
    }))
}

fn ssh_public_credentials(
    key_alg: KeyAlg,
    public_key: PublicKey,
) -> Result<PublicCredential, crate::Error> {
    let key_data = match public_key {
        PublicKey::Rsa { modulus, exponent } => KeyData::Rsa(RsaPublicKey {
            n: Mpint::from_bytes(&modulus)?,
            e: Mpint::from_bytes(&exponent)?,
        }),
        PublicKey::Ecc { point } => match key_alg {
            KeyAlg::EccP256 => {
                KeyData::Ecdsa(EcdsaPublicKey::NistP256(EncodedPoint::from_bytes(&point)?))
            }
            KeyAlg::EccP384 => {
                KeyData::Ecdsa(EcdsaPublicKey::NistP384(EncodedPoint::from_bytes(&point)?))
            }
            KeyAlg::EccP521 => {
                KeyData::Ecdsa(EcdsaPublicKey::NistP521(EncodedPoint::from_bytes(&point)?))
            }
            KeyAlg::Ed25519 => KeyData::Ed25519(Ed25519PublicKey::try_from(point.as_slice())?),
            KeyAlg::Rsa1024 | KeyAlg::Rsa2048 | KeyAlg::Rsa3072 | KeyAlg::Rsa4096 => {
                return Err(crate::Error::Other(
                    format!("Invalid KeyAlg {key_alg:?} and for PublicKey::Ecc").into(),
                ));
            }
            KeyAlg::X25519 => {
                // NOTE: this is technically unreachable because keyroost_piv::x509::signature_hash will already have returned "not supported"
                return Err(crate::Error::SshKey(
                    ssh_agent_lib::ssh_key::Error::AlgorithmUnknown,
                ));
            }
        },
    };
    Ok(PublicCredential::Key(key_data))
}

trait PivSigner {
    fn verify_pin(&mut self, pin: &[u8]) -> Result<(), TransportError>;
    fn sign(&mut self, slot: Slot, alg: KeyAlg, prepared: &[u8])
    -> Result<Vec<u8>, TransportError>;
}

impl PivSigner for PivSession<'_> {
    fn verify_pin(&mut self, pin: &[u8]) -> Result<(), TransportError> {
        Self::verify_pin(self, pin)
    }

    fn sign(
        &mut self,
        slot: Slot,
        alg: KeyAlg,
        prepared: &[u8],
    ) -> Result<Vec<u8>, TransportError> {
        Self::sign(self, slot, alg, prepared)
    }
}

fn sign_with_policy(
    signer: &mut impl PivSigner,
    slot: Slot,
    alg: KeyAlg,
    prepared: &[u8],
    pin_policy: Option<PinPolicy>,
    serial: Option<u128>,
    pinentry: &impl Pinentry,
) -> Result<Option<Vec<u8>>, crate::Error> {
    match pin_policy {
        Some(PinPolicy::Never) => Ok(Some(signer.sign(slot, alg, prepared)?)),
        Some(PinPolicy::Always) => {
            let Some(pin) = pinentry.prompt_pin(Applet::Piv, serial)? else {
                return Ok(None);
            };
            signer.verify_pin(pin.expose_secret().as_bytes())?;
            Ok(Some(signer.sign(slot, alg, prepared)?))
        }
        Some(PinPolicy::Once | PinPolicy::Default) | None => match signer.sign(slot, alg, prepared)
        {
            Ok(signature) => Ok(Some(signature)),
            Err(TransportError::PivSecurityNotSatisfied) => {
                let Some(pin) = pinentry.prompt_pin(Applet::Piv, serial)? else {
                    return Ok(None);
                };
                signer.verify_pin(pin.expose_secret().as_bytes())?;
                Ok(Some(signer.sign(slot, alg, prepared)?))
            }
            Err(err) => Err(err.into()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{PivSigner, sign_with_policy};
    use crate::pinentry::{Applet, Pinentry};
    use keyroost_piv::{KeyAlg, PinPolicy, Slot};
    use keyroost_transport::TransportError;
    use ssh_agent_lib::secrecy::SecretBox;
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
        verifies: usize,
        signs: usize,
        sign_result: Vec<u8>,
        sign_error: Option<fn() -> TransportError>,
    }

    impl MockSigner {
        fn new(verified: bool, sign_result: Vec<u8>) -> Self {
            Self {
                verified,
                verifies: 0,
                signs: 0,
                sign_result,
                sign_error: None,
            }
        }
    }

    impl PivSigner for MockSigner {
        fn verify_pin(&mut self, pin: &[u8]) -> Result<(), TransportError> {
            assert_eq!(pin, b"123456");
            self.verifies += 1;
            self.verified = true;
            Ok(())
        }

        fn sign(
            &mut self,
            _slot: Slot,
            _alg: KeyAlg,
            _prepared: &[u8],
        ) -> Result<Vec<u8>, TransportError> {
            self.signs += 1;
            if let Some(err) = self.sign_error {
                return Err(err());
            }
            if !self.verified {
                return Err(TransportError::PivSecurityNotSatisfied);
            }
            Ok(self.sign_result.clone())
        }
    }

    #[test]
    fn never_policy_signs_without_prompting_or_verifying() {
        let mut signer = MockSigner::new(true, vec![1, 2, 3]);
        let pinentry = MockPinentry::new(Some("123456"));

        let res = sign_with_policy(
            &mut signer,
            Slot::CardAuthentication,
            KeyAlg::EccP256,
            b"msg",
            Some(PinPolicy::Never),
            Some(1234),
            &pinentry,
        )
        .unwrap();

        assert_eq!(res, Some(vec![1, 2, 3]));
        assert_eq!(pinentry.prompts(), 0);
        assert_eq!(signer.verifies, 0);
        assert_eq!(signer.signs, 1);
    }

    #[test]
    fn always_policy_always_prompts_and_verifies_before_signing() {
        let mut signer = MockSigner::new(true, vec![4, 5, 6]);
        let pinentry = MockPinentry::new(Some("123456"));

        let res = sign_with_policy(
            &mut signer,
            Slot::Signature,
            KeyAlg::EccP256,
            b"msg",
            Some(PinPolicy::Always),
            Some(1234),
            &pinentry,
        )
        .unwrap();

        assert_eq!(res, Some(vec![4, 5, 6]));
        assert_eq!(pinentry.prompts(), 1);
        assert_eq!(signer.verifies, 1);
        assert_eq!(signer.signs, 1);
    }

    #[test]
    fn always_policy_returns_none_when_prompt_cancelled() {
        let mut signer = MockSigner::new(false, vec![4, 5, 6]);
        let pinentry = MockPinentry::new(None);

        let res = sign_with_policy(
            &mut signer,
            Slot::Signature,
            KeyAlg::EccP256,
            b"msg",
            Some(PinPolicy::Always),
            Some(1234),
            &pinentry,
        )
        .unwrap();

        assert_eq!(res, None);
        assert_eq!(signer.verifies, 0);
        assert_eq!(signer.signs, 0);
    }

    #[test]
    fn once_policy_skips_prompt_when_already_verified() {
        let mut signer = MockSigner::new(true, vec![7, 8, 9]);
        let pinentry = MockPinentry::new(Some("123456"));

        let res = sign_with_policy(
            &mut signer,
            Slot::Authentication,
            KeyAlg::EccP256,
            b"msg",
            Some(PinPolicy::Once),
            Some(1234),
            &pinentry,
        )
        .unwrap();

        assert_eq!(res, Some(vec![7, 8, 9]));
        assert_eq!(pinentry.prompts(), 0);
        assert_eq!(signer.verifies, 0);
        assert_eq!(signer.signs, 1);
    }

    #[test]
    fn once_policy_prompts_and_verifies_when_security_not_satisfied() {
        let mut signer = MockSigner::new(false, vec![10, 11, 12]);
        let pinentry = MockPinentry::new(Some("123456"));

        let res = sign_with_policy(
            &mut signer,
            Slot::Authentication,
            KeyAlg::EccP256,
            b"msg",
            Some(PinPolicy::Once),
            Some(1234),
            &pinentry,
        )
        .unwrap();

        assert_eq!(res, Some(vec![10, 11, 12]));
        assert_eq!(pinentry.prompts(), 1);
        assert_eq!(signer.verifies, 1);
        assert_eq!(signer.signs, 2);
    }

    #[test]
    fn once_policy_returns_none_when_prompt_cancelled() {
        let mut signer = MockSigner::new(false, vec![10, 11, 12]);
        let pinentry = MockPinentry::new(None);

        let res = sign_with_policy(
            &mut signer,
            Slot::Authentication,
            KeyAlg::EccP256,
            b"msg",
            Some(PinPolicy::Once),
            Some(1234),
            &pinentry,
        )
        .unwrap();

        assert_eq!(res, None);
        assert_eq!(signer.verifies, 0);
        assert_eq!(signer.signs, 1);
    }

    #[test]
    fn missing_and_default_policy_fall_back_safely() {
        for policy in [None, Some(PinPolicy::Default)] {
            let mut signer = MockSigner::new(false, vec![42]);
            let pinentry = MockPinentry::new(Some("123456"));

            let res = sign_with_policy(
                &mut signer,
                Slot::Authentication,
                KeyAlg::EccP256,
                b"msg",
                policy,
                Some(1234),
                &pinentry,
            )
            .unwrap();
            assert_eq!(res, Some(vec![42]));
            assert_eq!(pinentry.prompts(), 1);
            assert_eq!(signer.verifies, 1);
            assert_eq!(signer.signs, 2);

            let mut signer_cached = MockSigner::new(true, vec![43]);
            let pinentry_cached = MockPinentry::new(Some("123456"));
            let res_cached = sign_with_policy(
                &mut signer_cached,
                Slot::Authentication,
                KeyAlg::EccP256,
                b"msg",
                policy,
                Some(1234),
                &pinentry_cached,
            )
            .unwrap();
            assert_eq!(res_cached, Some(vec![43]));
            assert_eq!(pinentry_cached.prompts(), 0);
            assert_eq!(signer_cached.verifies, 0);
            assert_eq!(signer_cached.signs, 1);
        }
    }

    #[test]
    fn once_policy_propagates_non_security_sign_errors_without_prompting() {
        let mut signer = MockSigner::new(false, vec![]);
        signer.sign_error = Some(|| TransportError::PivBadPinLength);
        let pinentry = MockPinentry::new(Some("123456"));

        let err = sign_with_policy(
            &mut signer,
            Slot::Authentication,
            KeyAlg::EccP256,
            b"msg",
            Some(PinPolicy::Once),
            Some(1234),
            &pinentry,
        )
        .unwrap_err();

        assert!(matches!(err, crate::Error::Other(_)));
        assert_eq!(pinentry.prompts(), 0);
        assert_eq!(signer.verifies, 0);
    }
}
