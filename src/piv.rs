use keyroost_piv::{
    KeyAlg, PublicKey, Slot,
    x509::{SigHash, X509Error},
};
use keyroost_transport::PivSession;
use sha2::Digest;
use ssh_agent_lib::{
    proto::{Identity, PublicCredential},
    secrecy::{self, ExposeSecret},
    ssh_key::{
        Algorithm, HashAlg, Mpint, Signature,
        public::{EcdsaPublicKey, Ed25519PublicKey, KeyData, RsaPublicKey},
        sec1::EncodedPoint,
    },
};

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
    pinentry_binary: Option<String>,
}

impl PivSshAgent {
    // TODO: manually select slots
    pub(super) fn new(reader: String, pinentry_binary: Option<String>) -> Self {
        // default signature-related slots
        let sign_slots: &[Slot] = &[
            Slot::Authentication,
            Slot::CardAuthentication,
            Slot::Signature,
        ];

        Self {
            reader,
            pinentry_binary,
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

            // TODO: slot policy
            let Some(pin) = self.prompt_pin()? else {
                return Ok(None);
            };

            session.verify_pin(pin.expose_secret().as_bytes())?;

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

            let signature = session.sign(piv_identity.slot, piv_identity.key_alg, &prepared)?;

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

    fn prompt_pin(&self) -> Result<Option<secrecy::SecretBox<str>>, crate::Error> {
        let pinentry = match self.pinentry_binary.as_ref() {
            Some(binary_name) => pinentry::PassphraseInput::with_binary(binary_name),
            None => pinentry::PassphraseInput::with_default_binary(),
        };

        let Some(mut pinentry) = pinentry else {
            return Err(crate::Error::Other("pinentry binary not found".into()));
        };

        let pin = pinentry
            .with_prompt("PIN") // TODO: show card serial number
            .with_description("Please unlock the card")
            .required("PIN cannot be empty")
            .interact();

        match pin {
            Ok(pin) => Ok(Some(pin)),
            Err(pinentry::Error::Cancelled) => Ok(None),
            Err(other) => {
                tracing::warn!("pinentry failed {other}");
                Ok(None)
            }
        }
    }

    fn list_identities<'a: 'b, 'b>(
        &'a self,
        session: &'b mut PivSession,
    ) -> impl Iterator<Item = PivIdentity> + 'b {
        self.slots.iter().filter_map(|slot| {
            // TODO: deal with Err here, probably logging is sufficient
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

    Ok(Some(PivIdentity {
        slot,
        key_alg,
        ssh_identity: Identity {
            credential: ssh_public_credentials(key_alg, public_key)?,
            comment: format!("PIV {slot:?}"),
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
