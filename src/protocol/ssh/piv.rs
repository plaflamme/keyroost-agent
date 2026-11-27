use keyroost_piv::{
    KeyAlg, PublicKey, Slot,
    x509::{SigHash, X509Error},
};
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
    card::{
        CardOperationOutcome,
        piv::{PivCard, PivKeyInfo},
    },
    protocol::ssh::cache::{PivCachedIdentity, SignOutcome, SignResult},
};

#[derive(Clone)]
pub(crate) struct PivSshFrontend {
    card: PivCard,
}

impl PivSshFrontend {
    pub(crate) fn new(card: PivCard) -> Self {
        Self { card }
    }

    pub(crate) async fn disconnect(&self) {
        self.card.disconnect().await;
    }

    pub(crate) fn probe_identities(
        reader: &str,
        slots: Option<Vec<Slot>>,
    ) -> Result<bool, crate::Error> {
        let keys = PivCard::list_keys_ephemeral(reader, slots)?;
        Ok(keys.into_iter().any(|key| key_to_identity(key).is_ok()))
    }

    pub(crate) async fn request_identities_with_metadata(
        &self,
    ) -> Result<Vec<(Identity, PivCachedIdentity)>, crate::Error> {
        let keys = self.card.list_keys().await?;
        Ok(keys_to_identities(keys))
    }

    pub(crate) async fn sign(
        &self,
        public_credential: &PublicCredential,
        cached: Option<PivCachedIdentity>,
        data: &[u8],
        rsa_sig_hash: Option<HashAlg>,
    ) -> Result<SignResult<PivCachedIdentity>, crate::Error> {
        if let Some(cached) = cached {
            let Some(prepared) = prepare_sign_input(cached.key_alg, data)? else {
                return Ok(SignResult {
                    discovered: None,
                    outcome: SignOutcome::NotFound,
                });
            };
            match self
                .card
                .sign_raw(
                    cached.slot,
                    cached.key_alg,
                    cached.serial,
                    &prepared,
                    None,
                    None,
                )
                .await
            {
                Ok(CardOperationOutcome::Completed(raw_sig)) => {
                    let signature = encode_signature(cached.key_alg, &raw_sig, rsa_sig_hash)?;
                    return Ok(SignResult {
                        discovered: None,
                        outcome: SignOutcome::Signed(signature),
                    });
                }
                Ok(CardOperationOutcome::UserCancelled) => {
                    return Ok(SignResult {
                        discovered: None,
                        outcome: SignOutcome::UserCancelled,
                    });
                }
                Ok(CardOperationOutcome::NotFound) => {
                    tracing::debug!(
                        slot = ?cached.slot,
                        "cached PIV slot sign reported stale card/slot; re-scanning"
                    );
                }
                Err(err) if err.is_transport_error() => {
                    tracing::debug!(
                        "cached PIV sign hit transport error, retrying with fresh scan: {err}"
                    );
                }
                Err(err) => return Err(err),
            }
        }

        let keys = self.card.refresh_and_list_keys().await?;
        let identities = keys_to_identities(keys);
        let discovered: Vec<(PublicCredential, PivCachedIdentity)> = identities
            .iter()
            .map(|(id, meta)| (id.credential.clone(), *meta))
            .collect();

        let matched = identities
            .into_iter()
            .find(|(id, _)| &id.credential == public_credential);

        let Some((_, meta)) = matched else {
            tracing::debug!("no matching PIV identity for requested public key");
            return Ok(SignResult {
                discovered: Some(discovered),
                outcome: SignOutcome::NotFound,
            });
        };

        let Some(prepared) = prepare_sign_input(meta.key_alg, data)? else {
            return Ok(SignResult {
                discovered: Some(discovered),
                outcome: SignOutcome::NotFound,
            });
        };

        let outcome = match self
            .card
            .sign_raw(meta.slot, meta.key_alg, None, &prepared, None, None)
            .await?
        {
            CardOperationOutcome::Completed(raw_sig) => {
                SignOutcome::Signed(encode_signature(meta.key_alg, &raw_sig, rsa_sig_hash)?)
            }
            CardOperationOutcome::UserCancelled => SignOutcome::UserCancelled,
            CardOperationOutcome::NotFound => SignOutcome::NotFound,
        };

        Ok(SignResult {
            discovered: Some(discovered),
            outcome,
        })
    }
}

fn keys_to_identities(keys: Vec<PivKeyInfo>) -> Vec<(Identity, PivCachedIdentity)> {
    let mut identities = Vec::new();
    for key in keys {
        let slot = key.slot;
        match key_to_identity(key) {
            Ok(pair) => {
                tracing::info!("found usable identity on slot {:?}", slot);
                identities.push(pair);
            }
            Err(err) => {
                tracing::warn!("failed to configure slot {slot:?} as PIV identity: {err}");
            }
        }
    }
    identities
}

fn key_to_identity(key: PivKeyInfo) -> Result<(Identity, PivCachedIdentity), crate::Error> {
    let credential = ssh_public_credentials(key.key_alg, key.public_key)?;
    let comment = if let Some(serial) = key.serial {
        format!("PIV {serial}:{:?}", key.slot)
    } else {
        format!("PIV {:?}", key.slot)
    };
    let identity = Identity {
        credential,
        comment,
    };
    let meta = PivCachedIdentity {
        slot: key.slot,
        key_alg: key.key_alg,
        serial: key.serial,
    };
    Ok((identity, meta))
}

fn prepare_sign_input(key_alg: KeyAlg, data: &[u8]) -> Result<Option<Vec<u8>>, crate::Error> {
    let sig_hash = match keyroost_piv::x509::signature_hash(key_alg) {
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
    Ok(Some(prepared))
}

fn encode_signature(
    key_alg: KeyAlg,
    signature: &[u8],
    rsa_sig_hash: Option<HashAlg>,
) -> Result<Signature, crate::Error> {
    match key_alg {
        KeyAlg::EccP256 => Ok(Signature::try_from(
            ecdsa::Signature::<p256::NistP256>::from_der(signature)?,
        )?),
        KeyAlg::EccP384 => Ok(Signature::try_from(
            ecdsa::Signature::<p384::NistP384>::from_der(signature)?,
        )?),
        KeyAlg::EccP521 => Ok(Signature::try_from(
            ecdsa::Signature::<p521::NistP521>::from_der(signature)?,
        )?),
        KeyAlg::Ed25519 => Ok(Signature::new(Algorithm::Ed25519, signature.to_vec())?),
        KeyAlg::Rsa1024 | KeyAlg::Rsa2048 | KeyAlg::Rsa3072 | KeyAlg::Rsa4096 => {
            let signature = match rsa_sig_hash {
                Some(HashAlg::Sha256) => sha2::Sha256::digest(signature).to_vec(),
                Some(HashAlg::Sha512) => sha2::Sha512::digest(signature).to_vec(),
                None => signature.to_vec(),
                Some(other) => {
                    return Err(crate::Error::Other(
                        format!("Unsupported RSA hash algorithm {other}").into(),
                    ));
                }
            };
            Ok(Signature::new(
                Algorithm::Rsa { hash: rsa_sig_hash },
                signature,
            )?)
        }
        KeyAlg::X25519 => Err(crate::Error::Other(
            "Unsupported signature algorithm X25519".into(),
        )),
    }
}

fn ssh_public_credentials(
    key_alg: KeyAlg,
    public_key: PublicKey,
) -> Result<PublicCredential, crate::Error> {
    let key_data = match public_key {
        PublicKey::Rsa { modulus, exponent } => KeyData::Rsa(RsaPublicKey {
            n: Mpint::from_positive_bytes(&modulus)?,
            e: Mpint::from_positive_bytes(&exponent)?,
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
                return Err(crate::Error::SshKey(
                    ssh_agent_lib::ssh_key::Error::AlgorithmUnknown,
                ));
            }
        },
    };
    Ok(PublicCredential::Key(key_data))
}

#[cfg(test)]
mod tests {
    use super::ssh_public_credentials;
    use keyroost_piv::{KeyAlg, PublicKey};
    use ssh_agent_lib::{proto::PublicCredential, ssh_key::public::KeyData};

    #[test]
    fn rsa_public_key_with_msb_set_encodes_as_positive_mpint() {
        let mut modulus = vec![0x80; 256];
        modulus[255] = 0x01;
        let cred = ssh_public_credentials(
            KeyAlg::Rsa2048,
            PublicKey::Rsa {
                modulus: modulus.clone(),
                exponent: vec![0x01, 0x00, 0x01],
            },
        )
        .unwrap();

        let PublicCredential::Key(KeyData::Rsa(rsa)) = cred else {
            panic!("expected RSA key data");
        };
        assert_eq!(rsa.n.as_bytes()[0], 0x00);
        assert_eq!(rsa.n.as_positive_bytes(), Some(modulus.as_slice()));
        assert_eq!(rsa.e.as_positive_bytes(), Some([0x01, 0x00, 0x01].as_slice()));
    }
}
