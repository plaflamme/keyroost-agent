use keyroost_openpgp::{AlgorithmAttributes, Curve, EccKind, KeyCrt, PublicKey};
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
        openpgp::{OpenPgpCard, OpenPgpKeyInfo},
    },
    protocol::ssh::cache::{OpenPgpCachedIdentity, SignOutcome, SignResult},
};

const SSH_OPENPGP_SLOTS: [KeyCrt; 2] = [KeyCrt::Auth, KeyCrt::Sign];

// RFC 8017 §9.2 DER-encoded DigestInfo prefixes (without the digest bytes).
const SHA256_DIGEST_INFO_PREFIX: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];
const SHA512_DIGEST_INFO_PREFIX: &[u8] = &[
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
];

#[derive(Clone)]
pub(crate) struct OpenPgpSshFrontend {
    card: OpenPgpCard,
}

impl OpenPgpSshFrontend {
    pub(crate) fn new(card: OpenPgpCard) -> Self {
        Self { card }
    }

    pub(crate) async fn disconnect(&self) {
        self.card.disconnect().await;
    }

    pub(crate) fn probe_identities(reader: &str) -> Result<bool, crate::Error> {
        let keys = OpenPgpCard::list_keys_ephemeral(reader, &SSH_OPENPGP_SLOTS)?;
        Ok(!keys_to_identities(keys).is_empty())
    }

    pub(crate) async fn request_identities_with_metadata(
        &self,
    ) -> Result<Vec<(Identity, OpenPgpCachedIdentity)>, crate::Error> {
        let keys = self.card.list_keys(&SSH_OPENPGP_SLOTS).await?;
        Ok(keys_to_identities(keys))
    }

    pub(crate) async fn sign(
        &self,
        public_credential: &PublicCredential,
        cached: Option<OpenPgpCachedIdentity>,
        data: &[u8],
        rsa_sig_hash: Option<HashAlg>,
    ) -> Result<SignResult<OpenPgpCachedIdentity>, crate::Error> {
        if let Some(cached) = cached {
            let prepared = prepare_sign_input(cached.attrs, data, rsa_sig_hash)?;
            match self
                .card
                .sign_raw(cached.slot, cached.serial, &prepared, None, None)
                .await
            {
                Ok(CardOperationOutcome::Completed(raw_sig)) => {
                    let signature = encode_signature(cached.attrs, &raw_sig, rsa_sig_hash)?;
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
                        "cached OpenPGP slot sign reported stale card/slot; re-scanning"
                    );
                }
                Err(err) if err.is_transport_error() => {
                    tracing::debug!(
                        "cached OpenPGP sign hit transport error, retrying with fresh scan: {err}"
                    );
                }
                Err(err) => return Err(err),
            }
        }

        let keys = self.card.list_keys(&SSH_OPENPGP_SLOTS).await?;
        let identities = keys_to_identities(keys);
        let discovered: Vec<(PublicCredential, OpenPgpCachedIdentity)> = identities
            .iter()
            .map(|(id, meta)| (id.credential.clone(), *meta))
            .collect();

        let matched = identities
            .into_iter()
            .find(|(id, _)| &id.credential == public_credential);

        let Some((_, meta)) = matched else {
            tracing::debug!("no matching OpenPGP identity for requested public key");
            return Ok(SignResult {
                discovered: Some(discovered),
                outcome: SignOutcome::NotFound,
            });
        };

        let prepared = prepare_sign_input(meta.attrs, data, rsa_sig_hash)?;
        let outcome = match self
            .card
            .sign_raw(meta.slot, None, &prepared, None, None)
            .await?
        {
            CardOperationOutcome::Completed(raw_sig) => {
                SignOutcome::Signed(encode_signature(meta.attrs, &raw_sig, rsa_sig_hash)?)
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

fn keys_to_identities(keys: Vec<OpenPgpKeyInfo>) -> Vec<(Identity, OpenPgpCachedIdentity)> {
    let mut identities = Vec::new();
    for key in keys {
        let slot = key.slot;
        match key_to_identity(key) {
            Ok(Some(pair)) => {
                tracing::info!("found usable OpenPGP identity on slot {:?}", slot);
                identities.push(pair);
            }
            Ok(None) => {}
            Err(err) => {
                tracing::warn!("failed to configure slot {slot:?} as OpenPGP identity: {err}");
            }
        }
    }
    identities
}

fn key_to_identity(
    key: OpenPgpKeyInfo,
) -> Result<Option<(Identity, OpenPgpCachedIdentity)>, crate::Error> {
    let Some(credential) = ssh_public_credentials(key.attrs, key.public_key)? else {
        return Ok(None);
    };

    let comment = match key.serial {
        Some(serial) => format!("OpenPGP {serial}:{:?}", key.slot),
        None => format!("OpenPGP {:?}", key.slot),
    };

    let identity = Identity {
        credential,
        comment,
    };
    let meta = OpenPgpCachedIdentity {
        slot: key.slot,
        attrs: key.attrs,
        serial: key.full_serial,
    };
    Ok(Some((identity, meta)))
}

fn ssh_public_credentials(
    attrs: AlgorithmAttributes,
    public_key: PublicKey,
) -> Result<Option<PublicCredential>, crate::Error> {
    let key_data = match (attrs, public_key) {
        (AlgorithmAttributes::Rsa(_), PublicKey::Rsa { modulus, exponent }) => {
            KeyData::Rsa(RsaPublicKey {
                n: Mpint::from_positive_bytes(&modulus)?,
                e: Mpint::from_positive_bytes(&exponent)?,
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

#[cfg(test)]
mod tests {
    use super::{encode_signature, prepare_sign_input, ssh_public_credentials};
    use keyroost_openpgp::{
        AlgorithmAttributes, Curve, EccKind, PublicKey, RsaAttributes, RsaImportFormat,
    };
    use ssh_agent_lib::{
        proto::PublicCredential,
        ssh_key::{Algorithm, HashAlg, public::KeyData},
    };

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

    #[test]
    fn rsa_public_key_with_msb_set_encodes_as_positive_mpint() {
        let attrs = AlgorithmAttributes::Rsa(RsaAttributes {
            n_bits: 2048,
            e_bits: 32,
            format: RsaImportFormat::Standard,
        });
        let mut modulus = vec![0xC3; 256];
        modulus[255] = 0x01;
        let cred = ssh_public_credentials(
            attrs,
            PublicKey::Rsa {
                modulus: modulus.clone(),
                exponent: vec![0x00, 0x01, 0x00, 0x01],
            },
        )
        .unwrap()
        .expect("expected RSA credential");

        let PublicCredential::Key(KeyData::Rsa(rsa)) = cred else {
            panic!("expected RSA key data");
        };
        assert_eq!(rsa.n.as_bytes()[0], 0x00);
        assert_eq!(rsa.n.as_positive_bytes(), Some(modulus.as_slice()));
        assert_eq!(rsa.e.as_positive_bytes(), Some([0x01, 0x00, 0x01].as_slice()));
    }
}
