pub(crate) mod cache;
pub(crate) mod openpgp;
pub(crate) mod piv;

use ssh_agent_lib::{
    error::AgentError,
    proto::{Extension, Identity, ProtoError, PublicCredential, SignRequest},
    ssh_key::{HashAlg, Signature},
};
use tokio::net::UnixListener;
use tracing::{debug, trace};

use crate::{
    idle::IdleTracker,
    pin_cache::PinCache,
    protocol::ssh::cache::{
        CachedIdentity, IdentityCache, OpenPgpCachedIdentity, PivCachedIdentity, SignOutcome,
    },
};

#[derive(Clone)]
pub(crate) struct SshAgent {
    piv: Option<piv::PivSshFrontend>,
    openpgp: Option<openpgp::OpenPgpSshFrontend>,
    idle_tracker: IdleTracker,
    pin_cache: Option<PinCache>,
    identity_cache: IdentityCache,
}

impl SshAgent {
    pub(crate) fn new(
        piv: Option<piv::PivSshFrontend>,
        openpgp: Option<openpgp::OpenPgpSshFrontend>,
        idle_tracker: IdleTracker,
        pin_cache: Option<PinCache>,
    ) -> Self {
        Self {
            piv,
            openpgp,
            idle_tracker,
            pin_cache,
            identity_cache: IdentityCache::new(),
        }
    }

    pub(crate) async fn disconnect(&self) {
        if let Some(piv) = &self.piv {
            piv.disconnect().await;
        }
        if let Some(openpgp) = &self.openpgp {
            openpgp.disconnect().await;
        }
    }

    pub(crate) fn clear_pin_cache(&self) {
        if let Some(pin_cache) = &self.pin_cache {
            pin_cache.clear();
        }
    }

    pub(crate) fn clear_identity_cache(&self) {
        self.identity_cache.clear();
    }

    async fn sign_piv(
        &self,
        credential: &PublicCredential,
        cached: Option<PivCachedIdentity>,
        data: &[u8],
        rsa_sig_hash: Option<HashAlg>,
    ) -> Result<Option<SignOutcome>, AgentError> {
        let Some(piv) = &self.piv else {
            return Ok(None);
        };
        let result = piv.sign(credential, cached, data, rsa_sig_hash).await?;
        if let Some(discovered) = result.discovered {
            self.identity_cache.replace_piv(discovered);
        }
        Ok(Some(result.outcome))
    }

    async fn sign_openpgp(
        &self,
        credential: &PublicCredential,
        cached: Option<OpenPgpCachedIdentity>,
        data: &[u8],
        rsa_sig_hash: Option<HashAlg>,
    ) -> Result<Option<SignOutcome>, AgentError> {
        let Some(openpgp) = &self.openpgp else {
            return Ok(None);
        };
        let result = openpgp.sign(credential, cached, data, rsa_sig_hash).await?;
        if let Some(discovered) = result.discovered {
            self.identity_cache.replace_openpgp(discovered);
        }
        Ok(Some(result.outcome))
    }
}

#[ssh_agent_lib::async_trait]
impl ssh_agent_lib::agent::Session for SshAgent {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        debug!("request_identities");
        self.idle_tracker.record_activity();
        let mut identities = Vec::new();
        if let Some(piv) = &self.piv {
            let discovered = piv.request_identities_with_metadata().await?;
            self.identity_cache.replace_piv(
                discovered
                    .iter()
                    .map(|(id, meta)| (id.credential.clone(), *meta)),
            );
            identities.extend(discovered.into_iter().map(|(id, _)| id));
        }
        if let Some(openpgp) = &self.openpgp {
            let discovered = openpgp.request_identities_with_metadata().await?;
            self.identity_cache.replace_openpgp(
                discovered
                    .iter()
                    .map(|(id, meta)| (id.credential.clone(), *meta)),
            );
            identities.extend(discovered.into_iter().map(|(id, _)| id));
        }
        self.idle_tracker.record_activity();
        Ok(identities)
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        debug!("sign({})", format_credential(&request.credential));
        self.idle_tracker.record_activity();

        let rsa_sig_hash = if request.flags & 0x02 != 0 {
            Some(HashAlg::Sha256)
        } else if request.flags & 0x04 != 0 {
            Some(HashAlg::Sha512)
        } else {
            None
        };

        let mut skip_piv = false;
        let mut skip_openpgp = false;

        if let Some(cached) = self.identity_cache.get(&request.credential) {
            let outcome = match cached {
                CachedIdentity::Piv(piv_cached) => {
                    skip_piv = true;
                    self.sign_piv(
                        &request.credential,
                        Some(piv_cached),
                        &request.data,
                        rsa_sig_hash,
                    )
                    .await?
                }
                CachedIdentity::OpenPgp(pgp_cached) => {
                    skip_openpgp = true;
                    self.sign_openpgp(
                        &request.credential,
                        Some(pgp_cached),
                        &request.data,
                        rsa_sig_hash,
                    )
                    .await?
                }
            };

            match outcome {
                Some(SignOutcome::Signed(signature)) => {
                    self.idle_tracker.record_activity();
                    return Ok(signature);
                }
                Some(SignOutcome::UserCancelled) => {
                    self.idle_tracker.record_activity();
                    return Err(AgentError::Failure);
                }
                Some(SignOutcome::NotFound) => {}
                None => self.identity_cache.evict(&request.credential),
            }
        }

        if !skip_piv
            && let Some(outcome) = self
                .sign_piv(&request.credential, None, &request.data, rsa_sig_hash)
                .await?
        {
            match outcome {
                SignOutcome::Signed(signature) => {
                    self.idle_tracker.record_activity();
                    return Ok(signature);
                }
                SignOutcome::UserCancelled => {
                    self.idle_tracker.record_activity();
                    return Err(AgentError::Failure);
                }
                SignOutcome::NotFound => {}
            }
        }

        if !skip_openpgp
            && let Some(outcome) = self
                .sign_openpgp(&request.credential, None, &request.data, rsa_sig_hash)
                .await?
        {
            match outcome {
                SignOutcome::Signed(signature) => {
                    self.idle_tracker.record_activity();
                    return Ok(signature);
                }
                SignOutcome::UserCancelled => {
                    self.idle_tracker.record_activity();
                    return Err(AgentError::Failure);
                }
                SignOutcome::NotFound => {}
            }
        }

        self.idle_tracker.record_activity();
        Err(AgentError::Failure)
    }

    async fn remove_all_identities(&mut self) -> Result<(), AgentError> {
        debug!("remove_all_identities");
        self.disconnect().await;
        self.clear_pin_cache();
        self.clear_identity_cache();
        Ok(())
    }

    async fn lock(&mut self, _key: String) -> Result<(), AgentError> {
        debug!("lock");
        self.disconnect().await;
        self.clear_pin_cache();
        self.clear_identity_cache();
        Ok(())
    }

    async fn extension(&mut self, extension: Extension) -> Result<Option<Extension>, AgentError> {
        let details = extension.details.as_ref();
        debug!(
            name = %extension.name,
            details_len = details.len(),
            "extension"
        );
        trace!(
            name = %extension.name,
            ?details,
            "extension details"
        );
        Err(AgentError::from(ProtoError::UnsupportedCommand {
            command: 27,
        }))
    }
}

pub(crate) async fn serve(listener: UnixListener, agent: SshAgent) -> Result<(), std::io::Error> {
    match ssh_agent_lib::agent::listen(listener, agent).await {
        Ok(()) => Ok(()),
        Err(AgentError::IO(e)) => Err(e),
        Err(other) => Err(std::io::Error::other(other.to_string())),
    }
}

fn format_credential(credential: &PublicCredential) -> String {
    let key = credential.key_data();
    format!("{} {}", key.algorithm(), key.fingerprint(HashAlg::Sha256))
}

#[cfg(test)]
mod tests {
    use super::{
        AgentError, Extension, ProtoError, SshAgent,
        cache::{CachedIdentity, IdentityCache, PivCachedIdentity},
        format_credential, openpgp, piv,
    };
    use crate::{
        ConnectionMode,
        card::{openpgp::OpenPgpCard, piv::PivCard},
        idle::IdleTracker,
        pin_cache::PinCache,
        pinentry::{Applet, SystemPinentry},
    };
    use ssh_agent_lib::{
        agent::Session,
        proto::PublicCredential,
        secrecy::SecretBox,
        ssh_key::public::{Ed25519PublicKey, KeyData},
    };
    use std::time::Duration;

    #[test]
    fn format_credential_shows_algorithm_and_fingerprint() {
        let cred = PublicCredential::Key(KeyData::Ed25519(Ed25519PublicKey([0x11; 32])));
        let formatted = format_credential(&cred);
        assert!(formatted.starts_with("ssh-ed25519 SHA256:"));
    }

    #[tokio::test]
    async fn remove_all_identities_and_lock_disconnect_cleanly() {
        let mut agent = SshAgent::new(
            Some(piv::PivSshFrontend::new(PivCard::new(
                "mock-reader".to_owned(),
                None,
                SystemPinentry::default(),
                ConnectionMode::Persistent,
                None,
            ))),
            Some(openpgp::OpenPgpSshFrontend::new(OpenPgpCard::new(
                "mock-reader".to_owned(),
                SystemPinentry::default(),
                ConnectionMode::Persistent,
                None,
            ))),
            IdleTracker::new(),
            None,
        );

        agent.remove_all_identities().await.unwrap();
        agent.lock("passphrase".to_owned()).await.unwrap();
    }

    #[tokio::test]
    async fn remove_all_identities_clears_pin_cache() {
        let cache = PinCache::new(Duration::from_secs(60), None);
        cache.insert(
            Applet::Piv,
            Some(1),
            SecretBox::from(Box::<str>::from("123456")),
        );
        cache.insert(
            Applet::OpenPgp,
            Some(2),
            SecretBox::from(Box::<str>::from("654321")),
        );

        let identity_cache = IdentityCache::new();
        let cred = PublicCredential::Key(KeyData::Ed25519(Ed25519PublicKey([0x42; 32])));
        identity_cache.replace_piv([(
            cred.clone(),
            PivCachedIdentity {
                slot: keyroost_piv::Slot::Authentication,
                key_alg: keyroost_piv::KeyAlg::Ed25519,
                serial: Some(1),
            },
        )]);

        let mut agent = SshAgent {
            piv: None,
            openpgp: None,
            idle_tracker: IdleTracker::new(),
            pin_cache: Some(cache.clone()),
            identity_cache: identity_cache.clone(),
        };
        let cloned_agent = agent.clone();
        assert_eq!(
            cloned_agent.identity_cache.get(&cred),
            Some(CachedIdentity::Piv(PivCachedIdentity {
                slot: keyroost_piv::Slot::Authentication,
                key_alg: keyroost_piv::KeyAlg::Ed25519,
                serial: Some(1),
            }))
        );

        agent.remove_all_identities().await.unwrap();

        assert!(cache.get(Applet::Piv, Some(1)).is_none());
        assert!(cache.get(Applet::OpenPgp, Some(2)).is_none());
        assert!(identity_cache.get(&cred).is_none());
        assert!(cloned_agent.identity_cache.get(&cred).is_none());
    }

    #[tokio::test]
    async fn lock_clears_pin_cache() {
        let cache = PinCache::new(Duration::from_secs(60), None);
        cache.insert(
            Applet::Piv,
            Some(1),
            SecretBox::from(Box::<str>::from("123456")),
        );
        let identity_cache = IdentityCache::new();
        let cred = PublicCredential::Key(KeyData::Ed25519(Ed25519PublicKey([0x24; 32])));
        identity_cache.replace_piv([(
            cred.clone(),
            PivCachedIdentity {
                slot: keyroost_piv::Slot::Signature,
                key_alg: keyroost_piv::KeyAlg::Ed25519,
                serial: Some(1),
            },
        )]);

        let mut agent = SshAgent {
            piv: None,
            openpgp: None,
            idle_tracker: IdleTracker::new(),
            pin_cache: Some(cache.clone()),
            identity_cache: identity_cache.clone(),
        };

        agent.lock("passphrase".to_owned()).await.unwrap();

        assert!(cache.get(Applet::Piv, Some(1)).is_none());
        assert!(identity_cache.get(&cred).is_none());
    }

    #[tokio::test]
    async fn extension_returns_unsupported_command() {
        let mut agent = SshAgent::new(None, None, IdleTracker::new(), None);

        let err = agent
            .extension(Extension {
                name: "query".to_owned(),
                details: vec![1, 2, 3].into(),
            })
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            AgentError::Proto(ProtoError::UnsupportedCommand { command: 27 })
        ));
    }
}
