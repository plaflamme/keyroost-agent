use ssh_agent_lib::{
    error::AgentError,
    proto::{Identity, PublicCredential, SignRequest},
    ssh_key::{HashAlg, Signature},
};
use std::path::Path;
use tokio::net::UnixListener;
use tracing::debug;

mod error;
mod openpgp;
mod pin_cache;
mod pinentry;
mod piv;

pub(crate) use crate::error::Error;

/// Strategy for managing PC/SC connections to a smart-card applet.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ConnectionMode {
    /// Keep a persistent connection open to a single applet so on-card PIN verification persists.
    Persistent,
    /// Open a fresh connection per operation.
    #[default]
    Ephemeral,
}

/// Check whether the PIV applet on `reader` has at least one usable SSH identity.
///
/// # Errors
///
/// Returns an error if communicating with the PIV applet fails.
pub fn probe_piv_identities(reader: &str) -> Result<bool, std::io::Error> {
    let agent = piv::PivSshAgent::new(
        reader.to_owned(),
        pinentry::SystemPinentry::default(),
        ConnectionMode::Ephemeral,
        None,
    );
    agent
        .request_identities()
        .map(|identities| !identities.is_empty())
        .map_err(|err| std::io::Error::other(err.to_string()))
}

/// Check whether the `OpenPGP` applet on `reader` has at least one usable SSH identity.
///
/// # Errors
///
/// Returns an error if communicating with the `OpenPGP` applet fails.
pub fn probe_openpgp_identities(reader: &str) -> Result<bool, std::io::Error> {
    let agent = openpgp::OpenPgpSshAgent::new(
        reader.to_owned(),
        pinentry::SystemPinentry::default(),
        ConnectionMode::Ephemeral,
        None,
    );
    agent
        .request_identities()
        .map(|identities| !identities.is_empty())
        .map_err(|err| std::io::Error::other(err.to_string()))
}

#[derive(Clone)]
struct KeyroostAgent {
    piv: Option<piv::PivSshAgent>,
    openpgp: Option<openpgp::OpenPgpSshAgent>,
}

impl KeyroostAgent {
    fn disconnect(&self) {
        if let Some(piv) = &self.piv {
            piv.disconnect();
        }
        if let Some(openpgp) = &self.openpgp {
            openpgp.disconnect();
        }
    }
}

#[ssh_agent_lib::async_trait]
impl ssh_agent_lib::agent::Session for KeyroostAgent {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        debug!("request_identities");
        // TODO: cache identities so we can directly look them up later by public key
        let mut identities = Vec::new();
        if let Some(piv) = &self.piv {
            identities.extend(piv.request_identities()?);
        }
        if let Some(openpgp) = &self.openpgp {
            identities.extend(openpgp.request_identities()?);
        }
        Ok(identities)
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        debug!("sign({})", format_credential(&request.credential));

        let rsa_sig_hash = if request.flags & 0x02 != 0 {
            Some(HashAlg::Sha256)
        } else if request.flags & 0x04 != 0 {
            Some(HashAlg::Sha512)
        } else {
            None
        };

        if let Some(piv) = &self.piv
            && let Some(signature) = piv.sign(&request.credential, &request.data, rsa_sig_hash)?
        {
            return Ok(signature);
        }

        if let Some(openpgp) = &self.openpgp
            && let Some(signature) =
                openpgp.sign(&request.credential, &request.data, rsa_sig_hash)?
        {
            return Ok(signature);
        }

        Err(AgentError::Failure)
    }

    async fn remove_all_identities(&mut self) -> Result<(), AgentError> {
        debug!("remove_all_identities");
        self.disconnect();
        Ok(())
    }

    async fn lock(&mut self, _key: String) -> Result<(), AgentError> {
        debug!("lock");
        self.disconnect();
        Ok(())
    }
}

/// Launch an SSH agent and bind it to the specified socket path.
///
/// # Errors
///
/// Will return `Err` if an error occurs while binding to the socket or if the ssh agent raises an error while listening for connections.
pub async fn run(
    socket_path: &Path,
    piv_reader: Option<String>,
    openpgp_reader: Option<String>,
    pinentry_binary: Option<String>,
    connection_mode: ConnectionMode,
) -> Result<(), std::io::Error> {
    let listener = UnixListener::bind(socket_path)?;
    run_with_listener(
        listener,
        piv_reader,
        openpgp_reader,
        pinentry_binary,
        connection_mode,
    )
    .await
}

/// Launch an SSH agent on an already-bound Unix-domain socket listener.
///
/// # Errors
///
/// Will return `Err` if the ssh agent raises an error while listening for connections.
pub async fn run_with_listener(
    listener: UnixListener,
    piv_reader: Option<String>,
    openpgp_reader: Option<String>,
    pinentry_binary: Option<String>,
    connection_mode: ConnectionMode,
) -> Result<(), std::io::Error> {
    let pinentry = pinentry::SystemPinentry::new(pinentry_binary);
    let result = ssh_agent_lib::agent::listen(
        listener,
        KeyroostAgent {
            piv: piv_reader.map(|reader| {
                piv::PivSshAgent::new(reader, pinentry.clone(), connection_mode, None)
            }),
            openpgp: openpgp_reader.map(|reader| {
                openpgp::OpenPgpSshAgent::new(reader, pinentry, connection_mode, None)
            }),
        },
    )
    .await;

    match result {
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
    use super::{ConnectionMode, KeyroostAgent, format_credential, openpgp, pinentry, piv};
    use ssh_agent_lib::{
        agent::Session,
        proto::PublicCredential,
        ssh_key::public::{Ed25519PublicKey, KeyData},
    };

    #[test]
    fn format_credential_shows_algorithm_and_fingerprint() {
        let cred = PublicCredential::Key(KeyData::Ed25519(Ed25519PublicKey([0x11; 32])));
        let formatted = format_credential(&cred);
        assert!(formatted.starts_with("ssh-ed25519 SHA256:"));
    }

    #[tokio::test]
    async fn remove_all_identities_and_lock_disconnect_cleanly() {
        let mut agent = KeyroostAgent {
            piv: Some(piv::PivSshAgent::new(
                "mock-reader".to_owned(),
                pinentry::SystemPinentry::default(),
                ConnectionMode::Persistent,
                None,
            )),
            openpgp: Some(openpgp::OpenPgpSshAgent::new(
                "mock-reader".to_owned(),
                pinentry::SystemPinentry::default(),
                ConnectionMode::Persistent,
                None,
            )),
        };

        agent.remove_all_identities().await.unwrap();
        agent.lock("passphrase".to_owned()).await.unwrap();
    }
}
