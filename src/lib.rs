use ssh_agent_lib::{
    error::AgentError,
    proto::{Identity, SignRequest},
    ssh_key::{HashAlg, Signature},
};
use std::path::Path;
use tokio::net::UnixListener;
use tracing::debug;

mod error;
mod openpgp;
mod pinentry;
mod piv;

pub(crate) use crate::error::Error;

#[derive(Clone)]
struct KeyroostAgent {
    piv: Option<piv::PivSshAgent>,
    openpgp: Option<openpgp::OpenPgpSshAgent>,
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
        debug!("sign({:?})", request.credential); // TODO: saner display

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
) -> Result<(), std::io::Error> {
    let pinentry = pinentry::SystemPinentry::new(pinentry_binary);
    let listener = UnixListener::bind(socket_path)?;
    let result = ssh_agent_lib::agent::listen(
        listener,
        KeyroostAgent {
            piv: piv_reader.map(|reader| piv::PivSshAgent::new(reader, pinentry.clone())),
            openpgp: openpgp_reader.map(|reader| openpgp::OpenPgpSshAgent::new(reader, pinentry)),
        },
    )
    .await;

    match result {
        Ok(()) => Ok(()),
        Err(AgentError::IO(e)) => Err(e),
        Err(other) => Err(std::io::Error::other(other.to_string())),
    }
}
