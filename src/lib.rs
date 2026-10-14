use ssh_agent_lib::{
    error::AgentError,
    proto::{Identity, SignRequest},
    ssh_key::{HashAlg, Signature},
};
use std::path::Path;
use tokio::net::UnixListener;
use tracing::debug;

mod error;
mod piv;

pub(crate) use crate::error::Error;

#[derive(Clone)]
struct KeyroostAgent {
    piv: piv::PivSshAgent,
    // TODO: openpgp identity
}

#[ssh_agent_lib::async_trait]
impl ssh_agent_lib::agent::Session for KeyroostAgent {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        debug!("request_identities");
        // TODO: cache identities so we can directly look them up later by public key
        Ok(self.piv.request_identities()?)
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

        let signature = self
            .piv
            .sign(request.credential, &request.data, rsa_sig_hash)?;

        let Some(signature) = signature else {
            return Err(AgentError::Failure); // TODO: what error should we return for "not found"?
        };

        Ok(signature)
    }
}

/// Launch an SSH agent and bind it to the specified socket path.
pub async fn run(
    socket_path: &Path,
    piv_reader: String,
    pinentry_binary: Option<String>,
) -> Result<(), std::io::Error> {
    let listener = UnixListener::bind(socket_path)?;
    match ssh_agent_lib::agent::listen(
        listener,
        KeyroostAgent {
            piv: piv::PivSshAgent::new(piv_reader, pinentry_binary),
        },
    )
    .await
    {
        Ok(_) => Ok(()),
        Err(AgentError::IO(e)) => Err(e),
        Err(other) => Err(std::io::Error::other(other.to_string())),
    }
}
