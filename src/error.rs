use std::fmt::Display;

use keyroost_piv::{x509::X509Error, x509_parse::X509ParseError};
use keyroost_transport::TransportError;
use ssh_agent_lib::{proto::Error as ProtoError, ssh_key};

#[non_exhaustive]
#[derive(Debug)]
pub(crate) enum Error {
    /// An IO error
    Io(std::io::Error),
    SshKey(ssh_key::Error),
    Signature(signature::Error),
    Other(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "{error}"),
            Self::SshKey(error) => write!(f, "{error}"),
            Self::Signature(error) => write!(f, "{error}"),
            Self::Other(other) => write!(f, "{other}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<ssh_agent_lib::ssh_key::Error> for Error {
    fn from(value: ssh_agent_lib::ssh_key::Error) -> Self {
        Error::SshKey(value)
    }
}

impl From<ssh_agent_lib::ssh_key::sec1::Error> for Error {
    fn from(value: ssh_agent_lib::ssh_key::sec1::Error) -> Self {
        Error::SshKey(ssh_key::Error::Ecdsa(value))
    }
}

impl From<signature::Error> for Error {
    fn from(value: signature::Error) -> Self {
        Self::Signature(value)
    }
}

impl From<TransportError> for Error {
    fn from(value: TransportError) -> Self {
        Self::Other(Box::new(value))
    }
}

impl From<X509Error> for Error {
    fn from(value: X509Error) -> Self {
        Self::Other(Box::new(value))
    }
}

impl From<X509ParseError> for Error {
    fn from(value: X509ParseError) -> Self {
        Self::Other(Box::new(value))
    }
}

impl From<Error> for ssh_agent_lib::error::AgentError {
    fn from(value: Error) -> Self {
        match value {
            Error::Io(error) => ssh_agent_lib::error::AgentError::IO(error),
            Error::SshKey(error) => {
                ssh_agent_lib::error::AgentError::Proto(ProtoError::SshKey(error))
            }
            Error::Signature(error) => {
                ssh_agent_lib::error::AgentError::Proto(ProtoError::SshSignature(error))
            }
            Error::Other(error) => ssh_agent_lib::error::AgentError::Other(error),
        }
    }
}
