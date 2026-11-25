use std::fmt::Display;

use ssh_agent_lib::secrecy::SecretBox;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Applet {
    Piv,
    OpenPgp,
}

impl Display for Applet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Piv => f.write_str("PIV"),
            Self::OpenPgp => f.write_str("OpenPGP"),
        }
    }
}

pub(crate) trait Pinentry {
    fn prompt_pin(
        &self,
        applet: Applet,
        serial: Option<u128>,
    ) -> Result<Option<SecretBox<str>>, crate::Error>;
}

#[derive(Clone, Default)]
pub(crate) struct SystemPinentry {
    binary: Option<String>,
}

impl SystemPinentry {
    pub(crate) fn new(binary: Option<String>) -> Self {
        Self { binary }
    }
}

impl Pinentry for SystemPinentry {
    fn prompt_pin(
        &self,
        applet: Applet,
        serial: Option<u128>,
    ) -> Result<Option<SecretBox<str>>, crate::Error> {
        let pinentry = match self.binary.as_ref() {
            Some(binary_name) => pinentry::PassphraseInput::with_binary(binary_name),
            None => pinentry::PassphraseInput::with_default_binary(),
        };

        let Some(mut pinentry) = pinentry else {
            return Err(crate::Error::Other("pinentry binary not found".into()));
        };

        let description = match serial {
            Some(serial) => format!("Please unlock {applet} card {serial}"),
            None => format!("Please unlock the {applet} card"),
        };

        let pin = pinentry
            .with_prompt("PIN")
            .with_description(&description)
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
}
