use ssh_agent_lib::secrecy::SecretBox;

pub(crate) trait Pinentry {
    fn prompt_pin(&self, description: &str) -> Result<Option<SecretBox<str>>, crate::Error>;
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
    fn prompt_pin(&self, description: &str) -> Result<Option<SecretBox<str>>, crate::Error> {
        let pinentry = match self.binary.as_ref() {
            Some(binary_name) => pinentry::PassphraseInput::with_binary(binary_name),
            None => pinentry::PassphraseInput::with_default_binary(),
        };

        let Some(mut pinentry) = pinentry else {
            return Err(crate::Error::Other("pinentry binary not found".into()));
        };

        let pin = pinentry
            .with_prompt("PIN") // TODO: show card serial number
            .with_description(description)
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
