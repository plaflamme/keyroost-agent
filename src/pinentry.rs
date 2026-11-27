use std::{
    borrow::Cow,
    fmt::Display,
    io::{BufRead, BufReader, ErrorKind, Write},
    process::{Command, Stdio},
};

use ssh_agent_lib::secrecy::SecretBox;
use zeroize::{Zeroize, Zeroizing};

use crate::assuan::{is_cancelled_err, percent_decode, percent_encode};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Applet {
    Piv,
    OpenPgp,
}

impl Applet {
    pub(crate) fn keyinfo_name(self) -> &'static str {
        match self {
            Self::Piv => "piv",
            Self::OpenPgp => "openpgp",
        }
    }
}

impl Display for Applet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Piv => f.write_str("PIV"),
            Self::OpenPgp => f.write_str("OpenPGP"),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct PinentryEnv {
    pub(crate) ttyname: Option<String>,
    pub(crate) ttytype: Option<String>,
    pub(crate) display: Option<String>,
    pub(crate) xauthority: Option<String>,
    pub(crate) lc_ctype: Option<String>,
    pub(crate) lc_messages: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PinPromptOptions<'a> {
    pub(crate) allow_external_cache: bool,
    pub(crate) error: Option<&'a str>,
    pub(crate) description: Option<&'a str>,
    pub(crate) env: Option<&'a PinentryEnv>,
}

pub(crate) trait Pinentry {
    fn prompt_pin(
        &self,
        applet: Applet,
        serial: Option<u128>,
        options: PinPromptOptions<'_>,
    ) -> Result<Option<SecretBox<str>>, crate::Error>;

    fn external_cache_enabled(&self) -> bool {
        false
    }
}

#[derive(Clone, Default)]
pub(crate) struct SystemPinentry {
    binary: Option<String>,
    external_cache: bool,
}

impl SystemPinentry {
    pub(crate) fn new(binary: Option<String>, external_cache: bool) -> Self {
        Self {
            binary,
            external_cache,
        }
    }
}

impl Pinentry for SystemPinentry {
    fn prompt_pin(
        &self,
        applet: Applet,
        serial: Option<u128>,
        options: PinPromptOptions<'_>,
    ) -> Result<Option<SecretBox<str>>, crate::Error> {
        let binary = self.binary.as_deref().unwrap_or("pinentry");
        let mut child = match Command::new(binary)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            Err(err) if err.kind() == ErrorKind::NotFound => {
                return Err(crate::Error::Other(
                    format!("pinentry binary '{binary}' not found").into(),
                ));
            }
            Err(err) => return Err(crate::Error::Io(err)),
        };

        let Some(mut stdin) = child.stdin.take() else {
            let _ = child.wait();
            return Err(crate::Error::Other("pinentry stdin unavailable".into()));
        };
        let Some(stdout) = child.stdout.take() else {
            drop(stdin);
            let _ = child.wait();
            return Err(crate::Error::Other("pinentry stdout unavailable".into()));
        };

        let mut reader = BufReader::new(stdout);
        let use_external_cache =
            self.external_cache && options.allow_external_cache && serial.is_some();
        let result = interact_assuan(
            &mut reader,
            &mut stdin,
            applet,
            serial,
            use_external_cache,
            options,
        );

        drop(stdin);
        drop(reader);
        let _ = child.wait();

        match result {
            Ok(pin) => Ok(pin),
            Err(other) => {
                tracing::warn!("pinentry failed: {other}");
                Ok(None)
            }
        }
    }

    fn external_cache_enabled(&self) -> bool {
        self.external_cache
    }
}

#[derive(Debug)]
enum AssuanError {
    Io(std::io::Error),
    Protocol(&'static str),
    Server(String),
}

impl Display for AssuanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "I/O error communicating with pinentry: {err}"),
            Self::Protocol(msg) => write!(f, "Assuan protocol error: {msg}"),
            Self::Server(msg) => write!(f, "pinentry returned error: {msg}"),
        }
    }
}

impl From<std::io::Error> for AssuanError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

enum AssuanResponse {
    Ok(Zeroizing<Vec<u8>>),
    Err { code: u32, message: String },
}

fn read_response(reader: &mut impl BufRead) -> Result<AssuanResponse, AssuanError> {
    let mut data = Zeroizing::new(Vec::new());
    let mut line = Zeroizing::new(String::new());

    loop {
        line.zeroize();
        let read = reader.read_line(&mut line)?;
        if read == 0 {
            return Err(AssuanError::Protocol("unexpected EOF from pinentry"));
        }

        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty()
            || trimmed.starts_with('#')
            || trimmed == "S"
            || trimmed.starts_with("S ")
        {
            continue;
        }

        if let Some(payload) = trimmed.strip_prefix("D ") {
            percent_decode(payload, &mut data).map_err(AssuanError::Protocol)?;
        } else if trimmed == "OK" || trimmed.starts_with("OK ") {
            return Ok(AssuanResponse::Ok(data));
        } else if let Some(rest) = trimmed.strip_prefix("ERR ") {
            let code = rest
                .split_whitespace()
                .next()
                .and_then(|token| token.parse::<u32>().ok())
                .unwrap_or(0);
            return Ok(AssuanResponse::Err {
                code,
                message: rest.to_owned(),
            });
        } else if trimmed == "ERR" {
            return Ok(AssuanResponse::Err {
                code: 0,
                message: String::new(),
            });
        } else {
            return Err(AssuanError::Protocol(
                "unexpected response line from pinentry",
            ));
        }
    }
}

fn send_command(
    reader: &mut impl BufRead,
    writer: &mut impl Write,
    command: &str,
) -> Result<AssuanResponse, AssuanError> {
    writeln!(writer, "{command}")?;
    writer.flush()?;
    read_response(reader)
}

fn expect_ok(
    reader: &mut impl BufRead,
    writer: &mut impl Write,
    command: &str,
) -> Result<(), AssuanError> {
    match send_command(reader, writer, command)? {
        AssuanResponse::Ok(_) => Ok(()),
        AssuanResponse::Err { message, .. } => Err(AssuanError::Server(message)),
    }
}

fn interact_assuan(
    reader: &mut impl BufRead,
    writer: &mut impl Write,
    applet: Applet,
    serial: Option<u128>,
    use_external_cache: bool,
    options: PinPromptOptions<'_>,
) -> Result<Option<SecretBox<str>>, AssuanError> {
    match read_response(reader)? {
        AssuanResponse::Ok(_) => {}
        AssuanResponse::Err { message, .. } => return Err(AssuanError::Server(message)),
    }

    let result = (|| {
        if let Some(env) = options.env {
            for (key, value) in [
                ("ttyname", env.ttyname.as_deref()),
                ("ttytype", env.ttytype.as_deref()),
                ("display", env.display.as_deref()),
                ("xauthority", env.xauthority.as_deref()),
                ("lc-ctype", env.lc_ctype.as_deref()),
                ("lc-messages", env.lc_messages.as_deref()),
            ] {
                if let Some(val) = value
                    && let AssuanResponse::Err { message, .. } = send_command(
                        reader,
                        writer,
                        &format!("OPTION {key}={}", percent_encode(val)),
                    )?
                {
                    tracing::debug!("pinentry rejected OPTION {key}: {message}");
                }
            }
        }

        let description = match options.description {
            Some(desc) => Cow::Borrowed(desc),
            None => Cow::Owned(match serial {
                Some(serial) => format!("Please unlock {applet} card {serial}"),
                None => format!("Please unlock the {applet} card"),
            }),
        };
        expect_ok(
            reader,
            writer,
            &format!("SETDESC {}", percent_encode(&description)),
        )?;
        expect_ok(reader, writer, "SETPROMPT PIN")?;

        if let Some(err_msg) = options.error {
            expect_ok(
                reader,
                writer,
                &format!("SETERROR {}", percent_encode(err_msg)),
            )?;
        }

        if use_external_cache && let Some(serial) = serial {
            if let AssuanResponse::Err { message, .. } =
                send_command(reader, writer, "OPTION allow-external-password-cache")?
            {
                tracing::debug!("pinentry rejected allow-external-password-cache: {message}");
            }
            let keyinfo = format!("keyroost-agent-{}-{serial}", applet.keyinfo_name());
            if let AssuanResponse::Err { message, .. } = send_command(
                reader,
                writer,
                &format!("SETKEYINFO {}", percent_encode(&keyinfo)),
            )? {
                tracing::debug!("pinentry rejected SETKEYINFO: {message}");
            }
        }

        loop {
            match send_command(reader, writer, "GETPIN")? {
                AssuanResponse::Ok(data) => {
                    if data.is_empty() {
                        expect_ok(
                            reader,
                            writer,
                            &format!("SETERROR {}", percent_encode("PIN cannot be empty")),
                        )?;
                        continue;
                    }
                    let pin_str =
                        Zeroizing::new(String::from_utf8(data.to_vec()).map_err(|_| {
                            AssuanError::Protocol("pinentry returned non-UTF-8 PIN")
                        })?);
                    return Ok(Some(SecretBox::from(Box::<str>::from(pin_str.as_str()))));
                }
                AssuanResponse::Err { code, .. } if is_cancelled_err(code) => {
                    return Ok(None);
                }
                AssuanResponse::Err { message, .. } => {
                    return Err(AssuanError::Server(message));
                }
            }
        }
    })();

    if writeln!(writer, "BYE").is_ok() && writer.flush().is_ok() {
        let _ = read_response(reader);
    }

    result
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use ssh_agent_lib::secrecy::ExposeSecret;

    use super::{Applet, PinPromptOptions, PinentryEnv, interact_assuan};

    fn run_assuan_with_options(
        server_responses: &str,
        applet: Applet,
        serial: Option<u128>,
        use_external_cache: bool,
        options: PinPromptOptions<'_>,
    ) -> (Result<Option<String>, String>, Vec<String>) {
        let mut reader = Cursor::new(server_responses.as_bytes());
        let mut writer = Vec::new();
        let res = interact_assuan(
            &mut reader,
            &mut writer,
            applet,
            serial,
            use_external_cache,
            options,
        )
        .map(|opt| opt.map(|pin| pin.expose_secret().to_owned()))
        .map_err(|err| err.to_string());
        let commands = String::from_utf8(writer)
            .unwrap()
            .lines()
            .map(ToOwned::to_owned)
            .collect();
        (res, commands)
    }

    fn run_assuan(
        server_responses: &str,
        applet: Applet,
        serial: Option<u128>,
        use_external_cache: bool,
        error: Option<&str>,
    ) -> (Result<Option<String>, String>, Vec<String>) {
        run_assuan_with_options(
            server_responses,
            applet,
            serial,
            use_external_cache,
            PinPromptOptions {
                allow_external_cache: use_external_cache,
                error,
                ..Default::default()
            },
        )
    }

    #[test]
    fn basic_prompt_without_external_cache() {
        let responses = concat!(
            "OK Pleased to meet you\n",
            "OK\n", // SETDESC
            "OK\n", // SETPROMPT
            "# comment line ignored\n",
            "S PASSWORD_FROM_CACHE\n",
            "D 12%253456\n",
            "OK\n", // GETPIN
            "OK closing connection\n",
        );

        let (res, commands) = run_assuan(responses, Applet::Piv, Some(87_654_321), false, None);
        assert_eq!(res, Ok(Some("12%3456".to_owned())));
        assert_eq!(
            commands,
            vec![
                "SETDESC Please unlock PIV card 87654321",
                "SETPROMPT PIN",
                "GETPIN",
                "BYE",
            ]
        );
    }

    #[test]
    fn external_cache_emits_option_and_keyinfo_when_serial_present() {
        for (applet, expected_desc, expected_keyinfo) in [
            (
                Applet::Piv,
                "SETDESC Please unlock PIV card 87654321",
                "SETKEYINFO keyroost-agent-piv-87654321",
            ),
            (
                Applet::OpenPgp,
                "SETDESC Please unlock OpenPGP card 87654321",
                "SETKEYINFO keyroost-agent-openpgp-87654321",
            ),
        ] {
            let responses = concat!(
                "OK Pleased to meet you\n",
                "OK\n", // SETDESC
                "OK\n", // SETPROMPT
                "OK\n", // OPTION allow-external-password-cache
                "OK\n", // SETKEYINFO
                "D 123456\n",
                "OK\n", // GETPIN
                "OK closing connection\n",
            );

            let (res, commands) = run_assuan(responses, applet, Some(87_654_321), true, None);
            assert_eq!(res, Ok(Some("123456".to_owned())));
            assert_eq!(
                commands,
                vec![
                    expected_desc,
                    "SETPROMPT PIN",
                    "OPTION allow-external-password-cache",
                    expected_keyinfo,
                    "GETPIN",
                    "BYE",
                ]
            );
        }
    }

    #[test]
    fn external_cache_omitted_when_serial_is_none() {
        let responses = concat!(
            "OK Pleased to meet you\n",
            "OK\n", // SETDESC
            "OK\n", // SETPROMPT
            "D 123456\n",
            "OK\n", // GETPIN
            "OK closing connection\n",
        );

        let (res, commands) = run_assuan(responses, Applet::Piv, None, true, None);
        assert_eq!(res, Ok(Some("123456".to_owned())));
        assert_eq!(
            commands,
            vec![
                "SETDESC Please unlock the PIV card",
                "SETPROMPT PIN",
                "GETPIN",
                "BYE",
            ]
        );
    }

    #[test]
    fn seterror_emitted_when_error_provided() {
        let responses = concat!(
            "OK Pleased to meet you\n",
            "OK\n", // SETDESC
            "OK\n", // SETPROMPT
            "OK\n", // SETERROR
            "D 654321\n",
            "OK\n", // GETPIN
            "OK closing connection\n",
        );

        let (res, commands) = run_assuan(
            responses,
            Applet::Piv,
            Some(87_654_321),
            false,
            Some("Incorrect PIN"),
        );
        assert_eq!(res, Ok(Some("654321".to_owned())));
        assert_eq!(
            commands,
            vec![
                "SETDESC Please unlock PIV card 87654321",
                "SETPROMPT PIN",
                "SETERROR Incorrect PIN",
                "GETPIN",
                "BYE",
            ]
        );
    }

    #[test]
    fn operation_cancelled_returns_none() {
        let responses = concat!(
            "OK Pleased to meet you\n",
            "OK\n", // SETDESC
            "OK\n", // SETPROMPT
            "ERR 83886179 Operation cancelled <Pinentry>\n",
            "OK closing connection\n",
        );

        let (res, commands) = run_assuan(responses, Applet::OpenPgp, Some(42), false, None);
        assert_eq!(res, Ok(None));
        assert_eq!(
            commands,
            vec![
                "SETDESC Please unlock OpenPGP card 42",
                "SETPROMPT PIN",
                "GETPIN",
                "BYE",
            ]
        );
    }

    #[test]
    fn empty_pin_reprompts_with_seterror() {
        let responses = concat!(
            "OK Pleased to meet you\n",
            "OK\n", // SETDESC
            "OK\n", // SETPROMPT
            "OK\n", // first GETPIN (empty)
            "OK\n", // SETERROR PIN cannot be empty
            "D 123456\n",
            "OK\n", // second GETPIN
            "OK closing connection\n",
        );

        let (res, commands) = run_assuan(responses, Applet::Piv, Some(1), false, None);
        assert_eq!(res, Ok(Some("123456".to_owned())));
        assert_eq!(
            commands,
            vec![
                "SETDESC Please unlock PIV card 1",
                "SETPROMPT PIN",
                "GETPIN",
                "SETERROR PIN cannot be empty",
                "GETPIN",
                "BYE",
            ]
        );
    }

    #[test]
    fn custom_description_overrides_default_setdesc() {
        let responses = concat!(
            "OK Pleased to meet you\n",
            "OK\n", // SETDESC
            "OK\n", // SETPROMPT
            "D 123456\n",
            "OK\n", // GETPIN
            "OK closing connection\n",
        );

        let (res, commands) = run_assuan_with_options(
            responses,
            Applet::OpenPgp,
            Some(42),
            false,
            PinPromptOptions {
                description: Some("Sign commit\n100% verified"),
                ..Default::default()
            },
        );
        assert_eq!(res, Ok(Some("123456".to_owned())));
        assert_eq!(
            commands,
            vec![
                "SETDESC Sign commit%0A100%25 verified",
                "SETPROMPT PIN",
                "GETPIN",
                "BYE",
            ]
        );
    }

    #[test]
    fn pinentry_env_emits_present_options_in_assuan_format() {
        let responses = concat!(
            "OK Pleased to meet you\n",
            "OK\n", // OPTION ttyname
            "OK\n", // OPTION ttytype
            "OK\n", // OPTION display
            "ERR 536871187 Unknown option\n", // OPTION xauthority (ignored)
            "OK\n", // OPTION lc-ctype
            "OK\n", // OPTION lc-messages
            "OK\n", // SETDESC
            "OK\n", // SETPROMPT
            "D 654321\n",
            "OK\n", // GETPIN
            "OK closing connection\n",
        );

        let env = PinentryEnv {
            ttyname: Some("/dev/pts/3".to_owned()),
            ttytype: Some("xterm-256color".to_owned()),
            display: Some(":0".to_owned()),
            xauthority: Some("/tmp/auth%1".to_owned()),
            lc_ctype: Some("en_US.UTF-8".to_owned()),
            lc_messages: Some("C".to_owned()),
        };

        let (res, commands) = run_assuan_with_options(
            responses,
            Applet::Piv,
            Some(99),
            false,
            PinPromptOptions {
                env: Some(&env),
                ..Default::default()
            },
        );
        assert_eq!(res, Ok(Some("654321".to_owned())));
        assert_eq!(
            commands,
            vec![
                "OPTION ttyname=/dev/pts/3",
                "OPTION ttytype=xterm-256color",
                "OPTION display=:0",
                "OPTION xauthority=/tmp/auth%251",
                "OPTION lc-ctype=en_US.UTF-8",
                "OPTION lc-messages=C",
                "SETDESC Please unlock PIV card 99",
                "SETPROMPT PIN",
                "GETPIN",
                "BYE",
            ]
        );
    }

    #[test]
    fn pinentry_env_omits_none_fields() {
        let responses = concat!(
            "OK Pleased to meet you\n",
            "OK\n", // OPTION ttyname
            "OK\n", // OPTION lc-messages
            "OK\n", // SETDESC
            "OK\n", // SETPROMPT
            "D 123456\n",
            "OK\n", // GETPIN
            "OK closing connection\n",
        );

        let env = PinentryEnv {
            ttyname: Some("/dev/tty1".to_owned()),
            lc_messages: Some("en_GB.UTF-8".to_owned()),
            ..Default::default()
        };

        let (res, commands) = run_assuan_with_options(
            responses,
            Applet::Piv,
            None,
            false,
            PinPromptOptions {
                env: Some(&env),
                ..Default::default()
            },
        );
        assert_eq!(res, Ok(Some("123456".to_owned())));
        assert_eq!(
            commands,
            vec![
                "OPTION ttyname=/dev/tty1",
                "OPTION lc-messages=en_GB.UTF-8",
                "SETDESC Please unlock the PIV card",
                "SETPROMPT PIN",
                "GETPIN",
                "BYE",
            ]
        );
    }
}
