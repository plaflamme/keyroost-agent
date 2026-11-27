use std::path::Path;
use std::time::Duration;
use tokio::net::UnixListener;
use tracing::debug;

mod assuan;
mod card;
mod error;
mod idle;
mod pin_cache;
mod pinentry;
mod protocol;

pub(crate) use crate::error::Error;
use crate::{
    card::{openpgp::OpenPgpCard, piv::PivCard},
    idle::{AbortOnDrop, IdleTracker, run_idle_disconnect_loop, run_with_idle_exit},
    protocol::ssh::{
        SshAgent, openpgp::OpenPgpSshFrontend, piv::PivSshFrontend, serve as serve_ssh,
    },
};
pub use keyroost_piv::Slot as PivSlot;

/// Configuration options for the PIV smart-card applet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PivOptions {
    /// PC/SC reader name to open.
    pub reader: String,
    /// Optional explicit list of PIV slots to expose.
    ///
    /// When `None`, the default slot set (`Authentication`, `CardAuthentication`,
    /// `Signature`, and all retired slots `82`–`95`) is used. Duplicate entries
    /// are deduplicated while preserving order.
    pub slots: Option<Vec<PivSlot>>,
}

impl PivOptions {
    /// Create PIV options for `reader` using the default slot set.
    #[must_use]
    pub fn new(reader: impl Into<String>) -> Self {
        Self {
            reader: reader.into(),
            slots: None,
        }
    }

    /// Restrict the exposed PIV slots to `slots`.
    #[must_use]
    pub fn with_slots(mut self, slots: Vec<PivSlot>) -> Self {
        self.slots = Some(slots);
        self
    }
}

/// Configuration options for the `OpenPGP` smart-card applet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenPgpOptions {
    /// PC/SC reader name to open.
    pub reader: String,
}

impl OpenPgpOptions {
    /// Create `OpenPGP` options for `reader`.
    #[must_use]
    pub fn new(reader: impl Into<String>) -> Self {
        Self {
            reader: reader.into(),
        }
    }
}

/// Parse a PIV slot identifier or name into a [`PivSlot`].
///
/// Accepts case-insensitive hex key references (`9a`, `9c`, `9d`, `9e`, `82`–`95`,
/// with optional `0x` prefix), standard names (`authentication`/`auth`,
/// `signature`/`sig`, `key-management`/`keymgmt`/`km`,
/// `card-authentication`/`card-auth`), and retired slot names
/// (`retired1`–`retired20`, `retired-1`–`retired-20`, `r1`–`r20`).
///
/// # Errors
///
/// Returns an error message if `s` is not a recognized PIV slot identifier.
pub fn parse_piv_slot(s: &str) -> Result<PivSlot, String> {
    card::piv::parse_slot(s)
}

/// Strategy for managing PC/SC connections to a smart-card applet.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ConnectionMode {
    /// Keep a persistent connection open to a single applet so on-card PIN verification persists.
    Persistent,
    /// Open a fresh connection per operation.
    #[default]
    Ephemeral,
}

/// Strategy for caching smart-card PINs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PinCacheStrategy {
    /// Do not cache PINs; prompt on every card verification.
    #[default]
    None,
    /// Cache PINs in process memory for the configured TTL.
    Memory {
        /// Sliding time-to-live refreshed on each successful cached PIN verification.
        ttl: Duration,
        /// Optional absolute maximum lifetime from initial PIN entry (`None` or zero means no cap).
        max_ttl: Option<Duration>,
    },
    /// Delegate PIN caching to `pinentry`'s external password cache (OS keyring).
    Pinentry,
}

/// Configuration options for running the `keyroost-agent` SSH agent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyroostAgentOptions {
    /// Optional PIV smart-card applet configuration.
    pub piv: Option<PivOptions>,
    /// Optional `OpenPGP` smart-card applet configuration.
    pub openpgp: Option<OpenPgpOptions>,
    /// Optional path or name of the `pinentry` binary to invoke for PIN prompts.
    pub pinentry_binary: Option<String>,
    /// Strategy for managing PC/SC connections to the smart-card applets.
    pub connection_mode: ConnectionMode,
    /// Optional idle timeout for disconnecting persistent sessions.
    pub idle_timeout: Option<Duration>,
    /// Whether the agent should exit once the idle timeout elapses (e.g. for socket activation).
    pub exit_on_idle: bool,
    /// Strategy for caching smart-card PINs.
    pub pin_cache: PinCacheStrategy,
}

/// Parse a human-friendly duration string into a [`Duration`].
///
/// Supports `0`, bare seconds (e.g. `300`), and combinations of `h`, `m`, and `s`
/// suffixes (e.g. `30s`, `10m`, `1h`, `1h30m`).
///
/// # Errors
///
/// Returns an error message if `s` is empty, negative, contains unknown units,
/// or overflows `u64` seconds.
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("duration cannot be empty".to_owned());
    }

    if s.bytes().all(|b| b.is_ascii_digit()) {
        let secs: u64 = s
            .parse()
            .map_err(|_| format!("invalid duration '{s}': value too large"))?;
        return Ok(Duration::from_secs(secs));
    }

    let mut total_secs: u64 = 0;
    let mut rest = s;
    while !rest.is_empty() {
        let digit_end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        if digit_end == 0 {
            return Err(format!("invalid duration '{s}'"));
        }
        let value: u64 = rest[..digit_end]
            .parse()
            .map_err(|_| format!("invalid duration '{s}': value too large"))?;
        rest = &rest[digit_end..];
        let mut chars = rest.chars();
        let Some(unit) = chars.next() else {
            return Err(format!("invalid duration '{s}': missing unit suffix"));
        };
        let multiplier: u64 = match unit {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            _ => return Err(format!("invalid duration '{s}': unsupported unit '{unit}'")),
        };
        let part = value
            .checked_mul(multiplier)
            .ok_or_else(|| format!("invalid duration '{s}': value too large"))?;
        total_secs = total_secs
            .checked_add(part)
            .ok_or_else(|| format!("invalid duration '{s}': value too large"))?;
        rest = chars.as_str();
    }

    Ok(Duration::from_secs(total_secs))
}

/// Check whether the PIV applet configured by `options` has at least one usable SSH identity.
///
/// # Errors
///
/// Returns an error if communicating with the PIV applet fails.
pub fn probe_piv_identities(options: &PivOptions) -> Result<bool, std::io::Error> {
    PivSshFrontend::probe_identities(&options.reader, options.slots.clone())
        .map_err(|err| std::io::Error::other(err.to_string()))
}

/// Check whether the `OpenPGP` applet configured by `options` has at least one usable SSH identity.
///
/// # Errors
///
/// Returns an error if communicating with the `OpenPGP` applet fails.
pub fn probe_openpgp_identities(options: &OpenPgpOptions) -> Result<bool, std::io::Error> {
    OpenPgpSshFrontend::probe_identities(&options.reader)
        .map_err(|err| std::io::Error::other(err.to_string()))
}

/// Launch an SSH agent and bind it to the specified socket path.
///
/// # Errors
///
/// Will return `Err` if an error occurs while binding to the socket or if the ssh agent raises an error while listening for connections.
pub async fn run(socket_path: &Path, options: KeyroostAgentOptions) -> Result<(), std::io::Error> {
    let listener = UnixListener::bind(socket_path)?;
    run_with_listener(listener, options).await
}

/// Launch an SSH agent on an already-bound Unix-domain socket listener.
///
/// # Errors
///
/// Will return `Err` if the ssh agent raises an error while listening for connections.
pub async fn run_with_listener(
    listener: UnixListener,
    options: KeyroostAgentOptions,
) -> Result<(), std::io::Error> {
    let KeyroostAgentOptions {
        piv,
        openpgp,
        pinentry_binary,
        connection_mode,
        idle_timeout,
        exit_on_idle,
        pin_cache,
    } = options;
    let (pin_cache, external_pin_cache) = match pin_cache {
        PinCacheStrategy::None => (None, false),
        PinCacheStrategy::Memory { ttl, max_ttl } => {
            (Some(pin_cache::PinCache::new(ttl, max_ttl)), false)
        }
        PinCacheStrategy::Pinentry => (None, true),
    };
    let pinentry = pinentry::SystemPinentry::new(pinentry_binary, external_pin_cache);
    let idle_tracker = IdleTracker::new();
    let agent = SshAgent::new(
        piv.map(|opts| {
            PivSshFrontend::new(PivCard::new(
                opts.reader,
                opts.slots,
                pinentry.clone(),
                connection_mode,
                pin_cache.clone(),
            ))
        }),
        openpgp.map(|opts| {
            OpenPgpSshFrontend::new(OpenPgpCard::new(
                opts.reader,
                pinentry,
                connection_mode,
                pin_cache.clone(),
            ))
        }),
        idle_tracker.clone(),
        pin_cache,
    );

    let active_timeout = if connection_mode == ConnectionMode::Persistent {
        idle_timeout.filter(|timeout| !timeout.is_zero())
    } else {
        None
    };

    if let Some(timeout) = active_timeout {
        if exit_on_idle {
            let server = serve_ssh(listener, agent.clone());
            let disconnect_agent = agent.clone();
            return run_with_idle_exit(server, &idle_tracker, timeout, move || async move {
                disconnect_agent.disconnect().await;
            })
            .await;
        }

        let disconnect_agent = agent.clone();
        let _idle_guard = AbortOnDrop(tokio::spawn(run_idle_disconnect_loop(
            idle_tracker,
            timeout,
            move || {
                let disconnect_agent = disconnect_agent.clone();
                async move {
                    debug!(
                        ?timeout,
                        "idle timeout elapsed; disconnecting persistent session"
                    );
                    disconnect_agent.disconnect().await;
                }
            },
        )));

        let result = serve_ssh(listener, agent.clone()).await;
        agent.disconnect().await;
        return result;
    }

    serve_ssh(listener, agent).await
}

#[cfg(test)]
mod tests {
    use super::{ConnectionMode, KeyroostAgentOptions, parse_duration, run_with_listener};
    use std::path::PathBuf;
    use std::time::{Duration, Instant};
    use tokio::net::{UnixListener, UnixStream};

    struct RemoveFileOnDrop(PathBuf);

    impl Drop for RemoveFileOnDrop {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn parse_duration_accepts_valid_inputs() {
        assert_eq!(parse_duration("0"), Ok(Duration::ZERO));
        assert_eq!(parse_duration("0s"), Ok(Duration::ZERO));
        assert_eq!(parse_duration("0m"), Ok(Duration::ZERO));
        assert_eq!(parse_duration("0h"), Ok(Duration::ZERO));
        assert_eq!(parse_duration("30"), Ok(Duration::from_secs(30)));
        assert_eq!(parse_duration("300"), Ok(Duration::from_secs(300)));
        assert_eq!(parse_duration("30s"), Ok(Duration::from_secs(30)));
        assert_eq!(parse_duration("10m"), Ok(Duration::from_mins(10)));
        assert_eq!(parse_duration("30m"), Ok(Duration::from_mins(30)));
        assert_eq!(parse_duration("2h"), Ok(Duration::from_hours(2)));
        assert_eq!(parse_duration("1h30m"), Ok(Duration::from_mins(90)));
        assert_eq!(parse_duration("1h30m15s"), Ok(Duration::from_secs(5415)));
        assert_eq!(parse_duration(" 45s "), Ok(Duration::from_secs(45)));
    }

    #[test]
    fn parse_duration_rejects_invalid_inputs() {
        for invalid in [
            "",
            "   ",
            "-5s",
            "-1",
            "+5s",
            "s",
            "m",
            "h",
            "5d",
            "10ms",
            "1.5m",
            "1h30",
            "abc",
            "18446744073709551615m",
            "999999999999999999999999h",
        ] {
            assert!(
                parse_duration(invalid).is_err(),
                "expected '{invalid}' to fail parsing"
            );
        }
    }

    #[tokio::test]
    async fn run_with_listener_exits_cleanly_on_idle_in_socket_activated_mode() {
        let socket_path = std::env::temp_dir().join(format!(
            "keyroost-agent-idle-test-{}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&socket_path);
        let _cleanup = RemoveFileOnDrop(socket_path.clone());
        let listener = UnixListener::bind(&socket_path).unwrap();

        let client_path = socket_path.clone();
        let client_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(40)).await;
            let stream = UnixStream::connect(&client_path).await.unwrap();
            stream.writable().await.unwrap();
            // SSH_AGENTC_REQUEST_IDENTITIES (length = 1, type = 11)
            let req = [0_u8, 0, 0, 1, 11];
            let written = stream.try_write(&req).unwrap();
            assert_eq!(written, req.len());

            stream.readable().await.unwrap();
            let mut buf = [0_u8; 32];
            let n = stream.try_read(&mut buf).unwrap();
            assert!(n >= 5, "expected SSH agent identities answer");
        });

        let start = Instant::now();
        let result = run_with_listener(
            listener,
            KeyroostAgentOptions {
                connection_mode: ConnectionMode::Persistent,
                idle_timeout: Some(Duration::from_millis(80)),
                exit_on_idle: true,
                ..Default::default()
            },
        )
        .await;

        client_task.await.unwrap();
        assert!(result.is_ok());
        assert!(
            start.elapsed() >= Duration::from_millis(100),
            "expected SSH agent request at 40ms to reset 80ms idle timer, elapsed: {:?}",
            start.elapsed()
        );
    }
}
