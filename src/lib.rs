//! Pure-Rust SSH (`ssh-agent`) and GPG (`gpg-agent`) agent library backed by smart-card
//! PIV and `OpenPGP` applets via `keyroost` APIs.
//!
//! Use [`run_protocols`] to bind Unix-domain sockets for SSH, GPG, or both protocols
//! concurrently, or [`run_with_listeners`] to serve pre-bound listeners (for example from
//! systemd socket activation). When both protocols are active, they share the same
//! `OpenPGP` card session, PIN cache, pinentry integration, and idle timer.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
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
    protocol::{
        gpg::{GPG_OPENPGP_SLOTS, GpgAgent, serve as serve_gpg},
        ssh::{SshAgent, openpgp::OpenPgpSshFrontend, piv::PivSshFrontend, serve as serve_ssh},
    },
};
pub use keyroost_piv::Slot as PivSlot;

/// Unix-domain socket paths to bind for each supported agent protocol.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProtocolSockets {
    /// Optional SSH agent Unix-domain socket path.
    pub ssh: Option<PathBuf>,
    /// Optional GPG agent (Assuan) Unix-domain socket path.
    pub gpg: Option<PathBuf>,
}

/// Pre-bound Unix-domain socket listeners for each supported agent protocol.
#[derive(Debug, Default)]
pub struct ProtocolListeners {
    /// Optional pre-bound SSH agent Unix-domain socket listener.
    pub ssh: Option<UnixListener>,
    /// Optional pre-bound GPG agent (Assuan) Unix-domain socket listener.
    pub gpg: Option<UnixListener>,
    /// Optional socket path reported by GPG `GETINFO socket_name`.
    pub gpg_socket_name: Option<String>,
}

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

/// Configuration options for running `keyroost-agent` (SSH, GPG, or both protocols).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyroostAgentOptions {
    /// Optional PIV smart-card applet configuration (used by the SSH protocol).
    pub piv: Option<PivOptions>,
    /// Optional `OpenPGP` smart-card applet configuration (used by SSH and/or GPG protocols).
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

/// Check whether the `OpenPGP` applet configured by `options` has at least one usable GPG key
/// across the Sign, Decrypt, and Auth slots.
///
/// # Errors
///
/// Returns an error if communicating with the `OpenPGP` applet fails.
pub fn probe_openpgp_gpg_keys(options: &OpenPgpOptions) -> Result<bool, std::io::Error> {
    OpenPgpCard::probe_keys(&options.reader, &GPG_OPENPGP_SLOTS)
        .map_err(|err| std::io::Error::other(err.to_string()))
}

fn bind_unix_socket(path: &Path) -> Result<UnixListener, std::io::Error> {
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

async fn disconnect_all(ssh_agent: Option<&SshAgent>, gpg_agent: Option<&GpgAgent>) {
    if let Some(ssh) = ssh_agent {
        ssh.disconnect().await;
        ssh.clear_pin_cache();
        ssh.clear_identity_cache();
    }
    if let Some(gpg) = gpg_agent {
        gpg.disconnect().await;
        gpg.clear_pin_cache();
        gpg.clear_key_cache();
    }
}

async fn serve_protocols(
    ssh: Option<(UnixListener, SshAgent)>,
    gpg: Option<(UnixListener, GpgAgent)>,
) -> Result<(), std::io::Error> {
    match (ssh, gpg) {
        (Some((ssh_listener, ssh_agent)), Some((gpg_listener, gpg_agent))) => {
            tokio::select! {
                res = serve_ssh(ssh_listener, ssh_agent) => res,
                res = serve_gpg(gpg_listener, gpg_agent) => res,
            }
        }
        (Some((ssh_listener, ssh_agent)), None) => serve_ssh(ssh_listener, ssh_agent).await,
        (None, Some((gpg_listener, gpg_agent))) => serve_gpg(gpg_listener, gpg_agent).await,
        (None, None) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "at least one protocol listener (ssh or gpg) must be provided",
        )),
    }
}

/// Launch an SSH-only agent and bind it to the specified socket path.
///
/// For GPG or dual-protocol (SSH + GPG) operation, use [`run_protocols`].
///
/// # Errors
///
/// Returns an error if binding the socket fails or if the SSH agent raises an I/O error
/// while serving connections.
pub async fn run(socket_path: &Path, options: KeyroostAgentOptions) -> Result<(), std::io::Error> {
    run_protocols(
        ProtocolSockets {
            ssh: Some(socket_path.to_path_buf()),
            gpg: None,
        },
        options,
    )
    .await
}

/// Launch an SSH-only agent on an already-bound Unix-domain socket listener.
///
/// For GPG or dual-protocol (SSH + GPG) operation, use [`run_with_listeners`].
///
/// # Errors
///
/// Returns an error if the SSH agent raises an I/O error while serving connections.
pub async fn run_with_listener(
    listener: UnixListener,
    options: KeyroostAgentOptions,
) -> Result<(), std::io::Error> {
    run_with_listeners(
        ProtocolListeners {
            ssh: Some(listener),
            gpg: None,
            gpg_socket_name: None,
        },
        options,
    )
    .await
}

/// Bind the requested protocol sockets (SSH, GPG, or both) and serve them concurrently.
///
/// Each bound socket is created with mode `0o600`. All active protocols share the same
/// `OpenPGP` card session, PIN cache, pinentry integration, and idle timer.
///
/// # Errors
///
/// Returns [`std::io::ErrorKind::InvalidInput`] if both `sockets.ssh` and `sockets.gpg` are `None`,
/// or any I/O error raised while binding sockets or serving connections.
pub async fn run_protocols(
    sockets: ProtocolSockets,
    options: KeyroostAgentOptions,
) -> Result<(), std::io::Error> {
    if sockets.ssh.is_none() && sockets.gpg.is_none() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "at least one protocol socket (ssh or gpg) must be provided",
        ));
    }

    let ssh = sockets
        .ssh
        .as_deref()
        .map(bind_unix_socket)
        .transpose()?;
    let gpg_socket_name = sockets
        .gpg
        .as_ref()
        .map(|path| path.to_string_lossy().into_owned());
    let gpg = sockets
        .gpg
        .as_deref()
        .map(bind_unix_socket)
        .transpose()?;

    run_with_listeners(
        ProtocolListeners {
            ssh,
            gpg,
            gpg_socket_name,
        },
        options,
    )
    .await
}

async fn run_with_idle_management(
    ssh: Option<(UnixListener, SshAgent)>,
    gpg: Option<(UnixListener, GpgAgent)>,
    idle_tracker: IdleTracker,
    active_timeout: Option<Duration>,
    exit_on_idle: bool,
) -> Result<(), std::io::Error> {
    let ssh_agent = ssh.as_ref().map(|(_, agent)| agent.clone());
    let gpg_agent = gpg.as_ref().map(|(_, agent)| agent.clone());

    let Some(timeout) = active_timeout else {
        return serve_protocols(ssh, gpg).await;
    };

    if exit_on_idle {
        let server = serve_protocols(ssh, gpg);
        return run_with_idle_exit(server, &idle_tracker, timeout, move || async move {
            disconnect_all(ssh_agent.as_ref(), gpg_agent.as_ref()).await;
        })
        .await;
    }

    let disconnect_ssh = ssh_agent.clone();
    let disconnect_gpg = gpg_agent.clone();
    let _idle_guard = AbortOnDrop(tokio::spawn(run_idle_disconnect_loop(
        idle_tracker,
        timeout,
        move || {
            let disconnect_ssh = disconnect_ssh.clone();
            let disconnect_gpg = disconnect_gpg.clone();
            async move {
                debug!(
                    ?timeout,
                    "idle timeout elapsed; disconnecting persistent session"
                );
                disconnect_all(disconnect_ssh.as_ref(), disconnect_gpg.as_ref()).await;
            }
        },
    )));

    let result = serve_protocols(ssh, gpg).await;
    disconnect_all(ssh_agent.as_ref(), gpg_agent.as_ref()).await;
    result
}

/// Serve the requested pre-bound protocol listeners (SSH, GPG, or both) concurrently.
///
/// All active protocols share the same `OpenPGP` card session, PIN cache, pinentry
/// integration, and idle timer. When `listeners.gpg_socket_name` is `None`, the GPG
/// `GETINFO socket_name` response falls back to the listener's local socket path if
/// available.
///
/// # Errors
///
/// Returns [`std::io::ErrorKind::InvalidInput`] if both `listeners.ssh` and `listeners.gpg` are
/// `None`, or any I/O error raised while serving connections.
pub async fn run_with_listeners(
    listeners: ProtocolListeners,
    options: KeyroostAgentOptions,
) -> Result<(), std::io::Error> {
    if listeners.ssh.is_none() && listeners.gpg.is_none() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "at least one protocol listener (ssh or gpg) must be provided",
        ));
    }

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

    let piv_card = piv.map(|opts| {
        PivCard::new(
            opts.reader,
            opts.slots,
            pinentry.clone(),
            connection_mode,
            pin_cache.clone(),
        )
    });
    let openpgp_card = openpgp.map(|opts| {
        OpenPgpCard::new(
            opts.reader,
            pinentry,
            connection_mode,
            pin_cache.clone(),
        )
    });

    let ssh_agent = listeners.ssh.as_ref().map(|_| {
        SshAgent::new(
            piv_card.map(PivSshFrontend::new),
            openpgp_card.clone().map(OpenPgpSshFrontend::new),
            idle_tracker.clone(),
            pin_cache.clone(),
        )
    });

    let gpg_socket_name = listeners.gpg_socket_name.or_else(|| {
        listeners.gpg.as_ref().and_then(|listener| {
            listener
                .local_addr()
                .ok()
                .and_then(|addr| addr.as_pathname().map(|p| p.to_string_lossy().into_owned()))
        })
    });
    let gpg_agent = listeners.gpg.as_ref().map(|_| {
        GpgAgent::new(
            openpgp_card,
            idle_tracker.clone(),
            pin_cache,
            gpg_socket_name,
        )
    });

    let active_timeout = if connection_mode == ConnectionMode::Persistent {
        idle_timeout.filter(|timeout| !timeout.is_zero())
    } else {
        None
    };

    run_with_idle_management(
        listeners.ssh.zip(ssh_agent),
        listeners.gpg.zip(gpg_agent),
        idle_tracker,
        active_timeout,
        exit_on_idle,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::{
        ConnectionMode, KeyroostAgentOptions, ProtocolListeners, ProtocolSockets, parse_duration,
        run_protocols, run_with_listener, run_with_listeners,
    };
    use std::path::PathBuf;
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
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

    #[tokio::test]
    async fn run_protocols_and_run_with_listeners_reject_empty_protocols() {
        let err = run_protocols(ProtocolSockets::default(), KeyroostAgentOptions::default())
            .await
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);

        let err = run_with_listeners(
            ProtocolListeners::default(),
            KeyroostAgentOptions::default(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn run_with_listeners_serves_ssh_and_gpg_concurrently_with_shared_idle_timer() {
        let pid = std::process::id();
        let ssh_path = std::env::temp_dir().join(format!("keyroost-agent-dual-ssh-{pid}.sock"));
        let gpg_path = std::env::temp_dir().join(format!("keyroost-agent-dual-gpg-{pid}.sock"));
        let _ = std::fs::remove_file(&ssh_path);
        let _ = std::fs::remove_file(&gpg_path);
        let _ssh_cleanup = RemoveFileOnDrop(ssh_path.clone());
        let _gpg_cleanup = RemoveFileOnDrop(gpg_path.clone());

        let ssh_listener = UnixListener::bind(&ssh_path).unwrap();
        let gpg_listener = UnixListener::bind(&gpg_path).unwrap();

        let ssh_client_path = ssh_path.clone();
        let gpg_client_path = gpg_path.clone();
        let client_task = tokio::spawn(async move {
            // At 50ms: SSH request resets the 120ms idle timer.
            tokio::time::sleep(Duration::from_millis(50)).await;
            let ssh_stream = UnixStream::connect(&ssh_client_path).await.unwrap();
            ssh_stream.writable().await.unwrap();
            // SSH_AGENTC_REQUEST_IDENTITIES (length = 1, type = 11)
            let req = [0_u8, 0, 0, 1, 11];
            let written = ssh_stream.try_write(&req).unwrap();
            assert_eq!(written, req.len());

            ssh_stream.readable().await.unwrap();
            let mut buf = [0_u8; 32];
            let n = ssh_stream.try_read(&mut buf).unwrap();
            assert!(n >= 5, "expected SSH agent identities answer");
            drop(ssh_stream);

            // At 110ms (60ms later): GPG request resets the same 120ms idle timer.
            tokio::time::sleep(Duration::from_millis(60)).await;
            let gpg_stream = UnixStream::connect(&gpg_client_path).await.unwrap();
            let (read_half, mut write_half) = gpg_stream.into_split();
            let mut reader = BufReader::new(read_half);

            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            assert!(line.starts_with("OK"), "expected Assuan greeting, got {line:?}");

            write_half.write_all(b"NOP\n").await.unwrap();
            write_half.flush().await.unwrap();
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            assert!(line.starts_with("OK"), "expected OK for NOP, got {line:?}");

            write_half.write_all(b"GETINFO version\n").await.unwrap();
            write_half.flush().await.unwrap();
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            assert!(
                line.starts_with("D "),
                "expected version data line for GETINFO version, got {line:?}"
            );
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            assert!(
                line.starts_with("OK"),
                "expected OK after GETINFO version, got {line:?}"
            );

            write_half.write_all(b"BYE\n").await.unwrap();
            write_half.flush().await.unwrap();
            line.clear();
            reader.read_line(&mut line).await.unwrap();
            assert!(line.starts_with("OK"), "expected OK for BYE, got {line:?}");
        });

        let start = Instant::now();
        let result = run_with_listeners(
            ProtocolListeners {
                ssh: Some(ssh_listener),
                gpg: Some(gpg_listener),
                gpg_socket_name: Some(gpg_path.to_string_lossy().into_owned()),
            },
            KeyroostAgentOptions {
                connection_mode: ConnectionMode::Persistent,
                idle_timeout: Some(Duration::from_millis(120)),
                exit_on_idle: true,
                ..Default::default()
            },
        )
        .await;

        client_task.await.unwrap();
        assert!(result.is_ok());
        assert!(
            start.elapsed() >= Duration::from_millis(200),
            "expected SSH (50ms) and GPG (110ms) requests to both reset 120ms shared idle timer, elapsed: {:?}",
            start.elapsed()
        );
    }
}
