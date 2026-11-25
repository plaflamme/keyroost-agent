use ssh_agent_lib::{
    error::AgentError,
    proto::{Identity, PublicCredential, SignRequest},
    ssh_key::{HashAlg, Signature},
};
use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UnixListener;
use tokio::sync::Notify;
use tracing::{debug, info};

mod error;
mod openpgp;
mod pin_cache;
mod pinentry;
mod piv;

pub(crate) use crate::error::Error;
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
    piv::parse_slot(s)
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
    let agent = piv::PivSshAgent::new(
        options.reader.clone(),
        options.slots.clone(),
        pinentry::SystemPinentry::default(),
        ConnectionMode::Ephemeral,
        None,
    );
    agent
        .request_identities()
        .map(|identities| !identities.is_empty())
        .map_err(|err| std::io::Error::other(err.to_string()))
}

/// Check whether the `OpenPGP` applet configured by `options` has at least one usable SSH identity.
///
/// # Errors
///
/// Returns an error if communicating with the `OpenPGP` applet fails.
pub fn probe_openpgp_identities(options: &OpenPgpOptions) -> Result<bool, std::io::Error> {
    let agent = openpgp::OpenPgpSshAgent::new(
        options.reader.clone(),
        pinentry::SystemPinentry::default(),
        ConnectionMode::Ephemeral,
        None,
    );
    agent
        .request_identities()
        .map(|identities| !identities.is_empty())
        .map_err(|err| std::io::Error::other(err.to_string()))
}

#[derive(Clone, Default)]
struct IdleTracker {
    activity: Arc<Notify>,
}

impl IdleTracker {
    fn new() -> Self {
        Self {
            activity: Arc::new(Notify::new()),
        }
    }

    fn record_activity(&self) {
        self.activity.notify_one();
    }

    async fn wait_for_activity(&self) {
        self.activity.notified().await;
    }
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn wait_for_idle_exit(tracker: &IdleTracker, timeout: Duration) {
    loop {
        tokio::select! {
            biased;
            () = tracker.wait_for_activity() => {}
            () = tokio::time::sleep(timeout) => return,
        }
    }
}

async fn run_idle_disconnect_loop<F>(tracker: IdleTracker, timeout: Duration, mut on_idle: F)
where
    F: FnMut(),
{
    loop {
        tracker.wait_for_activity().await;

        loop {
            tokio::select! {
                biased;
                () = tracker.wait_for_activity() => {}
                () = tokio::time::sleep(timeout) => {
                    on_idle();
                    break;
                }
            }
        }
    }
}

async fn run_with_idle_exit<Fut, F>(
    server: Fut,
    tracker: &IdleTracker,
    timeout: Duration,
    on_idle: F,
) -> Result<(), std::io::Error>
where
    Fut: Future<Output = Result<(), std::io::Error>>,
    F: FnOnce(),
{
    tokio::select! {
        result = server => {
            on_idle();
            result
        }
        () = wait_for_idle_exit(tracker, timeout) => {
            info!(?timeout, "idle timeout elapsed; disconnecting and exiting");
            on_idle();
            Ok(())
        }
    }
}

#[derive(Clone)]
struct KeyroostAgent {
    piv: Option<piv::PivSshAgent>,
    openpgp: Option<openpgp::OpenPgpSshAgent>,
    idle_tracker: IdleTracker,
    pin_cache: Option<pin_cache::PinCache>,
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

    fn clear_pin_cache(&self) {
        if let Some(pin_cache) = &self.pin_cache {
            pin_cache.clear();
        }
    }
}

#[ssh_agent_lib::async_trait]
impl ssh_agent_lib::agent::Session for KeyroostAgent {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        debug!("request_identities");
        self.idle_tracker.record_activity();
        // TODO: cache identities so we can directly look them up later by public key
        let mut identities = Vec::new();
        if let Some(piv) = &self.piv {
            identities.extend(piv.request_identities()?);
        }
        if let Some(openpgp) = &self.openpgp {
            identities.extend(openpgp.request_identities()?);
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

        if let Some(piv) = &self.piv
            && let Some(signature) = piv.sign(&request.credential, &request.data, rsa_sig_hash)?
        {
            self.idle_tracker.record_activity();
            return Ok(signature);
        }

        if let Some(openpgp) = &self.openpgp
            && let Some(signature) =
                openpgp.sign(&request.credential, &request.data, rsa_sig_hash)?
        {
            self.idle_tracker.record_activity();
            return Ok(signature);
        }

        self.idle_tracker.record_activity();
        Err(AgentError::Failure)
    }

    async fn remove_all_identities(&mut self) -> Result<(), AgentError> {
        debug!("remove_all_identities");
        self.disconnect();
        self.clear_pin_cache();
        Ok(())
    }

    async fn lock(&mut self, _key: String) -> Result<(), AgentError> {
        debug!("lock");
        self.disconnect();
        self.clear_pin_cache();
        Ok(())
    }
}

fn map_listen_result(result: Result<(), AgentError>) -> Result<(), std::io::Error> {
    match result {
        Ok(()) => Ok(()),
        Err(AgentError::IO(e)) => Err(e),
        Err(other) => Err(std::io::Error::other(other.to_string())),
    }
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
    let agent = KeyroostAgent {
        piv: piv.map(|opts| {
            piv::PivSshAgent::new(
                opts.reader,
                opts.slots,
                pinentry.clone(),
                connection_mode,
                pin_cache.clone(),
            )
        }),
        openpgp: openpgp.map(|opts| {
            openpgp::OpenPgpSshAgent::new(opts.reader, pinentry, connection_mode, pin_cache.clone())
        }),
        idle_tracker: idle_tracker.clone(),
        pin_cache,
    };

    let active_timeout = if connection_mode == ConnectionMode::Persistent {
        idle_timeout.filter(|timeout| !timeout.is_zero())
    } else {
        None
    };

    if let Some(timeout) = active_timeout {
        if exit_on_idle {
            let server = async {
                map_listen_result(ssh_agent_lib::agent::listen(listener, agent.clone()).await)
            };
            return run_with_idle_exit(server, &idle_tracker, timeout, || agent.disconnect()).await;
        }

        let disconnect_agent = agent.clone();
        let _idle_guard = AbortOnDrop(tokio::spawn(run_idle_disconnect_loop(
            idle_tracker,
            timeout,
            move || {
                debug!(
                    ?timeout,
                    "idle timeout elapsed; disconnecting persistent session"
                );
                disconnect_agent.disconnect();
            },
        )));

        let result = map_listen_result(ssh_agent_lib::agent::listen(listener, agent.clone()).await);
        agent.disconnect();
        return result;
    }

    map_listen_result(ssh_agent_lib::agent::listen(listener, agent).await)
}

fn format_credential(credential: &PublicCredential) -> String {
    let key = credential.key_data();
    format!("{} {}", key.algorithm(), key.fingerprint(HashAlg::Sha256))
}

#[cfg(test)]
mod tests {
    use super::{
        AbortOnDrop, ConnectionMode, IdleTracker, KeyroostAgent, KeyroostAgentOptions,
        format_credential, openpgp, parse_duration, pinentry, piv, run_idle_disconnect_loop,
        run_with_idle_exit, run_with_listener,
    };
    use crate::{pin_cache::PinCache, pinentry::Applet};
    use ssh_agent_lib::{
        agent::Session,
        proto::PublicCredential,
        secrecy::SecretBox,
        ssh_key::public::{Ed25519PublicKey, KeyData},
    };
    use std::path::PathBuf;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::{Duration, Instant};
    use tokio::net::{UnixListener, UnixStream};

    struct RemoveFileOnDrop(PathBuf);

    impl Drop for RemoveFileOnDrop {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn format_credential_shows_algorithm_and_fingerprint() {
        let cred = PublicCredential::Key(KeyData::Ed25519(Ed25519PublicKey([0x11; 32])));
        let formatted = format_credential(&cred);
        assert!(formatted.starts_with("ssh-ed25519 SHA256:"));
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
    async fn remove_all_identities_and_lock_disconnect_cleanly() {
        let mut agent = KeyroostAgent {
            piv: Some(piv::PivSshAgent::new(
                "mock-reader".to_owned(),
                None,
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
            idle_tracker: IdleTracker::new(),
            pin_cache: None,
        };

        agent.remove_all_identities().await.unwrap();
        agent.lock("passphrase".to_owned()).await.unwrap();
    }

    #[tokio::test]
    async fn standalone_idle_loop_disconnects_once_and_rearms_after_activity() {
        let tracker = IdleTracker::new();
        let disconnects = Arc::new(AtomicUsize::new(0));
        let disconnects_clone = Arc::clone(&disconnects);

        let _guard = AbortOnDrop(tokio::spawn(run_idle_disconnect_loop(
            tracker.clone(),
            Duration::from_millis(60),
            move || {
                disconnects_clone.fetch_add(1, Ordering::SeqCst);
            },
        )));

        // No activity yet: idle disconnect must not fire.
        tokio::time::sleep(Duration::from_millis(90)).await;
        assert_eq!(disconnects.load(Ordering::SeqCst), 0);

        // Activity arms the timer; further activity before expiry resets it.
        tracker.record_activity();
        tokio::time::sleep(Duration::from_millis(35)).await;
        tracker.record_activity();
        tokio::time::sleep(Duration::from_millis(35)).await;
        assert_eq!(disconnects.load(Ordering::SeqCst), 0);

        // After full timeout of inactivity, disconnect fires once.
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(disconnects.load(Ordering::SeqCst), 1);

        // Staying idle must not busy-loop or re-fire disconnect.
        tokio::time::sleep(Duration::from_millis(140)).await;
        assert_eq!(disconnects.load(Ordering::SeqCst), 1);

        // Subsequent activity re-arms the timer and triggers another disconnect.
        tracker.record_activity();
        tokio::time::sleep(Duration::from_millis(90)).await;
        assert_eq!(disconnects.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn socket_activated_idle_exit_resets_on_activity_and_disconnects() {
        let tracker = IdleTracker::new();
        let disconnects = Arc::new(AtomicUsize::new(0));
        let disconnects_clone = Arc::clone(&disconnects);

        let activity_tracker = tracker.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(35)).await;
            activity_tracker.record_activity();
        });

        let start = Instant::now();
        let result = run_with_idle_exit(
            std::future::pending::<Result<(), std::io::Error>>(),
            &tracker,
            Duration::from_millis(70),
            move || {
                disconnects_clone.fetch_add(1, Ordering::SeqCst);
            },
        )
        .await;

        assert!(result.is_ok());
        assert!(
            start.elapsed() >= Duration::from_millis(90),
            "expected activity at 35ms to extend idle deadline, elapsed: {:?}",
            start.elapsed()
        );
        assert_eq!(disconnects.load(Ordering::SeqCst), 1);
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

        let mut agent = KeyroostAgent {
            piv: None,
            openpgp: None,
            idle_tracker: IdleTracker::new(),
            pin_cache: Some(cache.clone()),
        };

        agent.remove_all_identities().await.unwrap();

        assert!(cache.get(Applet::Piv, Some(1)).is_none());
        assert!(cache.get(Applet::OpenPgp, Some(2)).is_none());
    }

    #[tokio::test]
    async fn lock_clears_pin_cache() {
        let cache = PinCache::new(Duration::from_secs(60), None);
        cache.insert(
            Applet::Piv,
            Some(1),
            SecretBox::from(Box::<str>::from("123456")),
        );

        let mut agent = KeyroostAgent {
            piv: None,
            openpgp: None,
            idle_tracker: IdleTracker::new(),
            pin_cache: Some(cache.clone()),
        };

        agent.lock("passphrase".to_owned()).await.unwrap();

        assert!(cache.get(Applet::Piv, Some(1)).is_none());
    }
}
