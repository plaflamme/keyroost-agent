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

/// Parse a human-friendly duration string such as `"0"`, `"300"`, `"30s"`, `"30m"`, or `"1h"`.
///
/// # Errors
///
/// Returns an error if the input is empty, has an unsupported unit, is not a valid
/// non-negative integer, or overflows `u64` seconds.
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("duration cannot be empty".to_owned());
    }

    let (num_str, multiplier) = if let Some(n) = s.strip_suffix('s') {
        (n, 1_u64)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 60_u64)
    } else if let Some(n) = s.strip_suffix('h') {
        (n, 3600_u64)
    } else {
        (s, 1_u64)
    };

    if num_str.is_empty() || !num_str.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!(
            "invalid duration '{s}': expected a non-negative integer with optional s, m, or h suffix"
        ));
    }

    let value: u64 = num_str
        .parse()
        .map_err(|_| format!("duration value out of range: '{s}'"))?;
    let secs = value
        .checked_mul(multiplier)
        .ok_or_else(|| format!("duration overflow: '{s}'"))?;

    Ok(Duration::from_secs(secs))
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
        Ok(())
    }

    async fn lock(&mut self, _key: String) -> Result<(), AgentError> {
        debug!("lock");
        self.disconnect();
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
pub async fn run(
    socket_path: &Path,
    piv_reader: Option<String>,
    openpgp_reader: Option<String>,
    pinentry_binary: Option<String>,
    connection_mode: ConnectionMode,
    idle_timeout: Option<Duration>,
    exit_on_idle: bool,
) -> Result<(), std::io::Error> {
    let listener = UnixListener::bind(socket_path)?;
    run_with_listener(
        listener,
        piv_reader,
        openpgp_reader,
        pinentry_binary,
        connection_mode,
        idle_timeout,
        exit_on_idle,
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
    idle_timeout: Option<Duration>,
    exit_on_idle: bool,
) -> Result<(), std::io::Error> {
    let pinentry = pinentry::SystemPinentry::new(pinentry_binary);
    let idle_tracker = IdleTracker::new();
    let agent = KeyroostAgent {
        piv: piv_reader.map(|reader| {
            piv::PivSshAgent::new(reader, pinentry.clone(), connection_mode, None)
        }),
        openpgp: openpgp_reader
            .map(|reader| openpgp::OpenPgpSshAgent::new(reader, pinentry, connection_mode, None)),
        idle_tracker: idle_tracker.clone(),
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
                debug!(?timeout, "idle timeout elapsed; disconnecting persistent session");
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
        AbortOnDrop, ConnectionMode, IdleTracker, KeyroostAgent, format_credential, openpgp,
        parse_duration, pinentry, piv, run_idle_disconnect_loop, run_with_idle_exit,
        run_with_listener,
    };
    use ssh_agent_lib::{
        agent::Session,
        proto::PublicCredential,
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
    fn parse_duration_valid_inputs() {
        assert_eq!(parse_duration("0"), Ok(Duration::ZERO));
        assert_eq!(parse_duration("0s"), Ok(Duration::ZERO));
        assert_eq!(parse_duration("0m"), Ok(Duration::ZERO));
        assert_eq!(parse_duration("0h"), Ok(Duration::ZERO));
        assert_eq!(parse_duration("300"), Ok(Duration::from_secs(300)));
        assert_eq!(parse_duration("30s"), Ok(Duration::from_secs(30)));
        assert_eq!(parse_duration("30m"), Ok(Duration::from_mins(30)));
        assert_eq!(parse_duration("1h"), Ok(Duration::from_secs(3600)));
        assert_eq!(parse_duration(" 5m "), Ok(Duration::from_secs(300)));
    }

    #[test]
    fn parse_duration_invalid_inputs() {
        for invalid in [
            "",
            "   ",
            "s",
            "m",
            "h",
            "-5s",
            "+5s",
            "5d",
            "1.5m",
            "abc",
            "18446744073709551615m",
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
            None,
            None,
            None,
            ConnectionMode::Persistent,
            Some(Duration::from_millis(80)),
            true,
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
