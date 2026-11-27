use std::sync::{Arc, Mutex, mpsc};

use keyroost_piv::{KeyAlg, PinPolicy, PublicKey, Slot};
use keyroost_transport::{PivSession, PivSessionState, TransportError};
use tokio::sync::oneshot;

use crate::{
    ConnectionMode,
    card::CardOperationOutcome,
    pin_cache::{PinCache, verify_pin_with_cache},
    pinentry::{Applet, Pinentry, PinentryEnv, SystemPinentry},
};

#[derive(Clone, Debug)]
pub(crate) struct PivKeyInfo {
    pub(crate) slot: Slot,
    pub(crate) key_alg: KeyAlg,
    pub(crate) public_key: PublicKey,
    pub(crate) serial: Option<u128>,
}

#[derive(Clone)]
struct PivConfig {
    slots: Vec<Slot>,
    pinentry: SystemPinentry,
    pin_cache: Option<PinCache>,
}

enum PivRequest {
    ListKeys {
        refresh: bool,
    },
    SignRaw {
        slot: Slot,
        key_alg: KeyAlg,
        expected_serial: Option<u128>,
        prepared: Vec<u8>,
        prompt_desc: Option<String>,
        prompt_env: Option<Box<PinentryEnv>>,
    },
}

enum PivResponse {
    Keys(Vec<PivKeyInfo>),
    Signed(CardOperationOutcome<Vec<u8>>),
}

enum WorkerMessage<Req, Res, E> {
    Request {
        request: Req,
        reply: oneshot::Sender<Result<Res, E>>,
    },
    Disconnect {
        reply: oneshot::Sender<()>,
    },
}

type WorkerSender<Req, Res, E> = mpsc::Sender<WorkerMessage<Req, Res, E>>;

struct PersistentWorker<Req, Res, E> {
    sender: Arc<Mutex<Option<WorkerSender<Req, Res, E>>>>,
}

impl<Req, Res, E> Clone for PersistentWorker<Req, Res, E> {
    fn clone(&self) -> Self {
        Self {
            sender: Arc::clone(&self.sender),
        }
    }
}

impl<Req, Res, E> PersistentWorker<Req, Res, E> {
    fn new() -> Self {
        Self {
            sender: Arc::new(Mutex::new(None)),
        }
    }

    async fn send_request(
        &self,
        request: Req,
        spawn_worker: impl FnOnce(mpsc::Receiver<WorkerMessage<Req, Res, E>>),
        on_worker_gone: impl Fn(&'static str) -> E,
    ) -> Result<Res, E> {
        let tx = {
            let mut guard = self
                .sender
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard
                .get_or_insert_with(|| {
                    let (tx, rx) = mpsc::channel();
                    spawn_worker(rx);
                    tx
                })
                .clone()
        };

        let (reply_tx, reply_rx) = oneshot::channel();
        if tx
            .send(WorkerMessage::Request {
                request,
                reply: reply_tx,
            })
            .is_err()
        {
            *self
                .sender
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
            return Err(on_worker_gone("PIV worker thread disconnected"));
        }

        reply_rx
            .await
            .map_err(|_| on_worker_gone("PIV worker thread dropped reply"))?
    }

    async fn disconnect(&self) {
        let tx = {
            let guard = self
                .sender
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.clone()
        };
        let Some(tx) = tx else {
            return;
        };
        let (reply_tx, reply_rx) = oneshot::channel();
        if tx.send(WorkerMessage::Disconnect { reply: reply_tx }).is_ok() {
            let _ = reply_rx.await;
        }
    }
}

enum TransactionExit {
    Disconnect(oneshot::Sender<()>),
    Closed,
    TransportError,
}

fn serve_in_transaction<Req, Res, E>(
    first_req: Req,
    first_reply: oneshot::Sender<Result<Res, E>>,
    rx: &mpsc::Receiver<WorkerMessage<Req, Res, E>>,
    mut handle: impl FnMut(Req) -> Result<Res, E>,
    is_fatal: impl Fn(&E) -> bool,
) -> TransactionExit {
    let mut pending = Some((first_req, first_reply));
    loop {
        let (req, reply) = match pending.take() {
            Some(pair) => pair,
            None => match rx.recv() {
                Ok(WorkerMessage::Request { request, reply }) => (request, reply),
                Ok(WorkerMessage::Disconnect { reply }) => return TransactionExit::Disconnect(reply),
                Err(_) => return TransactionExit::Closed,
            },
        };
        let result = handle(req);
        let broken = result.as_ref().err().is_some_and(&is_fatal);
        let _ = reply.send(result);
        if broken {
            tracing::debug!("dropping persistent PIV session after transport error");
            return TransactionExit::TransportError;
        }
    }
}

fn run_worker<Req, Res, E>(
    rx: &mpsc::Receiver<WorkerMessage<Req, Res, E>>,
    mut open_and_serve: impl FnMut(
        &mut Option<(Req, oneshot::Sender<Result<Res, E>>)>,
        &mpsc::Receiver<WorkerMessage<Req, Res, E>>,
    ) -> Result<TransactionExit, E>,
) {
    while let Ok(msg) = rx.recv() {
        match msg {
            WorkerMessage::Disconnect { reply } => {
                let _ = reply.send(());
            }
            WorkerMessage::Request { request, reply } => {
                let mut pending = Some((request, reply));
                match open_and_serve(&mut pending, rx) {
                    Ok(TransactionExit::Disconnect(disconnect_reply)) => {
                        tracing::debug!("disconnected persistent PIV session");
                        let _ = disconnect_reply.send(());
                    }
                    Ok(TransactionExit::Closed | TransactionExit::TransportError) => {}
                    Err(err) => {
                        if let Some((_, reply)) = pending.take() {
                            let _ = reply.send(Err(err));
                        }
                    }
                }
            }
        }
    }
}

#[derive(Clone)]
enum PivBackend {
    Ephemeral,
    Persistent(PersistentWorker<PivRequest, PivResponse, crate::Error>),
}

#[derive(Clone)]
pub(crate) struct PivCard {
    reader: String,
    config: PivConfig,
    backend: PivBackend,
    session_state: Arc<Mutex<PivSessionState>>,
}

fn with_piv_transaction<R>(
    reader: &str,
    cached_state: &Mutex<PivSessionState>,
    f: impl FnOnce(&mut PivSession<'_>) -> Result<R, crate::Error>,
) -> Result<R, crate::Error> {
    let snapshot = cached_state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let result = PivSession::with_cached_transaction(reader, snapshot, |session| {
        let res = f(session);
        let next_state = if res.as_ref().err().is_some_and(crate::Error::is_transport_error) {
            PivSessionState::default()
        } else {
            session.state()
        };
        *cached_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = next_state;
        res
    });
    if result
        .as_ref()
        .err()
        .is_some_and(crate::Error::is_transport_error)
    {
        *cached_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = PivSessionState::default();
    }
    result
}

pub(crate) fn default_slots() -> Vec<Slot> {
    let mut slots = vec![
        Slot::Authentication,
        Slot::CardAuthentication,
        Slot::Signature,
    ];
    slots.extend(Slot::retired_all());
    slots
}

pub(crate) fn dedup_slots(slots: Vec<Slot>) -> Vec<Slot> {
    let mut deduped = Vec::with_capacity(slots.len());
    for slot in slots {
        if !deduped.contains(&slot) {
            deduped.push(slot);
        }
    }
    deduped
}

pub(crate) fn parse_slot(s: &str) -> Result<Slot, String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err("PIV slot cannot be empty".to_owned());
    }

    let normalized = trimmed.to_ascii_lowercase();
    let hex = normalized.strip_prefix("0x").unwrap_or(&normalized);
    if hex.len() == 2
        && hex.bytes().all(|b| b.is_ascii_hexdigit())
        && let Ok(key_ref) = u8::from_str_radix(hex, 16)
    {
        return match key_ref {
            0x9A => Ok(Slot::Authentication),
            0x9C => Ok(Slot::Signature),
            0x9D => Ok(Slot::KeyManagement),
            0x9E => Ok(Slot::CardAuthentication),
            0x82..=0x95 => Ok(Slot::retired(key_ref - 0x81).expect("0x82..=0x95 maps to 1..=20")),
            _ => Err(format!(
                "invalid PIV slot '{s}': unknown hex slot ID 0x{key_ref:02x} (expected 9a, 9c, 9d, 9e, or 82-95)"
            )),
        };
    }

    match normalized.as_str() {
        "authentication" | "auth" => return Ok(Slot::Authentication),
        "signature" | "sig" => return Ok(Slot::Signature),
        "key-management" | "key_management" | "keymanagement" | "key-mgmt" | "keymgmt" | "km" => {
            return Ok(Slot::KeyManagement);
        }
        "card-authentication"
        | "card_authentication"
        | "cardauthentication"
        | "card-auth"
        | "card_auth"
        | "cardauth" => return Ok(Slot::CardAuthentication),
        _ => {}
    }

    if let Some(rest) = normalized
        .strip_prefix("retired-")
        .or_else(|| normalized.strip_prefix("retired_"))
        .or_else(|| normalized.strip_prefix("retired"))
        .or_else(|| normalized.strip_prefix('r'))
        && !rest.is_empty()
        && rest.bytes().all(|b| b.is_ascii_digit())
    {
        return rest
            .parse::<u8>()
            .ok()
            .and_then(Slot::retired)
            .ok_or_else(|| {
                format!("invalid PIV retired slot '{s}': expected retired1-retired20 (82-95)")
            });
    }

    Err(format!(
        "invalid PIV slot '{s}': expected a slot hex ID (9a, 9c, 9d, 9e, 82-95) or name (authentication, signature, key-management, card-authentication, retired1-retired20)"
    ))
}

impl PivCard {
    pub(crate) fn new(
        reader: String,
        slots: Option<Vec<Slot>>,
        pinentry: SystemPinentry,
        connection_mode: ConnectionMode,
        pin_cache: Option<PinCache>,
    ) -> Self {
        let slots = match slots {
            Some(slots) => dedup_slots(slots),
            None => default_slots(),
        };

        let backend = match connection_mode {
            ConnectionMode::Ephemeral => PivBackend::Ephemeral,
            ConnectionMode::Persistent => PivBackend::Persistent(PersistentWorker::new()),
        };

        Self {
            reader,
            config: PivConfig {
                slots,
                pinentry,
                pin_cache,
            },
            backend,
            session_state: Arc::new(Mutex::new(PivSessionState::default())),
        }
    }

    pub(crate) async fn disconnect(&self) {
        if let PivBackend::Persistent(worker) = &self.backend {
            worker.disconnect().await;
        }
    }

    pub(crate) fn list_keys_ephemeral(
        reader: &str,
        slots: Option<Vec<Slot>>,
    ) -> Result<Vec<PivKeyInfo>, crate::Error> {
        let slots = match slots {
            Some(slots) => dedup_slots(slots),
            None => default_slots(),
        };
        PivSession::with_transaction(reader, |session| {
            let serial = session.status().ok().and_then(|status| status.serial);
            list_keys_in_session(&slots, session, serial)
        })
    }

    #[allow(dead_code)]
    pub(crate) fn probe_identities(
        reader: &str,
        slots: Option<Vec<Slot>>,
    ) -> Result<bool, crate::Error> {
        Self::list_keys_ephemeral(reader, slots).map(|keys| !keys.is_empty())
    }

    pub(crate) async fn list_keys(&self) -> Result<Vec<PivKeyInfo>, crate::Error> {
        self.list_keys_with_refresh(false).await
    }

    pub(crate) async fn refresh_and_list_keys(&self) -> Result<Vec<PivKeyInfo>, crate::Error> {
        self.list_keys_with_refresh(true).await
    }

    async fn list_keys_with_refresh(&self, refresh: bool) -> Result<Vec<PivKeyInfo>, crate::Error> {
        match &self.backend {
            PivBackend::Ephemeral => {
                tracing::debug!(
                    connection_mode = ?ConnectionMode::Ephemeral,
                    refresh,
                    "requesting PIV keys"
                );
                let reader = self.reader.clone();
                let slots = self.config.slots.clone();
                let session_state = Arc::clone(&self.session_state);
                tokio::task::spawn_blocking(move || {
                    with_piv_transaction(&reader, &session_state, |session| {
                        let serial = if refresh {
                            PivSlotSession::refresh(session)?
                        } else {
                            session.status().ok().and_then(|status| status.serial)
                        };
                        list_keys_in_session(&slots, session, serial)
                    })
                })
                .await
                .map_err(|err| crate::Error::Other(Box::new(err)))?
            }
            PivBackend::Persistent(worker) => {
                tracing::debug!(
                    connection_mode = ?ConnectionMode::Persistent,
                    refresh,
                    "requesting PIV keys"
                );
                let response = self
                    .send_persistent(worker, PivRequest::ListKeys { refresh })
                    .await?;
                match response {
                    PivResponse::Keys(keys) => Ok(keys),
                    PivResponse::Signed(_) => {
                        Err(crate::Error::Other("unexpected PIV worker response".into()))
                    }
                }
            }
        }
    }

    pub(crate) async fn sign_raw(
        &self,
        slot: Slot,
        key_alg: KeyAlg,
        expected_serial: Option<u128>,
        prepared: &[u8],
        prompt_desc: Option<&str>,
        prompt_env: Option<&PinentryEnv>,
    ) -> Result<CardOperationOutcome<Vec<u8>>, crate::Error> {
        match &self.backend {
            PivBackend::Ephemeral => {
                let reader = self.reader.clone();
                let config = self.config.clone();
                let session_state = Arc::clone(&self.session_state);
                let prepared = prepared.to_vec();
                let prompt_desc = prompt_desc.map(ToOwned::to_owned);
                let prompt_env = prompt_env.cloned();
                tokio::task::spawn_blocking(move || {
                    with_piv_transaction(&reader, &session_state, |session| {
                        let serial = session.status().ok().and_then(|status| status.serial);
                        sign_raw_in_session(
                            session,
                            slot,
                            key_alg,
                            serial,
                            expected_serial,
                            &prepared,
                            &config.pinentry,
                            config.pin_cache.as_ref(),
                            prompt_desc.as_deref(),
                            prompt_env.as_ref(),
                        )
                    })
                })
                .await
                .map_err(|err| crate::Error::Other(Box::new(err)))?
            }
            PivBackend::Persistent(worker) => {
                let response = self
                    .send_persistent(
                        worker,
                        PivRequest::SignRaw {
                            slot,
                            key_alg,
                            expected_serial,
                            prepared: prepared.to_vec(),
                            prompt_desc: prompt_desc.map(ToOwned::to_owned),
                            prompt_env: prompt_env.cloned().map(Box::new),
                        },
                    )
                    .await?;
                match response {
                    PivResponse::Signed(outcome) => Ok(outcome),
                    PivResponse::Keys(_) => {
                        Err(crate::Error::Other("unexpected PIV worker response".into()))
                    }
                }
            }
        }
    }

    async fn send_persistent(
        &self,
        worker: &PersistentWorker<PivRequest, PivResponse, crate::Error>,
        request: PivRequest,
    ) -> Result<PivResponse, crate::Error> {
        let reader = self.reader.clone();
        let config = self.config.clone();
        let session_state = Arc::clone(&self.session_state);
        worker
            .send_request(
                request,
                move |rx| {
                    std::thread::spawn(move || {
                        run_worker(&rx, |pending, rx| {
                            let exit = with_piv_transaction(&reader, &session_state, |session| {
                                // Read serial ONCE when the persistent session opens: on Token2 cards,
                                // `status()` performs a cross-applet OTP read which resets PIV PIN state.
                                let mut serial =
                                    session.status().ok().and_then(|status| status.serial);
                                let (first_req, first_reply) = pending
                                    .take()
                                    .expect("pending request present when entering transaction");
                                Ok(serve_in_transaction(
                                    first_req,
                                    first_reply,
                                    rx,
                                    |req| match req {
                                        PivRequest::ListKeys { refresh } => {
                                            if refresh {
                                                serial = PivSlotSession::refresh(session)?;
                                            }
                                            list_keys_in_session(&config.slots, session, serial)
                                                .map(PivResponse::Keys)
                                        }
                                        PivRequest::SignRaw {
                                            slot,
                                            key_alg,
                                            expected_serial,
                                            prepared,
                                            prompt_desc,
                                            prompt_env,
                                        } => sign_raw_in_session(
                                            session,
                                            slot,
                                            key_alg,
                                            serial,
                                            expected_serial,
                                            &prepared,
                                            &config.pinentry,
                                            config.pin_cache.as_ref(),
                                            prompt_desc.as_deref(),
                                            prompt_env.as_deref(),
                                        )
                                        .map(PivResponse::Signed),
                                    },
                                    crate::Error::is_transport_error,
                                ))
                            })?;
                            if matches!(exit, TransactionExit::TransportError) {
                                *session_state
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner) =
                                    PivSessionState::default();
                            }
                            Ok(exit)
                        });
                    });
                },
                |msg| crate::Error::Other(msg.into()),
            )
            .await
    }
}

fn list_keys_in_session(
    slots: &[Slot],
    session: &mut impl PivSlotSession,
    serial: Option<u128>,
) -> Result<Vec<PivKeyInfo>, crate::Error> {
    let mut keys = Vec::new();
    for &slot in slots {
        match read_slot_key(session, slot, serial) {
            Ok(Some(key)) => keys.push(key),
            Ok(None) => {}
            Err(err) if err.is_transport_error() => return Err(err),
            Err(err) => {
                tracing::warn!("failed to read PIV slot {slot:?}: {err}");
            }
        }
    }
    Ok(keys)
}

fn read_slot_key(
    session: &mut impl PivSlotSession,
    slot: Slot,
    serial: Option<u128>,
) -> Result<Option<PivKeyInfo>, crate::Error> {
    let Some(cert) = session.read_certificate(slot)? else {
        return Ok(None);
    };

    let (key_alg, public_key) = keyroost_piv::x509_parse::parse_certificate_public_key(&cert)?;

    Ok(Some(PivKeyInfo {
        slot,
        key_alg,
        public_key,
        serial,
    }))
}

fn is_piv_stale_apdu_error(err: &crate::Error) -> bool {
    let crate::Error::Other(inner) = err else {
        return false;
    };
    matches!(
        inner.downcast_ref::<TransportError>(),
        Some(
            TransportError::Apdu {
                sw1: 0x6A,
                sw2: 0x80 | 0x88,
                ..
            } | TransportError::Apdu {
                sw1: 0x69,
                sw2: 0x85,
                ..
            }
        )
    )
}

#[expect(clippy::too_many_arguments)]
fn sign_raw_in_session(
    session: &mut impl PivSlotSession,
    slot: Slot,
    key_alg: KeyAlg,
    current_serial: Option<u128>,
    expected_serial: Option<u128>,
    prepared: &[u8],
    pinentry: &impl Pinentry,
    pin_cache: Option<&PinCache>,
    prompt_desc: Option<&str>,
    prompt_env: Option<&PinentryEnv>,
) -> Result<CardOperationOutcome<Vec<u8>>, crate::Error> {
    if let Some(expected) = expected_serial
        && current_serial != Some(expected)
    {
        tracing::debug!(
            expected_serial = expected,
            ?current_serial,
            "PIV card serial changed"
        );
        return Ok(CardOperationOutcome::NotFound);
    }

    let pin_policy = session.slot_policy(slot).map(|(pin, _touch)| pin);
    tracing::debug!("slot {:?} PIN policy: {:?}", slot, pin_policy);

    match sign_with_policy(
        session,
        slot,
        key_alg,
        prepared,
        pin_policy,
        current_serial,
        pinentry,
        pin_cache,
        prompt_desc,
        prompt_env,
    ) {
        Ok(Some(signature)) => Ok(CardOperationOutcome::Completed(signature)),
        Ok(None) => Ok(CardOperationOutcome::UserCancelled),
        Err(err) if is_piv_stale_apdu_error(&err) => {
            tracing::debug!(
                slot = ?slot,
                "PIV slot sign failed with stale APDU error: {err}"
            );
            Ok(CardOperationOutcome::NotFound)
        }
        Err(err) => Err(err),
    }
}

trait PivSigner {
    fn verify_pin(&mut self, pin: &[u8]) -> Result<(), TransportError>;
    fn sign(&mut self, slot: Slot, alg: KeyAlg, prepared: &[u8])
    -> Result<Vec<u8>, TransportError>;
}

trait PivSlotSession: PivSigner {
    fn refresh(&mut self) -> Result<Option<u128>, TransportError>;
    fn read_certificate(&mut self, slot: Slot) -> Result<Option<Vec<u8>>, TransportError>;
    fn slot_policy(&mut self, slot: Slot) -> Option<(PinPolicy, keyroost_piv::TouchPolicy)>;
}

impl PivSigner for PivSession<'_> {
    fn verify_pin(&mut self, pin: &[u8]) -> Result<(), TransportError> {
        Self::verify_pin(self, pin)
    }

    fn sign(
        &mut self,
        slot: Slot,
        alg: KeyAlg,
        prepared: &[u8],
    ) -> Result<Vec<u8>, TransportError> {
        Self::sign(self, slot, alg, prepared)
    }
}

impl PivSlotSession for PivSession<'_> {
    fn refresh(&mut self) -> Result<Option<u128>, TransportError> {
        Self::refresh(self)?;
        Ok(self.status().ok().and_then(|status| status.serial))
    }

    fn read_certificate(&mut self, slot: Slot) -> Result<Option<Vec<u8>>, TransportError> {
        Self::read_certificate(self, slot)
    }

    fn slot_policy(&mut self, slot: Slot) -> Option<(PinPolicy, keyroost_piv::TouchPolicy)> {
        Self::slot_policy(self, slot)
    }
}

fn is_piv_wrong_pin(err: &TransportError) -> bool {
    matches!(
        err,
        TransportError::PivPinRejected {
            tries_remaining: Some(1..),
        } | TransportError::PivBadPinLength
    )
}

#[expect(clippy::too_many_arguments)]
fn sign_with_policy(
    signer: &mut impl PivSigner,
    slot: Slot,
    alg: KeyAlg,
    prepared: &[u8],
    pin_policy: Option<PinPolicy>,
    serial: Option<u128>,
    pinentry: &impl Pinentry,
    pin_cache: Option<&PinCache>,
    prompt_desc: Option<&str>,
    prompt_env: Option<&PinentryEnv>,
) -> Result<Option<Vec<u8>>, crate::Error> {
    match pin_policy {
        Some(PinPolicy::Never) => Ok(Some(signer.sign(slot, alg, prepared)?)),
        Some(PinPolicy::Always) => {
            if !verify_pin_with_cache(
                Applet::Piv,
                serial,
                false,
                pin_cache,
                pinentry,
                prompt_desc,
                prompt_env,
                |pin| signer.verify_pin(pin),
                is_piv_wrong_pin,
            )? {
                return Ok(None);
            }
            Ok(Some(signer.sign(slot, alg, prepared)?))
        }
        Some(PinPolicy::Once | PinPolicy::Default) | None => match signer.sign(slot, alg, prepared)
        {
            Ok(signature) => Ok(Some(signature)),
            Err(TransportError::PivSecurityNotSatisfied) => {
                if !verify_pin_with_cache(
                    Applet::Piv,
                    serial,
                    true,
                    pin_cache,
                    pinentry,
                    prompt_desc,
                    prompt_env,
                    |pin| signer.verify_pin(pin),
                    is_piv_wrong_pin,
                )? {
                    return Ok(None);
                }
                Ok(Some(signer.sign(slot, alg, prepared)?))
            }
            Err(err) => Err(err.into()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CardOperationOutcome, PivCard, PivSigner, PivSlotSession, default_slots, parse_slot,
        sign_raw_in_session, sign_with_policy,
    };
    use crate::{
        ConnectionMode,
        pin_cache::PinCache,
        pinentry::{Applet, PinPromptOptions, Pinentry, SystemPinentry},
    };
    use keyroost_piv::{KeyAlg, PinPolicy, Slot};
    use keyroost_transport::TransportError;
    use ssh_agent_lib::secrecy::{ExposeSecret, SecretBox};
    use std::{cell::RefCell, collections::VecDeque, time::Duration};

    #[test]
    fn parse_slot_accepts_hex_and_named_identifiers() {
        assert_eq!(parse_slot("9a"), Ok(Slot::Authentication));
        assert_eq!(parse_slot("9A"), Ok(Slot::Authentication));
        assert_eq!(parse_slot("0x9a"), Ok(Slot::Authentication));
        assert_eq!(parse_slot(" 0X9C "), Ok(Slot::Signature));
        assert_eq!(parse_slot("9d"), Ok(Slot::KeyManagement));
        assert_eq!(parse_slot("9e"), Ok(Slot::CardAuthentication));
        assert_eq!(parse_slot("82"), Ok(Slot::Retired(1)));
        assert_eq!(parse_slot("0x82"), Ok(Slot::Retired(1)));
        assert_eq!(parse_slot("95"), Ok(Slot::Retired(20)));
        assert_eq!(parse_slot("0x95"), Ok(Slot::Retired(20)));

        assert_eq!(parse_slot("authentication"), Ok(Slot::Authentication));
        assert_eq!(parse_slot("auth"), Ok(Slot::Authentication));
        assert_eq!(parse_slot("signature"), Ok(Slot::Signature));
        assert_eq!(parse_slot("sig"), Ok(Slot::Signature));
        assert_eq!(parse_slot("key-management"), Ok(Slot::KeyManagement));
        assert_eq!(parse_slot("keymgmt"), Ok(Slot::KeyManagement));
        assert_eq!(parse_slot("km"), Ok(Slot::KeyManagement));
        assert_eq!(
            parse_slot("card-authentication"),
            Ok(Slot::CardAuthentication)
        );
        assert_eq!(parse_slot("card-auth"), Ok(Slot::CardAuthentication));

        assert_eq!(parse_slot("retired1"), Ok(Slot::Retired(1)));
        assert_eq!(parse_slot("retired-5"), Ok(Slot::Retired(5)));
        assert_eq!(parse_slot("retired_10"), Ok(Slot::Retired(10)));
        assert_eq!(parse_slot("retired20"), Ok(Slot::Retired(20)));
        assert_eq!(parse_slot("r1"), Ok(Slot::Retired(1)));
        assert_eq!(parse_slot("R20"), Ok(Slot::Retired(20)));
    }

    #[test]
    fn parse_slot_rejects_invalid_identifiers() {
        for invalid in [
            "",
            "   ",
            "9b",
            "81",
            "96",
            "0x9f",
            "9a9c",
            "retired",
            "retired0",
            "retired21",
            "retired-0",
            "retired-21",
            "r0",
            "r21",
            "bogus",
        ] {
            assert!(
                parse_slot(invalid).is_err(),
                "expected '{invalid}' to fail parsing"
            );
        }
    }

    #[test]
    fn piv_card_new_defaults_and_deduplicates_explicit_slots() {
        let default_card = PivCard::new(
            "reader".to_owned(),
            None,
            SystemPinentry::default(),
            ConnectionMode::Ephemeral,
            None,
        );
        assert_eq!(default_card.config.slots, default_slots());
        assert!(!default_card.config.slots.contains(&Slot::KeyManagement));
        assert_eq!(default_card.config.slots.len(), 23);

        let custom_card = PivCard::new(
            "reader".to_owned(),
            Some(vec![
                Slot::Signature,
                Slot::KeyManagement,
                Slot::Signature,
                Slot::Authentication,
                Slot::KeyManagement,
            ]),
            SystemPinentry::default(),
            ConnectionMode::Ephemeral,
            None,
        );
        assert_eq!(
            custom_card.config.slots,
            vec![Slot::Signature, Slot::KeyManagement, Slot::Authentication]
        );
    }

    fn secret(pin: &str) -> SecretBox<str> {
        SecretBox::from(Box::<str>::from(pin))
    }

    struct MockPinentry {
        default_pin: Option<&'static str>,
        responses: RefCell<VecDeque<Option<&'static str>>>,
        external_cache: bool,
        calls: RefCell<Vec<(bool, Option<String>)>>,
    }

    impl MockPinentry {
        fn new(pin: Option<&'static str>) -> Self {
            Self {
                default_pin: pin,
                responses: RefCell::new(VecDeque::new()),
                external_cache: false,
                calls: RefCell::new(Vec::new()),
            }
        }

        fn with_external_cache(responses: impl IntoIterator<Item = Option<&'static str>>) -> Self {
            Self {
                default_pin: None,
                responses: RefCell::new(responses.into_iter().collect()),
                external_cache: true,
                calls: RefCell::new(Vec::new()),
            }
        }

        fn prompts(&self) -> usize {
            self.calls.borrow().len()
        }

        fn calls(&self) -> Vec<(bool, Option<String>)> {
            self.calls.borrow().clone()
        }
    }

    impl Pinentry for MockPinentry {
        fn prompt_pin(
            &self,
            _applet: Applet,
            _serial: Option<u128>,
            options: PinPromptOptions<'_>,
        ) -> Result<Option<SecretBox<str>>, crate::Error> {
            self.calls.borrow_mut().push((
                options.allow_external_cache,
                options.error.map(ToOwned::to_owned),
            ));
            let pin = self
                .responses
                .borrow_mut()
                .pop_front()
                .unwrap_or(self.default_pin);
            Ok(pin.map(|value| SecretBox::new(value.to_owned().into_boxed_str())))
        }

        fn external_cache_enabled(&self) -> bool {
            self.external_cache
        }
    }

    type VerifyHandler = fn(&[u8]) -> Result<(), TransportError>;

    struct MockSigner {
        verified: bool,
        verifies: usize,
        verified_pins: Vec<Vec<u8>>,
        signs: usize,
        sign_result: Vec<u8>,
        sign_error: Option<fn() -> TransportError>,
        verify_handler: VerifyHandler,
    }

    impl MockSigner {
        fn new(verified: bool, sign_result: Vec<u8>) -> Self {
            Self {
                verified,
                verifies: 0,
                verified_pins: Vec::new(),
                signs: 0,
                sign_result,
                sign_error: None,
                verify_handler: |pin| {
                    if pin == b"123456" {
                        Ok(())
                    } else {
                        Err(TransportError::PivPinRejected {
                            tries_remaining: Some(2),
                        })
                    }
                },
            }
        }
    }

    impl PivSigner for MockSigner {
        fn verify_pin(&mut self, pin: &[u8]) -> Result<(), TransportError> {
            self.verifies += 1;
            self.verified_pins.push(pin.to_vec());
            (self.verify_handler)(pin)?;
            self.verified = true;
            Ok(())
        }

        fn sign(
            &mut self,
            _slot: Slot,
            _alg: KeyAlg,
            _prepared: &[u8],
        ) -> Result<Vec<u8>, TransportError> {
            self.signs += 1;
            if let Some(err) = self.sign_error {
                return Err(err());
            }
            if !self.verified {
                return Err(TransportError::PivSecurityNotSatisfied);
            }
            Ok(self.sign_result.clone())
        }
    }

    #[test]
    fn never_policy_signs_without_prompting_or_verifying() {
        let mut signer = MockSigner::new(false, vec![1, 2, 3]);
        let pinentry = MockPinentry::new(Some("123456"));

        let res = sign_with_policy(
            &mut signer,
            Slot::CardAuthentication,
            KeyAlg::EccP256,
            b"msg",
            Some(PinPolicy::Never),
            Some(1234),
            &pinentry,
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(res, crate::Error::Other(_)));
        assert_eq!(pinentry.prompts(), 0);
        assert_eq!(signer.verifies, 0);
        assert_eq!(signer.signs, 1);

        let mut verified_signer = MockSigner::new(true, vec![1, 2, 3]);
        let res = sign_with_policy(
            &mut verified_signer,
            Slot::CardAuthentication,
            KeyAlg::EccP256,
            b"msg",
            Some(PinPolicy::Never),
            Some(1234),
            &pinentry,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(res, Some(vec![1, 2, 3]));
        assert_eq!(pinentry.prompts(), 0);
        assert_eq!(verified_signer.verifies, 0);
        assert_eq!(verified_signer.signs, 1);
    }

    #[test]
    fn always_policy_always_prompts_and_verifies_before_signing() {
        let mut signer = MockSigner::new(true, vec![4, 5, 6]);
        let pinentry = MockPinentry::new(Some("123456"));

        let res = sign_with_policy(
            &mut signer,
            Slot::Signature,
            KeyAlg::EccP256,
            b"msg",
            Some(PinPolicy::Always),
            Some(1234),
            &pinentry,
            None,
            None,
            None,
        )
        .unwrap();

        assert_eq!(res, Some(vec![4, 5, 6]));
        assert_eq!(pinentry.prompts(), 1);
        assert_eq!(signer.verifies, 1);
        assert_eq!(signer.signs, 1);
    }

    #[test]
    fn always_policy_returns_none_when_prompt_cancelled() {
        let mut signer = MockSigner::new(false, vec![4, 5, 6]);
        let pinentry = MockPinentry::new(None);

        let res = sign_with_policy(
            &mut signer,
            Slot::Signature,
            KeyAlg::EccP256,
            b"msg",
            Some(PinPolicy::Always),
            Some(1234),
            &pinentry,
            None,
            None,
            None,
        )
        .unwrap();

        assert_eq!(res, None);
        assert_eq!(signer.verifies, 0);
        assert_eq!(signer.signs, 0);
    }

    #[test]
    fn once_policy_skips_prompt_when_already_verified() {
        let mut signer = MockSigner::new(true, vec![7, 8, 9]);
        let pinentry = MockPinentry::new(Some("123456"));

        let res = sign_with_policy(
            &mut signer,
            Slot::Authentication,
            KeyAlg::EccP256,
            b"msg",
            Some(PinPolicy::Once),
            Some(1234),
            &pinentry,
            None,
            None,
            None,
        )
        .unwrap();

        assert_eq!(res, Some(vec![7, 8, 9]));
        assert_eq!(pinentry.prompts(), 0);
        assert_eq!(signer.verifies, 0);
        assert_eq!(signer.signs, 1);
    }

    #[test]
    fn once_policy_prompts_and_verifies_when_security_not_satisfied() {
        let mut signer = MockSigner::new(false, vec![10, 11, 12]);
        let pinentry = MockPinentry::new(Some("123456"));

        let res = sign_with_policy(
            &mut signer,
            Slot::Authentication,
            KeyAlg::EccP256,
            b"msg",
            Some(PinPolicy::Once),
            Some(1234),
            &pinentry,
            None,
            None,
            None,
        )
        .unwrap();

        assert_eq!(res, Some(vec![10, 11, 12]));
        assert_eq!(pinentry.prompts(), 1);
        assert_eq!(signer.verifies, 1);
        assert_eq!(signer.signs, 2);
    }

    #[test]
    fn once_policy_returns_none_when_prompt_cancelled() {
        let mut signer = MockSigner::new(false, vec![10, 11, 12]);
        let pinentry = MockPinentry::new(None);

        let res = sign_with_policy(
            &mut signer,
            Slot::Authentication,
            KeyAlg::EccP256,
            b"msg",
            Some(PinPolicy::Once),
            Some(1234),
            &pinentry,
            None,
            None,
            None,
        )
        .unwrap();

        assert_eq!(res, None);
        assert_eq!(signer.verifies, 0);
        assert_eq!(signer.signs, 1);
    }

    #[test]
    fn missing_and_default_policy_fall_back_safely() {
        for policy in [None, Some(PinPolicy::Default)] {
            let mut signer = MockSigner::new(false, vec![42]);
            let pinentry = MockPinentry::new(Some("123456"));

            let res = sign_with_policy(
                &mut signer,
                Slot::Authentication,
                KeyAlg::EccP256,
                b"msg",
                policy,
                Some(1234),
                &pinentry,
                None,
                None,
                None,
            )
            .unwrap();
            assert_eq!(res, Some(vec![42]));
            assert_eq!(pinentry.prompts(), 1);
            assert_eq!(signer.verifies, 1);
            assert_eq!(signer.signs, 2);

            let mut signer_cached = MockSigner::new(true, vec![43]);
            let pinentry_cached = MockPinentry::new(Some("123456"));
            let res_cached = sign_with_policy(
                &mut signer_cached,
                Slot::Authentication,
                KeyAlg::EccP256,
                b"msg",
                policy,
                Some(1234),
                &pinentry_cached,
                None,
                None,
                None,
            )
            .unwrap();
            assert_eq!(res_cached, Some(vec![43]));
            assert_eq!(pinentry_cached.prompts(), 0);
            assert_eq!(signer_cached.verifies, 0);
            assert_eq!(signer_cached.signs, 1);
        }
    }

    #[test]
    fn once_policy_propagates_non_security_sign_errors_without_prompting() {
        let mut signer = MockSigner::new(false, vec![]);
        signer.sign_error = Some(|| TransportError::PivBadPinLength);
        let pinentry = MockPinentry::new(Some("123456"));

        let err = sign_with_policy(
            &mut signer,
            Slot::Authentication,
            KeyAlg::EccP256,
            b"msg",
            Some(PinPolicy::Once),
            Some(1234),
            &pinentry,
            None,
            None,
            None,
        )
        .unwrap_err();

        assert!(matches!(err, crate::Error::Other(_)));
        assert_eq!(pinentry.prompts(), 0);
        assert_eq!(signer.verifies, 0);
    }

    #[test]
    fn cache_miss_inserts_pin_and_second_sign_hits_cache_and_refreshes_ttl() {
        let cache = PinCache::new(Duration::from_secs(60), None);
        let pinentry = MockPinentry::new(Some("123456"));

        let mut signer1 = MockSigner::new(false, vec![1, 2, 3]);
        let res1 = sign_with_policy(
            &mut signer1,
            Slot::Authentication,
            KeyAlg::EccP256,
            b"msg",
            Some(PinPolicy::Once),
            Some(1234),
            &pinentry,
            Some(&cache),
            None,
            None,
        )
        .unwrap();

        assert_eq!(res1, Some(vec![1, 2, 3]));
        assert_eq!(pinentry.prompts(), 1);
        assert_eq!(signer1.verifies, 1);
        assert_eq!(
            cache
                .get(Applet::Piv, Some(1234))
                .as_ref()
                .map(ExposeSecret::expose_secret),
            Some("123456")
        );
        let expires_before = cache.expires_at(Applet::Piv, Some(1234)).unwrap();

        std::thread::sleep(Duration::from_millis(2));

        let mut signer2 = MockSigner::new(false, vec![4, 5, 6]);
        let res2 = sign_with_policy(
            &mut signer2,
            Slot::Authentication,
            KeyAlg::EccP256,
            b"msg",
            Some(PinPolicy::Once),
            Some(1234),
            &pinentry,
            Some(&cache),
            None,
            None,
        )
        .unwrap();

        assert_eq!(res2, Some(vec![4, 5, 6]));
        assert_eq!(pinentry.prompts(), 1);
        assert_eq!(signer2.verifies, 1);
        assert_eq!(signer2.verified_pins, vec![b"123456".to_vec()]);
        let expires_after = cache.expires_at(Applet::Piv, Some(1234)).unwrap();
        assert!(expires_after > expires_before);
    }

    #[test]
    fn fresh_prompt_verify_failure_does_not_cache_wrong_pin() {
        let cache = PinCache::new(Duration::from_secs(60), None);
        let pinentry = MockPinentry::new(Some("000000"));
        let mut signer = MockSigner::new(false, vec![1, 2, 3]);

        let err = sign_with_policy(
            &mut signer,
            Slot::Authentication,
            KeyAlg::EccP256,
            b"msg",
            Some(PinPolicy::Once),
            Some(1234),
            &pinentry,
            Some(&cache),
            None,
            None,
        )
        .unwrap_err();

        assert!(matches!(err, crate::Error::Other(_)));
        assert_eq!(pinentry.prompts(), 1);
        assert_eq!(signer.verifies, 1);
        assert!(cache.get(Applet::Piv, Some(1234)).is_none());
    }

    #[test]
    fn wrong_cached_pin_evicts_reprompts_and_caches_new_pin() {
        let wrong_pin_handlers: [VerifyHandler; 2] = [
            |pin| {
                if pin == b"123456" {
                    Ok(())
                } else {
                    Err(TransportError::PivPinRejected {
                        tries_remaining: Some(2),
                    })
                }
            },
            |pin| {
                if pin == b"123456" {
                    Ok(())
                } else {
                    Err(TransportError::PivBadPinLength)
                }
            },
        ];

        for handler in wrong_pin_handlers {
            let cache = PinCache::new(Duration::from_secs(60), None);
            cache.insert(Applet::Piv, Some(1234), secret("stale1"));

            let pinentry = MockPinentry::new(Some("123456"));
            let mut signer = MockSigner::new(false, vec![9, 8, 7]);
            signer.verify_handler = handler;

            let res = sign_with_policy(
                &mut signer,
                Slot::Authentication,
                KeyAlg::EccP256,
                b"msg",
                Some(PinPolicy::Once),
                Some(1234),
                &pinentry,
                Some(&cache),
                None,
                None,
            )
            .unwrap();

            assert_eq!(res, Some(vec![9, 8, 7]));
            assert_eq!(pinentry.prompts(), 1);
            assert_eq!(signer.verifies, 2);
            assert_eq!(
                signer.verified_pins,
                vec![b"stale1".to_vec(), b"123456".to_vec()]
            );
            assert_eq!(
                cache
                    .get(Applet::Piv, Some(1234))
                    .as_ref()
                    .map(ExposeSecret::expose_secret),
                Some("123456")
            );
        }
    }

    #[test]
    fn wrong_cached_pin_with_cancelled_reprompt_evicts_and_returns_none() {
        let cache = PinCache::new(Duration::from_secs(60), None);
        cache.insert(Applet::Piv, Some(1234), secret("stale1"));

        let pinentry = MockPinentry::new(None);
        let mut signer = MockSigner::new(false, vec![9, 8, 7]);

        let res = sign_with_policy(
            &mut signer,
            Slot::Authentication,
            KeyAlg::EccP256,
            b"msg",
            Some(PinPolicy::Once),
            Some(1234),
            &pinentry,
            Some(&cache),
            None,
            None,
        )
        .unwrap();

        assert_eq!(res, None);
        assert_eq!(pinentry.prompts(), 1);
        assert_eq!(signer.verifies, 1);
        assert!(cache.get(Applet::Piv, Some(1234)).is_none());
    }

    #[test]
    fn non_wrong_pin_error_on_cache_hit_evicts_without_reprompting() {
        let fatal_handlers: [VerifyHandler; 3] = [
            |_| {
                Err(TransportError::PivPinRejected {
                    tries_remaining: Some(0),
                })
            },
            |_| {
                Err(TransportError::PivPinRejected {
                    tries_remaining: None,
                })
            },
            |_| Err(TransportError::NoPivApplet),
        ];

        for handler in fatal_handlers {
            let cache = PinCache::new(Duration::from_secs(60), None);
            cache.insert(Applet::Piv, Some(1234), secret("123456"));

            let pinentry = MockPinentry::new(Some("123456"));
            let mut signer = MockSigner::new(false, vec![9, 8, 7]);
            signer.verify_handler = handler;

            let err = sign_with_policy(
                &mut signer,
                Slot::Authentication,
                KeyAlg::EccP256,
                b"msg",
                Some(PinPolicy::Once),
                Some(1234),
                &pinentry,
                Some(&cache),
                None,
                None,
            )
            .unwrap_err();

            assert!(matches!(err, crate::Error::Other(_)));
            assert_eq!(pinentry.prompts(), 0);
            assert_eq!(signer.verifies, 1);
            assert!(cache.get(Applet::Piv, Some(1234)).is_none());
        }
    }

    #[test]
    fn always_policy_bypasses_cache_for_reads_and_writes() {
        // With an empty cache, Always prompts and does not insert the entered PIN.
        let empty_cache = PinCache::new(Duration::from_secs(60), None);
        let pinentry = MockPinentry::new(Some("123456"));
        let mut signer = MockSigner::new(false, vec![1, 2, 3]);

        let res = sign_with_policy(
            &mut signer,
            Slot::Signature,
            KeyAlg::EccP256,
            b"msg",
            Some(PinPolicy::Always),
            Some(1234),
            &pinentry,
            Some(&empty_cache),
            None,
            None,
        )
        .unwrap();

        assert_eq!(res, Some(vec![1, 2, 3]));
        assert_eq!(pinentry.prompts(), 1);
        assert_eq!(signer.verifies, 1);
        assert!(empty_cache.get(Applet::Piv, Some(1234)).is_none());

        // Even when a PIN is already cached, Always prompts and uses the prompted PIN.
        let populated_cache = PinCache::new(Duration::from_secs(60), None);
        populated_cache.insert(Applet::Piv, Some(1234), secret("cached"));
        let pinentry2 = MockPinentry::new(Some("123456"));
        let mut signer2 = MockSigner::new(false, vec![4, 5, 6]);

        let res2 = sign_with_policy(
            &mut signer2,
            Slot::Signature,
            KeyAlg::EccP256,
            b"msg",
            Some(PinPolicy::Always),
            Some(1234),
            &pinentry2,
            Some(&populated_cache),
            None,
            None,
        )
        .unwrap();

        assert_eq!(res2, Some(vec![4, 5, 6]));
        assert_eq!(pinentry2.prompts(), 1);
        assert_eq!(signer2.verified_pins, vec![b"123456".to_vec()]);
        assert_eq!(
            populated_cache
                .get(Applet::Piv, Some(1234))
                .as_ref()
                .map(ExposeSecret::expose_secret),
            Some("cached")
        );
    }

    #[test]
    fn external_cache_wrong_pin_retries_once_without_external_cache_and_with_error() {
        let pinentry = MockPinentry::with_external_cache([Some("stale1"), Some("123456")]);
        let mut signer = MockSigner::new(false, vec![1, 2, 3]);

        let res = sign_with_policy(
            &mut signer,
            Slot::Authentication,
            KeyAlg::EccP256,
            b"msg",
            Some(PinPolicy::Once),
            Some(1234),
            &pinentry,
            None,
            None,
            None,
        )
        .unwrap();

        assert_eq!(res, Some(vec![1, 2, 3]));
        assert_eq!(
            pinentry.calls(),
            vec![(true, None), (false, Some("Incorrect PIN".to_owned()))]
        );
        assert_eq!(
            signer.verified_pins,
            vec![b"stale1".to_vec(), b"123456".to_vec()]
        );

        // If retry also fails with wrong PIN, it propagates the error without looping.
        let pinentry2 = MockPinentry::with_external_cache([Some("stale1"), Some("wrong2")]);
        let mut signer2 = MockSigner::new(false, vec![1, 2, 3]);
        let err = sign_with_policy(
            &mut signer2,
            Slot::Authentication,
            KeyAlg::EccP256,
            b"msg",
            Some(PinPolicy::Once),
            Some(1234),
            &pinentry2,
            None,
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, crate::Error::Other(_)));
        assert_eq!(
            pinentry2.calls(),
            vec![(true, None), (false, Some("Incorrect PIN".to_owned()))]
        );
        assert_eq!(signer2.verifies, 2);
    }

    #[test]
    fn external_cache_always_policy_never_enables_external_cache_or_retries() {
        let pinentry = MockPinentry::with_external_cache([Some("wrong1"), Some("123456")]);
        let mut signer = MockSigner::new(false, vec![1, 2, 3]);

        let err = sign_with_policy(
            &mut signer,
            Slot::Signature,
            KeyAlg::EccP256,
            b"msg",
            Some(PinPolicy::Always),
            Some(1234),
            &pinentry,
            None,
            None,
            None,
        )
        .unwrap_err();

        assert!(matches!(err, crate::Error::Other(_)));
        assert_eq!(pinentry.calls(), vec![(false, None)]);
        assert_eq!(signer.verifies, 1);
    }

    #[derive(Debug, PartialEq, Eq)]
    enum MockErr {
        App,
        Transport,
        WorkerGone(&'static str),
    }

    impl MockErr {
        fn is_transport(&self) -> bool {
            matches!(self, Self::Transport)
        }
    }

    #[derive(Clone, Copy)]
    enum MockReq {
        Ping,
        AppErr,
        TransportErr,
    }

    struct MockCounters {
        opens: std::sync::atomic::AtomicUsize,
        active: std::sync::atomic::AtomicUsize,
        status_reads: std::sync::atomic::AtomicUsize,
        fail_next_open: std::sync::atomic::AtomicBool,
    }

    impl MockCounters {
        fn new() -> std::sync::Arc<Self> {
            std::sync::Arc::new(Self {
                opens: std::sync::atomic::AtomicUsize::new(0),
                active: std::sync::atomic::AtomicUsize::new(0),
                status_reads: std::sync::atomic::AtomicUsize::new(0),
                fail_next_open: std::sync::atomic::AtomicBool::new(false),
            })
        }
    }

    struct ActiveGuard(std::sync::Arc<MockCounters>);

    impl Drop for ActiveGuard {
        fn drop(&mut self) {
            self.0
                .active
                .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    async fn send_mock(
        worker: &super::PersistentWorker<MockReq, usize, MockErr>,
        counters: &std::sync::Arc<MockCounters>,
        req: MockReq,
    ) -> Result<usize, MockErr> {
        let counters = std::sync::Arc::clone(counters);
        worker
            .send_request(
                req,
                move |rx| {
                    std::thread::spawn(move || {
                        super::run_worker(&rx, |pending, rx| {
                            if counters
                                .fail_next_open
                                .swap(false, std::sync::atomic::Ordering::SeqCst)
                            {
                                return Err(MockErr::Transport);
                            }
                            let session_id = counters
                                .opens
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                                + 1;
                            counters
                                .active
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            let _guard = ActiveGuard(std::sync::Arc::clone(&counters));
                            counters
                                .status_reads
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            let (first_req, first_reply) = pending.take().unwrap();
                            Ok(super::serve_in_transaction(
                                first_req,
                                first_reply,
                                rx,
                                |req| match req {
                                    MockReq::Ping => Ok(session_id),
                                    MockReq::AppErr => Err(MockErr::App),
                                    MockReq::TransportErr => Err(MockErr::Transport),
                                },
                                MockErr::is_transport,
                            ))
                        });
                    });
                },
                MockErr::WorkerGone,
            )
            .await
    }

    #[tokio::test]
    async fn persistent_worker_lazily_opens_and_reuses_transaction_reading_status_once() {
        let counters = MockCounters::new();
        let worker = super::PersistentWorker::new();

        assert_eq!(counters.opens.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(
            counters
                .status_reads
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );

        assert_eq!(send_mock(&worker, &counters, MockReq::Ping).await, Ok(1));
        assert_eq!(send_mock(&worker, &counters, MockReq::Ping).await, Ok(1));
        assert_eq!(counters.opens.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(
            counters
                .status_reads
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(counters.active.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn persistent_worker_keeps_session_on_non_transport_error() {
        let counters = MockCounters::new();
        let worker = super::PersistentWorker::new();

        assert_eq!(send_mock(&worker, &counters, MockReq::Ping).await, Ok(1));
        assert_eq!(
            send_mock(&worker, &counters, MockReq::AppErr).await,
            Err(MockErr::App)
        );
        assert_eq!(send_mock(&worker, &counters, MockReq::Ping).await, Ok(1));
        assert_eq!(counters.opens.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn persistent_worker_drops_and_reopens_session_on_transport_error() {
        let counters = MockCounters::new();
        let worker = super::PersistentWorker::new();

        assert_eq!(send_mock(&worker, &counters, MockReq::Ping).await, Ok(1));
        assert_eq!(
            send_mock(&worker, &counters, MockReq::TransportErr).await,
            Err(MockErr::Transport)
        );
        assert_eq!(send_mock(&worker, &counters, MockReq::Ping).await, Ok(2));
        assert_eq!(counters.opens.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert_eq!(
            counters
                .status_reads
                .load(std::sync::atomic::Ordering::SeqCst),
            2
        );
        assert_eq!(counters.active.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn persistent_worker_disconnect_drops_session_synchronously_and_reopens_next() {
        let counters = MockCounters::new();
        let worker = super::PersistentWorker::new();

        assert_eq!(send_mock(&worker, &counters, MockReq::Ping).await, Ok(1));
        assert_eq!(counters.active.load(std::sync::atomic::Ordering::SeqCst), 1);

        worker.disconnect().await;
        assert_eq!(counters.active.load(std::sync::atomic::Ordering::SeqCst), 0);

        // Disconnecting while already disconnected is a no-op.
        worker.disconnect().await;
        assert_eq!(counters.active.load(std::sync::atomic::Ordering::SeqCst), 0);

        assert_eq!(send_mock(&worker, &counters, MockReq::Ping).await, Ok(2));
        assert_eq!(counters.opens.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert_eq!(counters.active.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn persistent_worker_clone_shares_active_transaction() {
        let counters = MockCounters::new();
        let worker_a = super::PersistentWorker::new();
        let worker_b = worker_a.clone();

        assert_eq!(send_mock(&worker_a, &counters, MockReq::Ping).await, Ok(1));
        assert_eq!(send_mock(&worker_b, &counters, MockReq::Ping).await, Ok(1));
        assert_eq!(counters.opens.load(std::sync::atomic::Ordering::SeqCst), 1);

        worker_b.disconnect().await;
        assert_eq!(counters.active.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(send_mock(&worker_a, &counters, MockReq::Ping).await, Ok(2));
    }

    #[tokio::test]
    async fn persistent_worker_propagates_open_failure_and_retries_next_request() {
        let counters = MockCounters::new();
        let worker = super::PersistentWorker::new();
        counters
            .fail_next_open
            .store(true, std::sync::atomic::Ordering::SeqCst);

        assert_eq!(
            send_mock(&worker, &counters, MockReq::Ping).await,
            Err(MockErr::Transport)
        );
        assert_eq!(counters.opens.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(send_mock(&worker, &counters, MockReq::Ping).await, Ok(1));
        assert_eq!(counters.opens.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    struct MockSlotSession {
        signer: MockSigner,
        refreshes: usize,
        cert_reads: usize,
        refreshed_serial: Option<u128>,
        policy: Option<(PinPolicy, keyroost_piv::TouchPolicy)>,
    }

    impl MockSlotSession {
        fn new(verified: bool, sign_result: Vec<u8>) -> Self {
            Self {
                signer: MockSigner::new(verified, sign_result),
                refreshes: 0,
                cert_reads: 0,
                refreshed_serial: Some(42),
                policy: Some((PinPolicy::Once, keyroost_piv::TouchPolicy::Never)),
            }
        }
    }

    impl PivSigner for MockSlotSession {
        fn verify_pin(&mut self, pin: &[u8]) -> Result<(), TransportError> {
            self.signer.verify_pin(pin)
        }

        fn sign(
            &mut self,
            slot: Slot,
            alg: KeyAlg,
            prepared: &[u8],
        ) -> Result<Vec<u8>, TransportError> {
            self.signer.sign(slot, alg, prepared)
        }
    }

    impl PivSlotSession for MockSlotSession {
        fn refresh(&mut self) -> Result<Option<u128>, TransportError> {
            self.refreshes += 1;
            Ok(self.refreshed_serial)
        }

        fn read_certificate(&mut self, _slot: Slot) -> Result<Option<Vec<u8>>, TransportError> {
            self.cert_reads += 1;
            Ok(None)
        }

        fn slot_policy(&mut self, _slot: Slot) -> Option<(PinPolicy, keyroost_piv::TouchPolicy)> {
            self.policy
        }
    }

    #[test]
    fn sign_raw_signs_directly_when_serial_matches() {
        let mut session = MockSlotSession::new(true, vec![0xAA; 64]);
        let pinentry = MockPinentry::new(Some("123456"));

        let outcome = sign_raw_in_session(
            &mut session,
            Slot::Authentication,
            KeyAlg::Ed25519,
            Some(42),
            Some(42),
            b"challenge",
            &pinentry,
            None,
            None,
            None,
        )
        .unwrap();

        assert_eq!(outcome, CardOperationOutcome::Completed(vec![0xAA; 64]));
        assert_eq!(session.refreshes, 0);
        assert_eq!(session.cert_reads, 0);
        assert_eq!(session.signer.signs, 1);
    }

    #[test]
    fn sign_raw_returns_not_found_on_serial_mismatch_without_signing() {
        let mut session = MockSlotSession::new(true, vec![0xAA; 64]);
        let pinentry = MockPinentry::new(Some("123456"));

        let outcome = sign_raw_in_session(
            &mut session,
            Slot::Authentication,
            KeyAlg::Ed25519,
            Some(99),
            Some(42),
            b"challenge",
            &pinentry,
            None,
            None,
            None,
        )
        .unwrap();

        assert_eq!(outcome, CardOperationOutcome::NotFound);
        assert_eq!(session.signer.signs, 0);
        assert_eq!(pinentry.prompts(), 0);
    }

    #[test]
    fn sign_raw_returns_not_found_on_stale_apdu_and_user_cancelled_on_cancel() {
        let mut stale_session = MockSlotSession::new(true, vec![]);
        stale_session.signer.sign_error = Some(|| TransportError::Apdu {
            label: "GENERAL AUTHENTICATE",
            sw1: 0x6A,
            sw2: 0x88,
        });
        let pinentry = MockPinentry::new(Some("123456"));

        let outcome = sign_raw_in_session(
            &mut stale_session,
            Slot::Authentication,
            KeyAlg::Ed25519,
            Some(42),
            Some(42),
            b"challenge",
            &pinentry,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(outcome, CardOperationOutcome::NotFound);

        let mut cancel_session = MockSlotSession::new(false, vec![0xAA; 64]);
        let cancel_pinentry = MockPinentry::new(None);
        let cancel_outcome = sign_raw_in_session(
            &mut cancel_session,
            Slot::Authentication,
            KeyAlg::Ed25519,
            Some(42),
            Some(42),
            b"challenge",
            &cancel_pinentry,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(cancel_outcome, CardOperationOutcome::UserCancelled);
        assert_eq!(cancel_pinentry.prompts(), 1);
    }
}
