use std::sync::{Arc, Mutex, mpsc};

use tokio::sync::oneshot;

use keyroost_piv::{
    KeyAlg, PinPolicy, PublicKey, Slot,
    x509::{SigHash, X509Error},
};
use keyroost_transport::{PivSession, PivSessionState, TransportError};
use sha2::Digest;
use ssh_agent_lib::{
    proto::{Identity, PublicCredential},
    ssh_key::{
        Algorithm, HashAlg, Mpint, Signature,
        public::{EcdsaPublicKey, Ed25519PublicKey, KeyData, RsaPublicKey},
        sec1::EncodedPoint,
    },
};

use crate::{
    ConnectionMode,
    identity_cache::{PivCachedIdentity, SignOutcome, SignResult},
    pin_cache::{PinCache, verify_pin_with_cache},
    pinentry::{Applet, Pinentry, SystemPinentry},
};

struct PivIdentity {
    slot: Slot,
    key_alg: KeyAlg,
    ssh_identity: Identity,
}

#[derive(Clone)]
struct PivConfig {
    slots: Vec<Slot>,
    pinentry: SystemPinentry,
    pin_cache: Option<PinCache>,
}

enum PivRequest {
    ListIdentities,
    Sign {
        credential: Box<PublicCredential>,
        cached: Option<PivCachedIdentity>,
        data: Vec<u8>,
        rsa_sig_hash: Option<HashAlg>,
    },
}

enum PivResponse {
    Identities(Vec<(Identity, PivCachedIdentity)>),
    Signature(SignResult<PivCachedIdentity>),
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
pub(super) struct PivSshAgent {
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

impl PivSshAgent {
    pub(super) fn new(
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

    pub(super) async fn disconnect(&self) {
        if let PivBackend::Persistent(worker) = &self.backend {
            worker.disconnect().await;
        }
    }

    pub(super) fn probe_identities(
        reader: &str,
        slots: Option<Vec<Slot>>,
    ) -> Result<bool, crate::Error> {
        let slots = match slots {
            Some(slots) => dedup_slots(slots),
            None => default_slots(),
        };
        PivSession::with_transaction(reader, |session| {
            let serial = session.status().ok().and_then(|status| status.serial);
            list_ssh_identities(&slots, session, serial).map(|ids| !ids.is_empty())
        })
    }

    pub(super) async fn request_identities_with_metadata(
        &self,
    ) -> Result<Vec<(Identity, PivCachedIdentity)>, crate::Error> {
        match &self.backend {
            PivBackend::Ephemeral => {
                tracing::debug!(
                    connection_mode = ?ConnectionMode::Ephemeral,
                    "requesting PIV identities"
                );
                let reader = self.reader.clone();
                let slots = self.config.slots.clone();
                let session_state = Arc::clone(&self.session_state);
                tokio::task::spawn_blocking(move || {
                    with_piv_transaction(&reader, &session_state, |session| {
                        let serial = session.status().ok().and_then(|status| status.serial);
                        list_ssh_identities(&slots, session, serial)
                    })
                })
                .await
                .map_err(|err| crate::Error::Other(Box::new(err)))?
            }
            PivBackend::Persistent(worker) => {
                tracing::debug!(
                    connection_mode = ?ConnectionMode::Persistent,
                    "requesting PIV identities"
                );
                let response = self
                    .send_persistent(worker, PivRequest::ListIdentities)
                    .await?;
                match response {
                    PivResponse::Identities(identities) => Ok(identities),
                    PivResponse::Signature(_) => {
                        Err(crate::Error::Other("unexpected PIV worker response".into()))
                    }
                }
            }
        }
    }

    pub(super) async fn sign(
        &self,
        public_credential: &PublicCredential,
        cached: Option<PivCachedIdentity>,
        data: &[u8],
        rsa_sig_hash: Option<HashAlg>,
    ) -> Result<SignResult<PivCachedIdentity>, crate::Error> {
        match self
            .sign_once(public_credential, cached, data, rsa_sig_hash)
            .await
        {
            Err(err) if cached.is_some() && err.is_transport_error() => {
                tracing::debug!(
                    "cached PIV sign hit transport error, retrying with fresh scan: {err}"
                );
                self.sign_once(public_credential, None, data, rsa_sig_hash)
                    .await
            }
            other => other,
        }
    }

    async fn sign_once(
        &self,
        public_credential: &PublicCredential,
        cached: Option<PivCachedIdentity>,
        data: &[u8],
        rsa_sig_hash: Option<HashAlg>,
    ) -> Result<SignResult<PivCachedIdentity>, crate::Error> {
        match &self.backend {
            PivBackend::Ephemeral => {
                let reader = self.reader.clone();
                let config = self.config.clone();
                let session_state = Arc::clone(&self.session_state);
                let public_credential = public_credential.clone();
                let data = data.to_vec();
                tokio::task::spawn_blocking(move || {
                    with_piv_transaction(&reader, &session_state, |session| {
                        let mut serial = session.status().ok().and_then(|status| status.serial);
                        sign_in_session(
                            &config.slots,
                            session,
                            &mut serial,
                            &public_credential,
                            cached,
                            &data,
                            rsa_sig_hash,
                            &config.pinentry,
                            config.pin_cache.as_ref(),
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
                        PivRequest::Sign {
                            credential: Box::new(public_credential.clone()),
                            cached,
                            data: data.to_vec(),
                            rsa_sig_hash,
                        },
                    )
                    .await?;
                match response {
                    PivResponse::Signature(result) => Ok(result),
                    PivResponse::Identities(_) => {
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
                                        PivRequest::ListIdentities => {
                                            list_ssh_identities(&config.slots, session, serial)
                                                .map(PivResponse::Identities)
                                        }
                                        PivRequest::Sign {
                                            credential,
                                            cached,
                                            data,
                                            rsa_sig_hash,
                                        } => sign_in_session(
                                            &config.slots,
                                            session,
                                            &mut serial,
                                            &credential,
                                            cached,
                                            &data,
                                            rsa_sig_hash,
                                            &config.pinentry,
                                            config.pin_cache.as_ref(),
                                        )
                                        .map(PivResponse::Signature),
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

fn list_identities(
    slots: &[Slot],
    session: &mut impl PivSlotSession,
    serial: Option<u128>,
) -> Result<Vec<PivIdentity>, crate::Error> {
    let mut identities = Vec::new();
    for &slot in slots {
        match slot_to_ssh_identity(session, slot, serial) {
            Ok(Some(identity)) => identities.push(identity),
            Ok(None) => {}
            Err(err) if err.is_transport_error() => return Err(err),
            Err(err) => {
                tracing::warn!("failed to configure slot {slot:?} as PIV identity: {err}");
            }
        }
    }
    Ok(identities)
}

fn list_ssh_identities(
    slots: &[Slot],
    session: &mut impl PivSlotSession,
    serial: Option<u128>,
) -> Result<Vec<(Identity, PivCachedIdentity)>, crate::Error> {
    let identities = list_identities(slots, session, serial)?;
    Ok(identities
        .into_iter()
        .inspect(|id| tracing::info!("found usable identity on slot {:?}", id.slot))
        .map(|id| {
            let meta = PivCachedIdentity {
                slot: id.slot,
                key_alg: id.key_alg,
                serial,
            };
            (id.ssh_identity, meta)
        })
        .collect())
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
fn sign_in_session(
    slots: &[Slot],
    session: &mut impl PivSlotSession,
    serial: &mut Option<u128>,
    public_credential: &PublicCredential,
    cached: Option<PivCachedIdentity>,
    data: &[u8],
    rsa_sig_hash: Option<HashAlg>,
    pinentry: &impl Pinentry,
    pin_cache: Option<&PinCache>,
) -> Result<SignResult<PivCachedIdentity>, crate::Error> {
    if let Some(cached) = cached {
        if *serial == cached.serial {
            match sign_slot(
                session,
                cached.slot,
                cached.key_alg,
                *serial,
                data,
                rsa_sig_hash,
                pinentry,
                pin_cache,
            ) {
                Ok(Some(signature)) => {
                    return Ok(SignResult {
                        discovered: None,
                        outcome: SignOutcome::Signed(signature),
                    });
                }
                Ok(None) => {
                    return Ok(SignResult {
                        discovered: None,
                        outcome: SignOutcome::UserCancelled,
                    });
                }
                Err(err) if is_piv_stale_apdu_error(&err) => {
                    tracing::debug!(
                        slot = ?cached.slot,
                        "cached PIV slot sign failed with stale APDU error, re-scanning: {err}"
                    );
                }
                Err(err) => return Err(err),
            }
        } else {
            tracing::debug!(
                cached_serial = ?cached.serial,
                current_serial = ?*serial,
                "PIV card serial changed; re-scanning slots"
            );
        }
    }

    *serial = session.refresh()?;
    let identities = list_identities(slots, session, *serial)?;
    let discovered: Vec<(PublicCredential, PivCachedIdentity)> = identities
        .iter()
        .map(|id| {
            (
                id.ssh_identity.credential.clone(),
                PivCachedIdentity {
                    slot: id.slot,
                    key_alg: id.key_alg,
                    serial: *serial,
                },
            )
        })
        .collect();

    let piv_identity = identities
        .into_iter()
        .find(|id| &id.ssh_identity.credential == public_credential);

    let Some(piv_identity) = piv_identity else {
        tracing::debug!("not matching PIV identity for requested public key");
        return Ok(SignResult {
            discovered: Some(discovered),
            outcome: SignOutcome::NotFound,
        });
    };

    let outcome = match sign_slot(
        session,
        piv_identity.slot,
        piv_identity.key_alg,
        *serial,
        data,
        rsa_sig_hash,
        pinentry,
        pin_cache,
    )? {
        Some(signature) => SignOutcome::Signed(signature),
        None => SignOutcome::UserCancelled,
    };

    Ok(SignResult {
        discovered: Some(discovered),
        outcome,
    })
}

#[expect(clippy::too_many_arguments)]
fn sign_slot(
    session: &mut impl PivSlotSession,
    slot: Slot,
    key_alg: KeyAlg,
    serial: Option<u128>,
    data: &[u8],
    rsa_sig_hash: Option<HashAlg>,
    pinentry: &impl Pinentry,
    pin_cache: Option<&PinCache>,
) -> Result<Option<Signature>, crate::Error> {
    let sig_hash = match keyroost_piv::x509::signature_hash(key_alg) {
        Ok(sig_hash) => sig_hash,
        Err(X509Error::UnsupportedAlgorithm) => return Ok(None),
        Err(other) => return Err(crate::Error::Other(Box::new(other))),
    };

    let prepared = match sig_hash {
        SigHash::Sha256 => sha2::Sha256::digest(data).to_vec(),
        SigHash::Sha384 => sha2::Sha384::digest(data).to_vec(),
        SigHash::Sha512 => sha2::Sha512::digest(data).to_vec(),
        SigHash::None => data.to_vec(),
    };

    let pin_policy = session.slot_policy(slot).map(|(pin, _touch)| pin);
    tracing::debug!("slot {:?} PIN policy: {:?}", slot, pin_policy);

    let Some(signature) = sign_with_policy(
        session, slot, key_alg, &prepared, pin_policy, serial, pinentry, pin_cache,
    )?
    else {
        return Ok(None);
    };

    let signature = match key_alg {
        KeyAlg::EccP256 => {
            Signature::try_from(ecdsa::Signature::<p256::NistP256>::from_der(&signature)?)?
        }
        KeyAlg::EccP384 => {
            Signature::try_from(ecdsa::Signature::<p384::NistP384>::from_der(&signature)?)?
        }
        KeyAlg::EccP521 => {
            Signature::try_from(ecdsa::Signature::<p521::NistP521>::from_der(&signature)?)?
        }

        KeyAlg::Ed25519 => {
            Signature::new(ssh_agent_lib::ssh_key::Algorithm::Ed25519, signature)?
        }
        KeyAlg::Rsa1024 | KeyAlg::Rsa2048 | KeyAlg::Rsa3072 | KeyAlg::Rsa4096 => {
            let signature = match rsa_sig_hash {
                Some(HashAlg::Sha256) => sha2::Sha256::digest(signature).to_vec(),
                Some(HashAlg::Sha512) => sha2::Sha512::digest(signature).to_vec(),
                None => signature,
                Some(other) => {
                    return Err(crate::Error::Other(
                        format!("Unsupported RSA hash algorithm {other}").into(),
                    ));
                }
            };
            Signature::new(Algorithm::Rsa { hash: rsa_sig_hash }, signature)?
        }
        KeyAlg::X25519 => {
            return Err(crate::Error::Other(
                "Unsupported signature algorithm X25519".into(),
            ));
        }
    };

    Ok(Some(signature))
}

fn slot_to_ssh_identity(
    session: &mut impl PivSlotSession,
    slot: Slot,
    serial: Option<u128>,
) -> Result<Option<PivIdentity>, crate::Error> {
    let Some(cert) = session.read_certificate(slot)? else {
        return Ok(None);
    };

    let (key_alg, public_key) = keyroost_piv::x509_parse::parse_certificate_public_key(&cert)?;

    let comment = if let Some(serial) = serial {
        format!("PIV {serial}:{slot:?}")
    } else {
        format!("PIV {slot:?}")
    };
    Ok(Some(PivIdentity {
        slot,
        key_alg,
        ssh_identity: Identity {
            credential: ssh_public_credentials(key_alg, public_key)?,
            comment,
        },
    }))
}

fn ssh_public_credentials(
    key_alg: KeyAlg,
    public_key: PublicKey,
) -> Result<PublicCredential, crate::Error> {
    let key_data = match public_key {
        PublicKey::Rsa { modulus, exponent } => KeyData::Rsa(RsaPublicKey {
            n: Mpint::from_bytes(&modulus)?,
            e: Mpint::from_bytes(&exponent)?,
        }),
        PublicKey::Ecc { point } => match key_alg {
            KeyAlg::EccP256 => {
                KeyData::Ecdsa(EcdsaPublicKey::NistP256(EncodedPoint::from_bytes(&point)?))
            }
            KeyAlg::EccP384 => {
                KeyData::Ecdsa(EcdsaPublicKey::NistP384(EncodedPoint::from_bytes(&point)?))
            }
            KeyAlg::EccP521 => {
                KeyData::Ecdsa(EcdsaPublicKey::NistP521(EncodedPoint::from_bytes(&point)?))
            }
            KeyAlg::Ed25519 => KeyData::Ed25519(Ed25519PublicKey::try_from(point.as_slice())?),
            KeyAlg::Rsa1024 | KeyAlg::Rsa2048 | KeyAlg::Rsa3072 | KeyAlg::Rsa4096 => {
                return Err(crate::Error::Other(
                    format!("Invalid KeyAlg {key_alg:?} and for PublicKey::Ecc").into(),
                ));
            }
            KeyAlg::X25519 => {
                // NOTE: this is technically unreachable because keyroost_piv::x509::signature_hash will already have returned "not supported"
                return Err(crate::Error::SshKey(
                    ssh_agent_lib::ssh_key::Error::AlgorithmUnknown,
                ));
            }
        },
    };
    Ok(PublicCredential::Key(key_data))
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
    use super::{PivSigner, PivSshAgent, default_slots, parse_slot, sign_with_policy};
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
    fn piv_agent_new_defaults_and_deduplicates_explicit_slots() {
        let default_agent = PivSshAgent::new(
            "reader".to_owned(),
            None,
            SystemPinentry::default(),
            ConnectionMode::Ephemeral,
            None,
        );
        assert_eq!(default_agent.config.slots, default_slots());
        assert!(!default_agent.config.slots.contains(&Slot::KeyManagement));
        assert_eq!(default_agent.config.slots.len(), 23);

        let custom_agent = PivSshAgent::new(
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
            custom_agent.config.slots,
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
        let mut signer = MockSigner::new(true, vec![1, 2, 3]);
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
        )
        .unwrap();

        assert_eq!(res, Some(vec![1, 2, 3]));
        assert_eq!(pinentry.prompts(), 0);
        assert_eq!(signer.verifies, 0);
        assert_eq!(signer.signs, 1);
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
    }

    #[tokio::test]
    async fn persistent_worker_disconnect_drops_session_synchronously_and_reopens_next() {
        let counters = MockCounters::new();
        let worker = super::PersistentWorker::new();

        // Disconnect before any request is a no-op and does not open a session.
        worker.disconnect().await;
        assert_eq!(counters.opens.load(std::sync::atomic::Ordering::SeqCst), 0);

        assert_eq!(send_mock(&worker, &counters, MockReq::Ping).await, Ok(1));
        assert_eq!(counters.active.load(std::sync::atomic::Ordering::SeqCst), 1);

        worker.disconnect().await;
        assert_eq!(counters.active.load(std::sync::atomic::Ordering::SeqCst), 0);

        // Next request lazily opens a new transaction.
        assert_eq!(send_mock(&worker, &counters, MockReq::Ping).await, Ok(2));
        assert_eq!(counters.opens.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert_eq!(counters.active.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn persistent_worker_clone_shares_active_transaction() {
        let counters = MockCounters::new();
        let worker1 = super::PersistentWorker::new();
        let worker2 = worker1.clone();

        assert_eq!(send_mock(&worker1, &counters, MockReq::Ping).await, Ok(1));
        assert_eq!(send_mock(&worker2, &counters, MockReq::Ping).await, Ok(1));
        assert_eq!(counters.opens.load(std::sync::atomic::Ordering::SeqCst), 1);

        worker2.disconnect().await;
        assert_eq!(counters.active.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(send_mock(&worker1, &counters, MockReq::Ping).await, Ok(2));
    }

    #[tokio::test]
    async fn persistent_worker_propagates_open_failure_and_retries_next_request() {
        let counters = MockCounters::new();
        counters
            .fail_next_open
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let worker = super::PersistentWorker::new();

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
        refreshed_serial: Option<u128>,
        cert_reads: usize,
        policy: Option<(PinPolicy, keyroost_piv::TouchPolicy)>,
    }

    impl MockSlotSession {
        fn new(verified: bool, sign_result: Vec<u8>) -> Self {
            Self {
                signer: MockSigner::new(verified, sign_result),
                refreshes: 0,
                refreshed_serial: Some(42),
                cert_reads: 0,
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

    impl super::PivSlotSession for MockSlotSession {
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

    fn dummy_ed25519_cred() -> ssh_agent_lib::proto::PublicCredential {
        ssh_agent_lib::proto::PublicCredential::Key(
            ssh_agent_lib::ssh_key::public::KeyData::Ed25519(
                ssh_agent_lib::ssh_key::public::Ed25519PublicKey([0x11; 32]),
            ),
        )
    }

    #[test]
    fn sign_cached_signs_directly_without_reading_certificates() {
        let mut session = MockSlotSession::new(true, vec![0xAA; 64]);
        let pinentry = MockPinentry::new(Some("123456"));
        let cached = crate::identity_cache::PivCachedIdentity {
            slot: Slot::Authentication,
            key_alg: KeyAlg::Ed25519,
            serial: Some(42),
        };
        let mut serial = Some(42);

        let result = super::sign_in_session(
            &[Slot::Authentication, Slot::Signature],
            &mut session,
            &mut serial,
            &dummy_ed25519_cred(),
            Some(cached),
            b"challenge",
            None,
            &pinentry,
            None,
        )
        .unwrap();

        assert!(result.discovered.is_none());
        assert!(matches!(
            result.outcome,
            crate::identity_cache::SignOutcome::Signed(_)
        ));
        assert_eq!(session.refreshes, 0);
        assert_eq!(session.cert_reads, 0);
        assert_eq!(session.signer.signs, 1);
    }

    #[test]
    fn sign_cached_rescans_in_session_on_serial_mismatch_without_signing_cached_slot() {
        let mut session = MockSlotSession::new(true, vec![0xAA; 64]);
        session.refreshed_serial = Some(99);
        let pinentry = MockPinentry::new(Some("123456"));
        let cached = crate::identity_cache::PivCachedIdentity {
            slot: Slot::Authentication,
            key_alg: KeyAlg::Ed25519,
            serial: Some(42),
        };
        let mut serial = Some(99);

        let result = super::sign_in_session(
            &[Slot::Authentication, Slot::Signature],
            &mut session,
            &mut serial,
            &dummy_ed25519_cred(),
            Some(cached),
            b"challenge",
            None,
            &pinentry,
            None,
        )
        .unwrap();

        assert_eq!(result.discovered, Some(vec![]));
        assert!(matches!(
            result.outcome,
            crate::identity_cache::SignOutcome::NotFound
        ));
        assert_eq!(session.refreshes, 1);
        assert_eq!(session.cert_reads, 2);
        assert_eq!(session.signer.signs, 0);
        assert_eq!(pinentry.prompts(), 0);
    }

    #[test]
    fn sign_cached_rescans_on_missing_slot_apdu_and_stops_on_user_cancel() {
        let mut stale_session = MockSlotSession::new(true, vec![]);
        stale_session.signer.sign_error = Some(|| TransportError::Apdu {
            label: "GENERAL AUTHENTICATE",
            sw1: 0x6A,
            sw2: 0x88,
        });
        let pinentry = MockPinentry::new(Some("123456"));
        let cached = crate::identity_cache::PivCachedIdentity {
            slot: Slot::Authentication,
            key_alg: KeyAlg::Ed25519,
            serial: Some(42),
        };
        let mut serial = Some(42);

        let result = super::sign_in_session(
            &[Slot::Authentication],
            &mut stale_session,
            &mut serial,
            &dummy_ed25519_cred(),
            Some(cached),
            b"challenge",
            None,
            &pinentry,
            None,
        )
        .unwrap();
        assert_eq!(result.discovered, Some(vec![]));
        assert!(matches!(
            result.outcome,
            crate::identity_cache::SignOutcome::NotFound
        ));
        assert_eq!(stale_session.refreshes, 1);
        assert_eq!(stale_session.cert_reads, 1);

        let mut cancel_session = MockSlotSession::new(false, vec![0xAA; 64]);
        let cancel_pinentry = MockPinentry::new(None);
        let cancel_result = super::sign_in_session(
            &[Slot::Authentication],
            &mut cancel_session,
            &mut serial,
            &dummy_ed25519_cred(),
            Some(cached),
            b"challenge",
            None,
            &cancel_pinentry,
            None,
        )
        .unwrap();
        assert!(cancel_result.discovered.is_none());
        assert!(matches!(
            cancel_result.outcome,
            crate::identity_cache::SignOutcome::UserCancelled
        ));
        assert_eq!(cancel_session.refreshes, 0);
        assert_eq!(cancel_session.cert_reads, 0);
        assert_eq!(cancel_pinentry.prompts(), 1);
    }
}
