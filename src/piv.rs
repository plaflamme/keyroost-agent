use std::sync::{Arc, Mutex, mpsc};

use keyroost_piv::{
    KeyAlg, PinPolicy, PublicKey, Slot,
    x509::{SigHash, X509Error},
};
use keyroost_transport::{PivSession, TransportError};
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
    pin_cache::{PinCache, verify_pin_with_cache},
    pinentry::{Applet, Pinentry, SystemPinentry},
};

struct PivIdentity {
    slot: Slot,
    key_alg: KeyAlg,
    ssh_identity: Identity,
}

impl From<PivIdentity> for Identity {
    fn from(value: PivIdentity) -> Self {
        value.ssh_identity
    }
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
        credential: PublicCredential,
        data: Vec<u8>,
        rsa_sig_hash: Option<HashAlg>,
    },
}

enum PivResponse {
    Identities(Vec<Identity>),
    Signature(Option<Signature>),
}

enum WorkerMessage<Req, Res, E> {
    Request {
        request: Req,
        reply: mpsc::Sender<Result<Res, E>>,
    },
    Disconnect {
        reply: mpsc::Sender<()>,
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

    fn send_request(
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

        let (reply_tx, reply_rx) = mpsc::channel();
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
            .recv()
            .map_err(|_| on_worker_gone("PIV worker thread dropped reply"))?
    }

    fn disconnect(&self) {
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
        let (reply_tx, reply_rx) = mpsc::channel();
        if tx.send(WorkerMessage::Disconnect { reply: reply_tx }).is_ok() {
            let _ = reply_rx.recv();
        }
    }
}

fn serve_in_transaction<Req, Res, E>(
    first_req: Req,
    first_reply: mpsc::Sender<Result<Res, E>>,
    rx: &mpsc::Receiver<WorkerMessage<Req, Res, E>>,
    mut handle: impl FnMut(Req) -> Result<Res, E>,
    is_fatal: impl Fn(&E) -> bool,
) -> Option<mpsc::Sender<()>> {
    let mut pending = Some((first_req, first_reply));
    loop {
        let (req, reply) = match pending.take() {
            Some(pair) => pair,
            None => match rx.recv() {
                Ok(WorkerMessage::Request { request, reply }) => (request, reply),
                Ok(WorkerMessage::Disconnect { reply }) => return Some(reply),
                Err(_) => return None,
            },
        };
        let result = handle(req);
        let broken = result.as_ref().err().is_some_and(&is_fatal);
        let _ = reply.send(result);
        if broken {
            tracing::debug!("dropping persistent PIV session after transport error");
            return None;
        }
    }
}

fn run_worker<Req, Res, E>(
    rx: &mpsc::Receiver<WorkerMessage<Req, Res, E>>,
    mut open_and_serve: impl FnMut(
        &mut Option<(Req, mpsc::Sender<Result<Res, E>>)>,
        &mpsc::Receiver<WorkerMessage<Req, Res, E>>,
    ) -> Result<Option<mpsc::Sender<()>>, E>,
) {
    while let Ok(msg) = rx.recv() {
        match msg {
            WorkerMessage::Disconnect { reply } => {
                let _ = reply.send(());
            }
            WorkerMessage::Request { request, reply } => {
                let mut pending = Some((request, reply));
                match open_and_serve(&mut pending, rx) {
                    Ok(Some(disconnect_reply)) => {
                        tracing::debug!("disconnected persistent PIV session");
                        let _ = disconnect_reply.send(());
                    }
                    Ok(None) => {}
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
}

impl PivSshAgent {
    // TODO: manually select slots
    pub(super) fn new(
        reader: String,
        pinentry: SystemPinentry,
        connection_mode: ConnectionMode,
        pin_cache: Option<PinCache>,
    ) -> Self {
        // default signature-related slots
        let sign_slots: &[Slot] = &[
            Slot::Authentication,
            Slot::CardAuthentication,
            Slot::Signature,
        ];

        let backend = match connection_mode {
            ConnectionMode::Ephemeral => PivBackend::Ephemeral,
            ConnectionMode::Persistent => PivBackend::Persistent(PersistentWorker::new()),
        };

        Self {
            reader,
            config: PivConfig {
                slots: Vec::from_iter([sign_slots, &Slot::retired_all()].concat()),
                pinentry,
                pin_cache,
            },
            backend,
        }
    }

    pub(super) fn disconnect(&self) {
        if let PivBackend::Persistent(worker) = &self.backend {
            worker.disconnect();
        }
    }

    pub(super) fn request_identities(&self) -> Result<Vec<Identity>, crate::Error> {
        match &self.backend {
            PivBackend::Ephemeral => {
                tracing::debug!(
                    connection_mode = ?ConnectionMode::Ephemeral,
                    "requesting PIV identities"
                );
                PivSession::with_transaction(&self.reader, |session| {
                    let serial = session.status().ok().and_then(|status| status.serial);
                    list_ssh_identities(&self.config.slots, session, serial)
                })
            }
            PivBackend::Persistent(worker) => {
                tracing::debug!(
                    connection_mode = ?ConnectionMode::Persistent,
                    "requesting PIV identities"
                );
                let response = self.send_persistent(worker, PivRequest::ListIdentities)?;
                match response {
                    PivResponse::Identities(identities) => Ok(identities),
                    PivResponse::Signature(_) => {
                        Err(crate::Error::Other("unexpected PIV worker response".into()))
                    }
                }
            }
        }
    }

    pub(super) fn sign(
        &self,
        public_credential: &PublicCredential,
        data: &[u8],
        rsa_sig_hash: Option<HashAlg>,
    ) -> Result<Option<Signature>, crate::Error> {
        match &self.backend {
            PivBackend::Ephemeral => PivSession::with_transaction(&self.reader, |session| {
                let serial = session.status().ok().and_then(|status| status.serial);
                sign_in_session(
                    &self.config,
                    session,
                    serial,
                    public_credential,
                    data,
                    rsa_sig_hash,
                )
            }),
            PivBackend::Persistent(worker) => {
                let response = self.send_persistent(
                    worker,
                    PivRequest::Sign {
                        credential: public_credential.clone(),
                        data: data.to_vec(),
                        rsa_sig_hash,
                    },
                )?;
                match response {
                    PivResponse::Signature(signature) => Ok(signature),
                    PivResponse::Identities(_) => {
                        Err(crate::Error::Other("unexpected PIV worker response".into()))
                    }
                }
            }
        }
    }

    fn send_persistent(
        &self,
        worker: &PersistentWorker<PivRequest, PivResponse, crate::Error>,
        request: PivRequest,
    ) -> Result<PivResponse, crate::Error> {
        let reader = self.reader.clone();
        let config = self.config.clone();
        worker.send_request(
            request,
            move |rx| {
                std::thread::spawn(move || {
                    run_worker(&rx, |pending, rx| {
                        PivSession::with_transaction(&reader, |session| {
                            // Read serial ONCE when the persistent session opens: on Token2 cards,
                            // `status()` performs a cross-applet OTP read which resets PIV PIN state.
                            let serial = session.status().ok().and_then(|status| status.serial);
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
                                        data,
                                        rsa_sig_hash,
                                    } => sign_in_session(
                                        &config,
                                        session,
                                        serial,
                                        &credential,
                                        &data,
                                        rsa_sig_hash,
                                    )
                                    .map(PivResponse::Signature),
                                },
                                crate::Error::is_transport_error,
                            ))
                        })
                    });
                });
            },
            |msg| crate::Error::Other(msg.into()),
        )
    }
}

fn list_identities(
    slots: &[Slot],
    session: &mut PivSession,
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
    session: &mut PivSession,
    serial: Option<u128>,
) -> Result<Vec<Identity>, crate::Error> {
    let identities = list_identities(slots, session, serial)?;
    Ok(identities
        .into_iter()
        .inspect(|id| tracing::info!("found usable identity on slot {:?}", id.slot))
        .map(Into::into)
        .collect())
}

fn sign_in_session(
    config: &PivConfig,
    session: &mut PivSession,
    serial: Option<u128>,
    public_credential: &PublicCredential,
    data: &[u8],
    rsa_sig_hash: Option<HashAlg>,
) -> Result<Option<Signature>, crate::Error> {
    let piv_identity = list_identities(&config.slots, session, serial)?
        .into_iter()
        .find(|id| &id.ssh_identity.credential == public_credential);

    let Some(piv_identity) = piv_identity else {
        tracing::debug!("not matching PIV identity for requested public key");
        return Ok(None);
    };

    let sig_hash = match keyroost_piv::x509::signature_hash(piv_identity.key_alg) {
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

    let pin_policy = session
        .slot_policy(piv_identity.slot)
        .map(|(pin, _touch)| pin);
    tracing::debug!("slot {:?} PIN policy: {:?}", piv_identity.slot, pin_policy);

    let Some(signature) = sign_with_policy(
        session,
        piv_identity.slot,
        piv_identity.key_alg,
        &prepared,
        pin_policy,
        serial,
        &config.pinentry,
        config.pin_cache.as_ref(),
    )?
    else {
        return Ok(None);
    };

    let signature = match piv_identity.key_alg {
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
    session: &mut PivSession,
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
    use super::{PivSigner, sign_with_policy};
    use crate::{
        pin_cache::PinCache,
        pinentry::{Applet, Pinentry},
    };
    use keyroost_piv::{KeyAlg, PinPolicy, Slot};
    use keyroost_transport::TransportError;
    use ssh_agent_lib::secrecy::{ExposeSecret, SecretBox};
    use std::{cell::Cell, time::Duration};

    fn secret(pin: &str) -> SecretBox<str> {
        SecretBox::from(Box::<str>::from(pin))
    }

    struct MockPinentry {
        pin: Option<&'static str>,
        prompts: Cell<usize>,
    }

    impl MockPinentry {
        fn new(pin: Option<&'static str>) -> Self {
            Self {
                pin,
                prompts: Cell::new(0),
            }
        }

        fn prompts(&self) -> usize {
            self.prompts.get()
        }
    }

    impl Pinentry for MockPinentry {
        fn prompt_pin(
            &self,
            _applet: Applet,
            _serial: Option<u128>,
        ) -> Result<Option<SecretBox<str>>, crate::Error> {
            self.prompts.set(self.prompts.get() + 1);
            Ok(self
                .pin
                .map(|value| SecretBox::new(value.to_owned().into_boxed_str())))
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

    fn send_mock(
        worker: &super::PersistentWorker<MockReq, usize, MockErr>,
        counters: &std::sync::Arc<MockCounters>,
        req: MockReq,
    ) -> Result<usize, MockErr> {
        let counters = std::sync::Arc::clone(counters);
        worker.send_request(
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
    }

    #[test]
    fn persistent_worker_lazily_opens_and_reuses_transaction_reading_status_once() {
        let counters = MockCounters::new();
        let worker = super::PersistentWorker::new();

        assert_eq!(counters.opens.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(
            counters
                .status_reads
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );

        assert_eq!(send_mock(&worker, &counters, MockReq::Ping), Ok(1));
        assert_eq!(send_mock(&worker, &counters, MockReq::Ping), Ok(1));
        assert_eq!(counters.opens.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(
            counters
                .status_reads
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(counters.active.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn persistent_worker_keeps_session_on_non_transport_error() {
        let counters = MockCounters::new();
        let worker = super::PersistentWorker::new();

        assert_eq!(send_mock(&worker, &counters, MockReq::Ping), Ok(1));
        assert_eq!(
            send_mock(&worker, &counters, MockReq::AppErr),
            Err(MockErr::App)
        );
        assert_eq!(send_mock(&worker, &counters, MockReq::Ping), Ok(1));
        assert_eq!(counters.opens.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn persistent_worker_drops_and_reopens_session_on_transport_error() {
        let counters = MockCounters::new();
        let worker = super::PersistentWorker::new();

        assert_eq!(send_mock(&worker, &counters, MockReq::Ping), Ok(1));
        assert_eq!(
            send_mock(&worker, &counters, MockReq::TransportErr),
            Err(MockErr::Transport)
        );
        assert_eq!(send_mock(&worker, &counters, MockReq::Ping), Ok(2));
        assert_eq!(counters.opens.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert_eq!(
            counters
                .status_reads
                .load(std::sync::atomic::Ordering::SeqCst),
            2
        );
    }

    #[test]
    fn persistent_worker_disconnect_drops_session_synchronously_and_reopens_next() {
        let counters = MockCounters::new();
        let worker = super::PersistentWorker::new();

        // Disconnect before any request is a no-op and does not open a session.
        worker.disconnect();
        assert_eq!(counters.opens.load(std::sync::atomic::Ordering::SeqCst), 0);

        assert_eq!(send_mock(&worker, &counters, MockReq::Ping), Ok(1));
        assert_eq!(counters.active.load(std::sync::atomic::Ordering::SeqCst), 1);

        worker.disconnect();
        assert_eq!(counters.active.load(std::sync::atomic::Ordering::SeqCst), 0);

        // Next request lazily opens a new transaction.
        assert_eq!(send_mock(&worker, &counters, MockReq::Ping), Ok(2));
        assert_eq!(counters.opens.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert_eq!(counters.active.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn persistent_worker_clone_shares_active_transaction() {
        let counters = MockCounters::new();
        let worker1 = super::PersistentWorker::new();
        let worker2 = worker1.clone();

        assert_eq!(send_mock(&worker1, &counters, MockReq::Ping), Ok(1));
        assert_eq!(send_mock(&worker2, &counters, MockReq::Ping), Ok(1));
        assert_eq!(counters.opens.load(std::sync::atomic::Ordering::SeqCst), 1);

        worker2.disconnect();
        assert_eq!(counters.active.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(send_mock(&worker1, &counters, MockReq::Ping), Ok(2));
    }

    #[test]
    fn persistent_worker_propagates_open_failure_and_retries_next_request() {
        let counters = MockCounters::new();
        counters
            .fail_next_open
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let worker = super::PersistentWorker::new();

        assert_eq!(
            send_mock(&worker, &counters, MockReq::Ping),
            Err(MockErr::Transport)
        );
        assert_eq!(counters.opens.load(std::sync::atomic::Ordering::SeqCst), 0);

        assert_eq!(send_mock(&worker, &counters, MockReq::Ping), Ok(1));
        assert_eq!(counters.opens.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}
