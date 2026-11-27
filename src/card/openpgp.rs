use std::sync::{Arc, Mutex};

use keyroost_openpgp::{self as pgp, AlgorithmAttributes, KeyCrt, PW1_OTHER, PW1_SIGN, PublicKey};
use keyroost_transport::{OpenPgpSession, OpenPgpStatus, TransportError};

use crate::{
    ConnectionMode,
    card::CardOperationOutcome,
    pin_cache::{PinCache, verify_pin_with_cache},
    pinentry::{Applet, Pinentry, PinentryEnv, SystemPinentry},
};

#[derive(Clone, Debug)]
pub(crate) struct OpenPgpKeyInfo {
    pub(crate) slot: KeyCrt,
    pub(crate) attrs: AlgorithmAttributes,
    pub(crate) public_key: PublicKey,
    #[allow(dead_code)]
    pub(crate) fingerprint: [u8; 20],
    pub(crate) aid: Vec<u8>,
    pub(crate) serial: Option<u32>,
    pub(crate) full_serial: Option<u128>,
}

/// Read-only snapshot of an `OpenPGP` card's status metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OpenPgpCardStatus {
    pub(crate) reader: String,
    pub(crate) aid: Vec<u8>,
    pub(crate) sig_attrs: Vec<u8>,
    pub(crate) dec_attrs: Vec<u8>,
    pub(crate) aut_attrs: Vec<u8>,
    pub(crate) fingerprint_sig: [u8; 20],
    pub(crate) fingerprint_dec: [u8; 20],
    pub(crate) fingerprint_aut: [u8; 20],
    pub(crate) tries_pw1: u8,
    pub(crate) tries_rc: u8,
    pub(crate) tries_pw3: u8,
    pub(crate) signature_count: Option<u32>,
    #[allow(dead_code)]
    pub(crate) serial: Option<u32>,
    #[allow(dead_code)]
    pub(crate) full_serial: Option<u128>,
}

impl OpenPgpCardStatus {
    fn from_status(reader: String, status: &OpenPgpStatus) -> Self {
        Self {
            reader,
            aid: status.aid.clone(),
            sig_attrs: status.sig_attrs.clone(),
            dec_attrs: status.dec_attrs.clone(),
            aut_attrs: status.aut_attrs.clone(),
            fingerprint_sig: status.fingerprint_sig,
            fingerprint_dec: status.fingerprint_dec,
            fingerprint_aut: status.fingerprint_aut,
            tries_pw1: status.tries_pw1,
            tries_rc: status.tries_rc,
            tries_pw3: status.tries_pw3,
            signature_count: status.signature_count,
            serial: status.serial(),
            full_serial: status.full_serial(),
        }
    }
}

struct OpenPgpStatusView<'a> {
    aid: &'a [u8],
    sig_attrs: &'a [u8],
    dec_attrs: &'a [u8],
    aut_attrs: &'a [u8],
    fingerprint_sig: [u8; 20],
    fingerprint_dec: [u8; 20],
    fingerprint_aut: [u8; 20],
    serial: Option<u32>,
    full_serial: Option<u128>,
}

impl<'a> From<&'a OpenPgpStatus> for OpenPgpStatusView<'a> {
    fn from(status: &'a OpenPgpStatus) -> Self {
        Self {
            aid: &status.aid,
            sig_attrs: &status.sig_attrs,
            dec_attrs: &status.dec_attrs,
            aut_attrs: &status.aut_attrs,
            fingerprint_sig: status.fingerprint_sig,
            fingerprint_dec: status.fingerprint_dec,
            fingerprint_aut: status.fingerprint_aut,
            serial: status.serial(),
            full_serial: status.full_serial(),
        }
    }
}

struct PersistentOpenPgp<S = OpenPgpSession, St = OpenPgpStatus> {
    session: S,
    status: St,
}

struct PersistentSlot<S = OpenPgpSession, St = OpenPgpStatus> {
    state: Arc<Mutex<Option<PersistentOpenPgp<S, St>>>>,
}

impl<S, St> Clone for PersistentSlot<S, St> {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
        }
    }
}

impl<S, St> PersistentSlot<S, St> {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(None)),
        }
    }

    fn with_session<T, E>(
        &self,
        open: impl FnOnce() -> Result<(S, St), E>,
        is_fatal: impl Fn(&E) -> bool,
        f: impl FnOnce(&mut S, &St) -> Result<T, E>,
    ) -> Result<T, E> {
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.is_none() {
            let (session, status) = open()?;
            *guard = Some(PersistentOpenPgp { session, status });
        }
        let persistent = guard.as_mut().expect("persistent session initialized above");
        let result = f(&mut persistent.session, &persistent.status);
        if result.as_ref().err().is_some_and(is_fatal) {
            tracing::debug!("dropping persistent OpenPGP session after transport error");
            *guard = None;
        }
        result
    }

    fn disconnect(&self) {
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.take().is_some() {
            tracing::debug!("disconnected persistent OpenPGP session");
        }
    }
}

#[derive(Clone)]
enum OpenPgpBackend {
    Ephemeral,
    Persistent(PersistentSlot),
}

#[derive(Clone)]
pub(crate) struct OpenPgpCard {
    reader: String,
    pinentry: SystemPinentry,
    backend: OpenPgpBackend,
    pin_cache: Option<PinCache>,
}

impl OpenPgpCard {
    pub(crate) fn new(
        reader: String,
        pinentry: SystemPinentry,
        connection_mode: ConnectionMode,
        pin_cache: Option<PinCache>,
    ) -> Self {
        let backend = match connection_mode {
            ConnectionMode::Ephemeral => OpenPgpBackend::Ephemeral,
            ConnectionMode::Persistent => OpenPgpBackend::Persistent(PersistentSlot::new()),
        };

        Self {
            reader,
            pinentry,
            backend,
            pin_cache,
        }
    }

    pub(crate) async fn disconnect(&self) {
        if let OpenPgpBackend::Persistent(slot) = &self.backend {
            let slot = slot.clone();
            let _ = tokio::task::spawn_blocking(move || slot.disconnect()).await;
        }
    }

    pub(crate) fn list_keys_ephemeral(
        reader: &str,
        slots: &[KeyCrt],
    ) -> Result<Vec<OpenPgpKeyInfo>, crate::Error> {
        let mut session = OpenPgpSession::open(reader)?;
        let status = session.status()?;
        let status_view = OpenPgpStatusView::from(&status);
        list_keys_in_session(&mut session, &status_view, slots)
    }

    pub(crate) fn probe_keys(reader: &str, slots: &[KeyCrt]) -> Result<bool, crate::Error> {
        Self::list_keys_ephemeral(reader, slots).map(|keys| !keys.is_empty())
    }

    fn with_session<T>(
        &self,
        f: impl FnOnce(&mut OpenPgpSession, &OpenPgpStatus) -> Result<T, crate::Error>,
    ) -> Result<T, crate::Error> {
        match &self.backend {
            OpenPgpBackend::Ephemeral => {
                let mut session = OpenPgpSession::open(&self.reader)?;
                let status = session.status()?;
                f(&mut session, &status)
            }
            OpenPgpBackend::Persistent(slot) => slot.with_session(
                || {
                    let mut session = OpenPgpSession::open(&self.reader)?;
                    // Read status ONCE when the persistent session opens: on Token2 cards,
                    // `status()` performs a cross-applet OTP read which resets OpenPGP PIN state.
                    let status = session.status()?;
                    Ok((session, status))
                },
                crate::Error::is_transport_error,
                f,
            ),
        }
    }

    pub(crate) async fn card_status(&self) -> Result<OpenPgpCardStatus, crate::Error> {
        let card = self.clone();
        tokio::task::spawn_blocking(move || {
            card.with_session(|_session, status| {
                Ok(OpenPgpCardStatus::from_status(card.reader.clone(), status))
            })
        })
        .await
        .map_err(|err| crate::Error::Other(Box::new(err)))?
    }

    pub(crate) async fn list_keys(
        &self,
        slots: &[KeyCrt],
    ) -> Result<Vec<OpenPgpKeyInfo>, crate::Error> {
        let mode = match self.backend {
            OpenPgpBackend::Ephemeral => ConnectionMode::Ephemeral,
            OpenPgpBackend::Persistent(_) => ConnectionMode::Persistent,
        };
        tracing::debug!(connection_mode = ?mode, "requesting OpenPGP keys");
        let card = self.clone();
        let slots = slots.to_vec();
        tokio::task::spawn_blocking(move || {
            card.with_session(|session, status| {
                let status_view = OpenPgpStatusView::from(status);
                list_keys_in_session(session, &status_view, &slots)
            })
        })
        .await
        .map_err(|err| crate::Error::Other(Box::new(err)))?
    }

    pub(crate) async fn sign_raw(
        &self,
        slot: KeyCrt,
        expected_serial: Option<u128>,
        data: &[u8],
        prompt_desc: Option<&str>,
        prompt_env: Option<&PinentryEnv>,
    ) -> Result<CardOperationOutcome<Vec<u8>>, crate::Error> {
        let card = self.clone();
        let data = data.to_vec();
        let prompt_desc = prompt_desc.map(ToOwned::to_owned);
        let prompt_env = prompt_env.cloned();
        tokio::task::spawn_blocking(move || {
            card.with_session(|session, status| {
                sign_raw_in_session(
                    session,
                    slot,
                    status.full_serial(),
                    expected_serial,
                    &data,
                    &card.pinentry,
                    card.pin_cache.as_ref(),
                    prompt_desc.as_deref(),
                    prompt_env.as_ref(),
                )
            })
        })
        .await
        .map_err(|err| crate::Error::Other(Box::new(err)))?
    }

    pub(crate) async fn decrypt_rsa(
        &self,
        expected_serial: Option<u128>,
        cryptogram: &[u8],
        prompt_desc: Option<&str>,
        prompt_env: Option<&PinentryEnv>,
    ) -> Result<CardOperationOutcome<Vec<u8>>, crate::Error> {
        let card = self.clone();
        let cryptogram = cryptogram.to_vec();
        let prompt_desc = prompt_desc.map(ToOwned::to_owned);
        let prompt_env = prompt_env.cloned();
        tokio::task::spawn_blocking(move || {
            card.with_session(|session, status| {
                decrypt_rsa_in_session(
                    session,
                    status.full_serial(),
                    expected_serial,
                    &cryptogram,
                    &card.pinentry,
                    card.pin_cache.as_ref(),
                    prompt_desc.as_deref(),
                    prompt_env.as_ref(),
                )
            })
        })
        .await
        .map_err(|err| crate::Error::Other(Box::new(err)))?
    }

    pub(crate) async fn decrypt_ecdh(
        &self,
        expected_serial: Option<u128>,
        ephemeral_point: &[u8],
        prompt_desc: Option<&str>,
        prompt_env: Option<&PinentryEnv>,
    ) -> Result<CardOperationOutcome<Vec<u8>>, crate::Error> {
        let card = self.clone();
        let ephemeral_point = ephemeral_point.to_vec();
        let prompt_desc = prompt_desc.map(ToOwned::to_owned);
        let prompt_env = prompt_env.cloned();
        tokio::task::spawn_blocking(move || {
            card.with_session(|session, status| {
                decrypt_ecdh_in_session(
                    session,
                    status.full_serial(),
                    expected_serial,
                    &ephemeral_point,
                    &card.pinentry,
                    card.pin_cache.as_ref(),
                    prompt_desc.as_deref(),
                    prompt_env.as_ref(),
                )
            })
        })
        .await
        .map_err(|err| crate::Error::Other(Box::new(err)))?
    }
}

fn is_openpgp_stale_apdu_error(err: &crate::Error) -> bool {
    let crate::Error::Other(inner) = err else {
        return false;
    };
    matches!(
        inner.downcast_ref::<TransportError>(),
        Some(TransportError::Apdu {
            sw1: 0x6A,
            sw2: 0x88,
            ..
        })
    )
}

fn list_keys_in_session(
    session: &mut impl OpenPgpSlotSession,
    status: &OpenPgpStatusView<'_>,
    slots: &[KeyCrt],
) -> Result<Vec<OpenPgpKeyInfo>, crate::Error> {
    let mut keys = Vec::new();
    for &slot in slots {
        match read_slot_key(session, status, slot) {
            Ok(Some(key)) => keys.push(key),
            Ok(None) => {}
            Err(err) if err.is_transport_error() => return Err(err),
            Err(err) => {
                tracing::warn!("failed to read OpenPGP slot {slot:?}: {err}");
            }
        }
    }
    Ok(keys)
}

fn read_slot_key(
    session: &mut impl OpenPgpSlotSession,
    status: &OpenPgpStatusView<'_>,
    slot: KeyCrt,
) -> Result<Option<OpenPgpKeyInfo>, crate::Error> {
    let (raw_attrs, fingerprint) = match slot {
        KeyCrt::Sign => (status.sig_attrs, status.fingerprint_sig),
        KeyCrt::Decrypt => (status.dec_attrs, status.fingerprint_dec),
        KeyCrt::Auth => (status.aut_attrs, status.fingerprint_aut),
    };

    if raw_attrs.is_empty() {
        return Ok(None);
    }

    let attrs = match pgp::parse_algorithm_attributes(raw_attrs) {
        Ok(attrs) => attrs,
        Err(pgp::ParseError::UnsupportedAlgorithm) => return Ok(None),
        Err(err) => return Err(crate::Error::Other(Box::new(err))),
    };

    let public_key = match session.read_public_key(slot) {
        Ok(key) => key,
        Err(
            TransportError::OpenPgpParse(_)
            | TransportError::Apdu {
                sw1: 0x6A,
                sw2: 0x88,
                ..
            },
        ) => return Ok(None),
        Err(err) => return Err(err.into()),
    };

    Ok(Some(OpenPgpKeyInfo {
        slot,
        attrs,
        public_key,
        fingerprint,
        aid: status.aid.to_vec(),
        serial: status.serial,
        full_serial: status.full_serial,
    }))
}

trait OpenPgpOps {
    fn verify_pin(&mut self, pw_ref: u8, pin: &[u8]) -> Result<(), TransportError>;
    fn sign(&mut self, digest_info: &[u8]) -> Result<Vec<u8>, TransportError>;
    fn internal_authenticate(&mut self, auth_input: &[u8]) -> Result<Vec<u8>, TransportError>;
    fn decrypt(&mut self, cryptogram: &[u8]) -> Result<Vec<u8>, TransportError>;
    fn decrypt_ecdh(&mut self, ephemeral_point: &[u8]) -> Result<Vec<u8>, TransportError>;
}

trait OpenPgpSlotSession: OpenPgpOps {
    fn read_public_key(&mut self, crt: KeyCrt) -> Result<PublicKey, TransportError>;
}

impl OpenPgpOps for OpenPgpSession {
    fn verify_pin(&mut self, pw_ref: u8, pin: &[u8]) -> Result<(), TransportError> {
        Self::verify_pin(self, pw_ref, pin)
    }

    fn sign(&mut self, digest_info: &[u8]) -> Result<Vec<u8>, TransportError> {
        Self::sign(self, digest_info)
    }

    fn internal_authenticate(&mut self, auth_input: &[u8]) -> Result<Vec<u8>, TransportError> {
        Self::internal_authenticate(self, auth_input)
    }

    fn decrypt(&mut self, cryptogram: &[u8]) -> Result<Vec<u8>, TransportError> {
        Self::decrypt(self, cryptogram)
    }

    fn decrypt_ecdh(&mut self, ephemeral_point: &[u8]) -> Result<Vec<u8>, TransportError> {
        Self::decrypt_ecdh(self, ephemeral_point)
    }
}

impl OpenPgpSlotSession for OpenPgpSession {
    fn read_public_key(&mut self, crt: KeyCrt) -> Result<PublicKey, TransportError> {
        Self::read_public_key(self, crt)
    }
}

fn is_openpgp_wrong_pin(err: &TransportError) -> bool {
    matches!(
        err,
        TransportError::OpenPgpPinRejected {
            tries_remaining: Some(1..),
        } | TransportError::Apdu {
            sw1: 0x63,
            sw2: 0xC1..=0xCF,
            ..
        }
    )
}

#[expect(clippy::too_many_arguments)]
fn execute_with_pin<S: OpenPgpOps>(
    ops: &mut S,
    pw_ref: u8,
    serial: Option<u128>,
    pinentry: &impl Pinentry,
    pin_cache: Option<&PinCache>,
    prompt_desc: Option<&str>,
    prompt_env: Option<&PinentryEnv>,
    mut op: impl FnMut(&mut S) -> Result<Vec<u8>, TransportError>,
) -> Result<Option<Vec<u8>>, crate::Error> {
    match op(ops) {
        Ok(out) => Ok(Some(out)),
        Err(TransportError::Apdu {
            sw1: 0x69,
            sw2: 0x82,
            ..
        }) => {
            if !verify_pin_with_cache(
                Applet::OpenPgp,
                serial,
                true,
                pin_cache,
                pinentry,
                prompt_desc,
                prompt_env,
                |pin| ops.verify_pin(pw_ref, pin),
                is_openpgp_wrong_pin,
            )? {
                return Ok(None);
            }
            Ok(Some(op(ops)?))
        }
        Err(err) => Err(err.into()),
    }
}

#[expect(clippy::too_many_arguments)]
fn execute_checked<S: OpenPgpOps>(
    ops: &mut S,
    pw_ref: u8,
    current_serial: Option<u128>,
    expected_serial: Option<u128>,
    pinentry: &impl Pinentry,
    pin_cache: Option<&PinCache>,
    prompt_desc: Option<&str>,
    prompt_env: Option<&PinentryEnv>,
    op: impl FnMut(&mut S) -> Result<Vec<u8>, TransportError>,
) -> Result<CardOperationOutcome<Vec<u8>>, crate::Error> {
    if let Some(expected) = expected_serial
        && current_serial != Some(expected)
    {
        tracing::debug!(
            expected_serial = expected,
            ?current_serial,
            "OpenPGP card serial changed"
        );
        return Ok(CardOperationOutcome::NotFound);
    }

    match execute_with_pin(
        ops,
        pw_ref,
        current_serial,
        pinentry,
        pin_cache,
        prompt_desc,
        prompt_env,
        op,
    ) {
        Ok(Some(output)) => Ok(CardOperationOutcome::Completed(output)),
        Ok(None) => Ok(CardOperationOutcome::UserCancelled),
        Err(err) if is_openpgp_stale_apdu_error(&err) => {
            tracing::debug!("OpenPGP card operation failed with stale APDU error: {err}");
            Ok(CardOperationOutcome::NotFound)
        }
        Err(err) => Err(err),
    }
}

#[expect(clippy::too_many_arguments)]
fn sign_raw_in_session(
    ops: &mut impl OpenPgpOps,
    slot: KeyCrt,
    current_serial: Option<u128>,
    expected_serial: Option<u128>,
    data: &[u8],
    pinentry: &impl Pinentry,
    pin_cache: Option<&PinCache>,
    prompt_desc: Option<&str>,
    prompt_env: Option<&PinentryEnv>,
) -> Result<CardOperationOutcome<Vec<u8>>, crate::Error> {
    let pw_ref = match slot {
        KeyCrt::Sign => PW1_SIGN,
        KeyCrt::Auth => PW1_OTHER,
        KeyCrt::Decrypt => {
            return Err(crate::Error::Other(
                "OpenPGP decrypt slot cannot be used for signing".into(),
            ));
        }
    };

    execute_checked(
        ops,
        pw_ref,
        current_serial,
        expected_serial,
        pinentry,
        pin_cache,
        prompt_desc,
        prompt_env,
        |s| match slot {
            KeyCrt::Sign => s.sign(data),
            KeyCrt::Auth => s.internal_authenticate(data),
            KeyCrt::Decrypt => unreachable!(),
        },
    )
}

#[expect(clippy::too_many_arguments)]
fn decrypt_rsa_in_session(
    ops: &mut impl OpenPgpOps,
    current_serial: Option<u128>,
    expected_serial: Option<u128>,
    cryptogram: &[u8],
    pinentry: &impl Pinentry,
    pin_cache: Option<&PinCache>,
    prompt_desc: Option<&str>,
    prompt_env: Option<&PinentryEnv>,
) -> Result<CardOperationOutcome<Vec<u8>>, crate::Error> {
    execute_checked(
        ops,
        PW1_OTHER,
        current_serial,
        expected_serial,
        pinentry,
        pin_cache,
        prompt_desc,
        prompt_env,
        |s| s.decrypt(cryptogram),
    )
}

#[expect(clippy::too_many_arguments)]
fn decrypt_ecdh_in_session(
    ops: &mut impl OpenPgpOps,
    current_serial: Option<u128>,
    expected_serial: Option<u128>,
    ephemeral_point: &[u8],
    pinentry: &impl Pinentry,
    pin_cache: Option<&PinCache>,
    prompt_desc: Option<&str>,
    prompt_env: Option<&PinentryEnv>,
) -> Result<CardOperationOutcome<Vec<u8>>, crate::Error> {
    execute_checked(
        ops,
        PW1_OTHER,
        current_serial,
        expected_serial,
        pinentry,
        pin_cache,
        prompt_desc,
        prompt_env,
        |s| s.decrypt_ecdh(ephemeral_point),
    )
}

#[cfg(test)]
mod tests {
    use super::{
        CardOperationOutcome, OpenPgpOps, OpenPgpSlotSession, OpenPgpStatusView,
        decrypt_ecdh_in_session, decrypt_rsa_in_session, execute_with_pin, list_keys_in_session,
        sign_raw_in_session,
    };
    use crate::{
        pin_cache::PinCache,
        pinentry::{Applet, PinPromptOptions, Pinentry, PinentryEnv},
    };
    use keyroost_openpgp::{
        AlgorithmAttributes, Curve, EccKind, KeyCrt, PW1_OTHER, PW1_SIGN, PublicKey,
    };
    use keyroost_transport::TransportError;
    use ssh_agent_lib::secrecy::{ExposeSecret, SecretBox};
    use std::{cell::RefCell, collections::VecDeque, time::Duration};

    fn secret(pin: &str) -> SecretBox<str> {
        SecretBox::from(Box::<str>::from(pin))
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct PromptCall {
        allow_external_cache: bool,
        error: Option<String>,
        description: Option<String>,
        env: Option<PinentryEnv>,
    }

    struct MockPinentry {
        default_pin: Option<&'static str>,
        responses: RefCell<VecDeque<Option<&'static str>>>,
        external_cache: bool,
        calls: RefCell<Vec<PromptCall>>,
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
            self.calls
                .borrow()
                .iter()
                .map(|c| (c.allow_external_cache, c.error.clone()))
                .collect()
        }

        fn full_calls(&self) -> Vec<PromptCall> {
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
            self.calls.borrow_mut().push(PromptCall {
                allow_external_cache: options.allow_external_cache,
                error: options.error.map(ToOwned::to_owned),
                description: options.description.map(ToOwned::to_owned),
                env: options.env.cloned(),
            });
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

    struct MockOps {
        verified: bool,
        verified_refs: Vec<u8>,
        verified_pins: Vec<Vec<u8>>,
        signs: usize,
        authenticates: usize,
        rsa_decrypts: usize,
        ecdh_decrypts: usize,
        last_input: Vec<u8>,
        result: Vec<u8>,
        error: Option<fn() -> TransportError>,
        verify_handler: VerifyHandler,
    }

    impl MockOps {
        fn new(verified: bool, result: Vec<u8>) -> Self {
            Self {
                verified,
                verified_refs: Vec::new(),
                verified_pins: Vec::new(),
                signs: 0,
                authenticates: 0,
                rsa_decrypts: 0,
                ecdh_decrypts: 0,
                last_input: Vec::new(),
                result,
                error: None,
                verify_handler: |pin| {
                    if pin == b"123456" {
                        Ok(())
                    } else {
                        Err(TransportError::OpenPgpPinRejected {
                            tries_remaining: Some(2),
                        })
                    }
                },
            }
        }
    }

    impl OpenPgpOps for MockOps {
        fn verify_pin(&mut self, pw_ref: u8, pin: &[u8]) -> Result<(), TransportError> {
            self.verified_refs.push(pw_ref);
            self.verified_pins.push(pin.to_vec());
            (self.verify_handler)(pin)?;
            self.verified = true;
            Ok(())
        }

        fn sign(&mut self, digest_info: &[u8]) -> Result<Vec<u8>, TransportError> {
            self.signs += 1;
            self.last_input = digest_info.to_vec();
            if let Some(err) = self.error {
                return Err(err());
            }
            if !self.verified {
                return Err(TransportError::Apdu {
                    label: "PSO:CDS",
                    sw1: 0x69,
                    sw2: 0x82,
                });
            }
            Ok(self.result.clone())
        }

        fn internal_authenticate(&mut self, auth_input: &[u8]) -> Result<Vec<u8>, TransportError> {
            self.authenticates += 1;
            self.last_input = auth_input.to_vec();
            if let Some(err) = self.error {
                return Err(err());
            }
            if !self.verified {
                return Err(TransportError::Apdu {
                    label: "INTERNAL AUTHENTICATE",
                    sw1: 0x69,
                    sw2: 0x82,
                });
            }
            Ok(self.result.clone())
        }

        fn decrypt(&mut self, cryptogram: &[u8]) -> Result<Vec<u8>, TransportError> {
            self.rsa_decrypts += 1;
            self.last_input = cryptogram.to_vec();
            if let Some(err) = self.error {
                return Err(err());
            }
            if !self.verified {
                return Err(TransportError::Apdu {
                    label: "PSO:DECIPHER",
                    sw1: 0x69,
                    sw2: 0x82,
                });
            }
            Ok(self.result.clone())
        }

        fn decrypt_ecdh(&mut self, ephemeral_point: &[u8]) -> Result<Vec<u8>, TransportError> {
            self.ecdh_decrypts += 1;
            self.last_input = ephemeral_point.to_vec();
            if let Some(err) = self.error {
                return Err(err());
            }
            if !self.verified {
                return Err(TransportError::Apdu {
                    label: "PSO:DECIPHER",
                    sw1: 0x69,
                    sw2: 0x82,
                });
            }
            Ok(self.result.clone())
        }
    }

    fn sign_with_pin_helper(
        ops: &mut impl OpenPgpOps,
        slot: KeyCrt,
        prepared: &[u8],
        serial: Option<u128>,
        pinentry: &impl Pinentry,
        pin_cache: Option<&PinCache>,
    ) -> Result<Option<Vec<u8>>, crate::Error> {
        let pw_ref = match slot {
            KeyCrt::Sign => PW1_SIGN,
            KeyCrt::Auth => PW1_OTHER,
            KeyCrt::Decrypt => {
                return Err(crate::Error::Other(
                    "OpenPGP decrypt slot cannot be used for signing".into(),
                ));
            }
        };
        execute_with_pin(
            ops,
            pw_ref,
            serial,
            pinentry,
            pin_cache,
            None,
            None,
            |s| match slot {
                KeyCrt::Sign => s.sign(prepared),
                KeyCrt::Auth => s.internal_authenticate(prepared),
                KeyCrt::Decrypt => unreachable!(),
            },
        )
    }

    #[test]
    fn already_verified_card_signs_without_prompting() {
        let mut signer = MockOps::new(true, vec![1, 2, 3]);
        let pinentry = MockPinentry::new(Some("123456"));
        let res = sign_with_pin_helper(
            &mut signer,
            KeyCrt::Sign,
            b"digest",
            Some(1234),
            &pinentry,
            None,
        )
        .unwrap();

        assert_eq!(res, Some(vec![1, 2, 3]));
        assert_eq!(pinentry.prompts(), 0);
        assert_eq!(signer.verified_refs, [] as [u8; 0]);
        assert_eq!(signer.signs, 1);
        assert_eq!(signer.authenticates, 0);

        let mut auth_signer = MockOps::new(true, vec![4, 5, 6]);
        let auth_pinentry = MockPinentry::new(Some("123456"));
        let auth_res = sign_with_pin_helper(
            &mut auth_signer,
            KeyCrt::Auth,
            b"digest",
            Some(1234),
            &auth_pinentry,
            None,
        )
        .unwrap();

        assert_eq!(auth_res, Some(vec![4, 5, 6]));
        assert_eq!(auth_pinentry.prompts(), 0);
        assert_eq!(auth_signer.verified_refs, [] as [u8; 0]);
        assert_eq!(auth_signer.signs, 0);
        assert_eq!(auth_signer.authenticates, 1);
    }

    #[test]
    fn sign_slot_verifies_pw1_sign_and_retries_pso_sign() {
        let mut signer = MockOps::new(false, vec![1, 2, 3]);
        let pinentry = MockPinentry::new(Some("123456"));
        let res = sign_with_pin_helper(
            &mut signer,
            KeyCrt::Sign,
            b"digest",
            Some(1234),
            &pinentry,
            None,
        )
        .unwrap();

        assert_eq!(res, Some(vec![1, 2, 3]));
        assert_eq!(pinentry.prompts(), 1);
        assert_eq!(signer.verified_refs, vec![PW1_SIGN]);
        assert_eq!(signer.signs, 2);
        assert_eq!(signer.authenticates, 0);
    }

    #[test]
    fn auth_slot_verifies_pw1_other_and_retries_internal_authenticate() {
        let mut signer = MockOps::new(false, vec![4, 5, 6]);
        let pinentry = MockPinentry::new(Some("123456"));
        let res = sign_with_pin_helper(
            &mut signer,
            KeyCrt::Auth,
            b"digest",
            Some(1234),
            &pinentry,
            None,
        )
        .unwrap();

        assert_eq!(res, Some(vec![4, 5, 6]));
        assert_eq!(pinentry.prompts(), 1);
        assert_eq!(signer.verified_refs, vec![PW1_OTHER]);
        assert_eq!(signer.signs, 0);
        assert_eq!(signer.authenticates, 2);
    }

    #[test]
    fn cancelled_pin_returns_none_without_verifying() {
        let mut signer = MockOps::new(false, vec![7, 8, 9]);
        let pinentry = MockPinentry::new(None);
        let res = sign_with_pin_helper(
            &mut signer,
            KeyCrt::Auth,
            b"digest",
            Some(1234),
            &pinentry,
            None,
        )
        .unwrap();

        assert_eq!(res, None);
        assert_eq!(pinentry.prompts(), 1);
        assert_eq!(signer.verified_refs, [] as [u8; 0]);
        assert_eq!(signer.signs, 0);
        assert_eq!(signer.authenticates, 1);
    }

    #[test]
    fn non_security_error_propagates_without_prompting() {
        let mut signer = MockOps::new(false, vec![]);
        signer.error = Some(|| TransportError::Apdu {
            label: "INTERNAL AUTHENTICATE",
            sw1: 0x6A,
            sw2: 0x88,
        });
        let pinentry = MockPinentry::new(Some("123456"));

        let err = sign_with_pin_helper(
            &mut signer,
            KeyCrt::Auth,
            b"digest",
            Some(1234),
            &pinentry,
            None,
        )
        .unwrap_err();

        assert!(matches!(err, crate::Error::Other(_)));
        assert_eq!(pinentry.prompts(), 0);
        assert_eq!(signer.verified_refs, [] as [u8; 0]);
        assert_eq!(signer.signs, 0);
        assert_eq!(signer.authenticates, 1);
    }

    #[test]
    fn cache_miss_inserts_pin_and_second_sign_hits_cache_and_refreshes_ttl() {
        let cache = PinCache::new(Duration::from_secs(60), None);
        let pinentry = MockPinentry::new(Some("123456"));

        let mut signer1 = MockOps::new(false, vec![1, 2, 3]);
        let res1 = sign_with_pin_helper(
            &mut signer1,
            KeyCrt::Sign,
            b"digest",
            Some(1234),
            &pinentry,
            Some(&cache),
        )
        .unwrap();

        assert_eq!(res1, Some(vec![1, 2, 3]));
        assert_eq!(pinentry.prompts(), 1);
        assert_eq!(signer1.verified_refs, vec![PW1_SIGN]);
        assert_eq!(
            cache
                .get(Applet::OpenPgp, Some(1234))
                .as_ref()
                .map(ExposeSecret::expose_secret),
            Some("123456")
        );
        let expires_before = cache.expires_at(Applet::OpenPgp, Some(1234)).unwrap();

        std::thread::sleep(Duration::from_millis(2));

        let mut signer2 = MockOps::new(false, vec![4, 5, 6]);
        let res2 = sign_with_pin_helper(
            &mut signer2,
            KeyCrt::Auth,
            b"digest",
            Some(1234),
            &pinentry,
            Some(&cache),
        )
        .unwrap();

        assert_eq!(res2, Some(vec![4, 5, 6]));
        assert_eq!(pinentry.prompts(), 1);
        assert_eq!(signer2.verified_refs, vec![PW1_OTHER]);
        assert_eq!(signer2.verified_pins, vec![b"123456".to_vec()]);
        let expires_after = cache.expires_at(Applet::OpenPgp, Some(1234)).unwrap();
        assert!(expires_after > expires_before);
    }

    #[test]
    fn fresh_prompt_verify_failure_does_not_cache_wrong_pin() {
        let cache = PinCache::new(Duration::from_secs(60), None);
        let pinentry = MockPinentry::new(Some("000000"));
        let mut signer = MockOps::new(false, vec![1, 2, 3]);

        let err = sign_with_pin_helper(
            &mut signer,
            KeyCrt::Sign,
            b"digest",
            Some(1234),
            &pinentry,
            Some(&cache),
        )
        .unwrap_err();

        assert!(matches!(err, crate::Error::Other(_)));
        assert_eq!(pinentry.prompts(), 1);
        assert_eq!(signer.verified_refs, vec![PW1_SIGN]);
        assert!(cache.get(Applet::OpenPgp, Some(1234)).is_none());
    }

    #[test]
    fn wrong_cached_pin_evicts_reprompts_and_caches_new_pin() {
        let wrong_pin_handlers: [VerifyHandler; 2] = [
            |pin| {
                if pin == b"123456" {
                    Ok(())
                } else {
                    Err(TransportError::OpenPgpPinRejected {
                        tries_remaining: Some(2),
                    })
                }
            },
            |pin| {
                if pin == b"123456" {
                    Ok(())
                } else {
                    Err(TransportError::Apdu {
                        label: "openpgp verify",
                        sw1: 0x63,
                        sw2: 0xC2,
                    })
                }
            },
        ];

        for handler in wrong_pin_handlers {
            let cache = PinCache::new(Duration::from_secs(60), None);
            cache.insert(Applet::OpenPgp, Some(1234), secret("stale1"));

            let pinentry = MockPinentry::new(Some("123456"));
            let mut signer = MockOps::new(false, vec![9, 8, 7]);
            signer.verify_handler = handler;

            let res = sign_with_pin_helper(
                &mut signer,
                KeyCrt::Auth,
                b"digest",
                Some(1234),
                &pinentry,
                Some(&cache),
            )
            .unwrap();

            assert_eq!(res, Some(vec![9, 8, 7]));
            assert_eq!(pinentry.prompts(), 1);
            assert_eq!(signer.verified_refs, vec![PW1_OTHER, PW1_OTHER]);
            assert_eq!(
                signer.verified_pins,
                vec![b"stale1".to_vec(), b"123456".to_vec()]
            );
            assert_eq!(
                cache
                    .get(Applet::OpenPgp, Some(1234))
                    .as_ref()
                    .map(ExposeSecret::expose_secret),
                Some("123456")
            );
        }
    }

    #[test]
    fn wrong_cached_pin_with_cancelled_reprompt_evicts_and_returns_none() {
        let cache = PinCache::new(Duration::from_secs(60), None);
        cache.insert(Applet::OpenPgp, Some(1234), secret("stale1"));

        let pinentry = MockPinentry::new(None);
        let mut signer = MockOps::new(false, vec![9, 8, 7]);

        let res = sign_with_pin_helper(
            &mut signer,
            KeyCrt::Auth,
            b"digest",
            Some(1234),
            &pinentry,
            Some(&cache),
        )
        .unwrap();

        assert_eq!(res, None);
        assert_eq!(pinentry.prompts(), 1);
        assert_eq!(signer.verified_refs, vec![PW1_OTHER]);
        assert!(cache.get(Applet::OpenPgp, Some(1234)).is_none());
    }

    #[test]
    fn non_wrong_pin_error_on_cache_hit_evicts_without_reprompting() {
        let fatal_handlers: [VerifyHandler; 5] = [
            |_| {
                Err(TransportError::OpenPgpPinRejected {
                    tries_remaining: Some(0),
                })
            },
            |_| {
                Err(TransportError::OpenPgpPinRejected {
                    tries_remaining: None,
                })
            },
            |_| {
                Err(TransportError::Apdu {
                    label: "openpgp verify",
                    sw1: 0x69,
                    sw2: 0x83,
                })
            },
            |_| {
                Err(TransportError::Apdu {
                    label: "openpgp verify",
                    sw1: 0x63,
                    sw2: 0xC0,
                })
            },
            |_| Err(TransportError::NoOpenPgpApplet),
        ];

        for handler in fatal_handlers {
            let cache = PinCache::new(Duration::from_secs(60), None);
            cache.insert(Applet::OpenPgp, Some(1234), secret("123456"));

            let pinentry = MockPinentry::new(Some("123456"));
            let mut signer = MockOps::new(false, vec![9, 8, 7]);
            signer.verify_handler = handler;

            let err = sign_with_pin_helper(
                &mut signer,
                KeyCrt::Auth,
                b"digest",
                Some(1234),
                &pinentry,
                Some(&cache),
            )
            .unwrap_err();

            assert!(matches!(err, crate::Error::Other(_)));
            assert_eq!(pinentry.prompts(), 0);
            assert_eq!(signer.verified_refs, vec![PW1_OTHER]);
            assert!(cache.get(Applet::OpenPgp, Some(1234)).is_none());
        }
    }

    #[test]
    fn external_cache_wrong_pin_retries_once_without_external_cache_and_with_error() {
        let pinentry = MockPinentry::with_external_cache([Some("stale1"), Some("123456")]);
        let mut signer = MockOps::new(false, vec![4, 5, 6]);

        let res = sign_with_pin_helper(
            &mut signer,
            KeyCrt::Auth,
            b"digest",
            Some(1234),
            &pinentry,
            None,
        )
        .unwrap();

        assert_eq!(res, Some(vec![4, 5, 6]));
        assert_eq!(
            pinentry.calls(),
            vec![(true, None), (false, Some("Incorrect PIN".to_owned()))]
        );
        assert_eq!(signer.verified_refs, vec![PW1_OTHER, PW1_OTHER]);
        assert_eq!(
            signer.verified_pins,
            vec![b"stale1".to_vec(), b"123456".to_vec()]
        );
    }

    #[derive(Debug, PartialEq, Eq)]
    enum MockErr {
        App,
        Transport,
    }

    impl MockErr {
        fn is_transport(&self) -> bool {
            matches!(self, Self::Transport)
        }
    }

    struct MockSession {
        id: usize,
        active: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Drop for MockSession {
        fn drop(&mut self) {
            self.active
                .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[test]
    fn persistent_slot_lazily_opens_and_reads_status_once() {
        let slot = super::PersistentSlot::<MockSession, usize>::new();
        let active = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut opens = 0usize;

        let open = |opens: &mut usize| {
            *opens += 1;
            active.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok::<_, MockErr>((
                MockSession {
                    id: *opens,
                    active: std::sync::Arc::clone(&active),
                },
                *opens * 100,
            ))
        };

        let first = slot
            .with_session(
                || open(&mut opens),
                MockErr::is_transport,
                |sess, &status| Ok((sess.id, status)),
            )
            .unwrap();
        let second = slot
            .with_session(
                || open(&mut opens),
                MockErr::is_transport,
                |sess, &status| Ok((sess.id, status)),
            )
            .unwrap();

        assert_eq!(first, (1, 100));
        assert_eq!(second, (1, 100));
        assert_eq!(opens, 1);
        assert_eq!(active.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn persistent_slot_keeps_session_on_non_transport_error() {
        let slot = super::PersistentSlot::<MockSession, usize>::new();
        let active = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut opens = 0usize;

        let mut open_fn = || {
            opens += 1;
            active.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok::<_, MockErr>((
                MockSession {
                    id: opens,
                    active: std::sync::Arc::clone(&active),
                },
                opens,
            ))
        };

        assert_eq!(
            slot.with_session(&mut open_fn, MockErr::is_transport, |s, _| Ok(s.id)),
            Ok(1)
        );
        assert_eq!(
            slot.with_session(&mut open_fn, MockErr::is_transport, |_, _| Err::<usize, _>(
                MockErr::App
            )),
            Err(MockErr::App)
        );
        assert_eq!(
            slot.with_session(&mut open_fn, MockErr::is_transport, |s, _| Ok(s.id)),
            Ok(1)
        );
        assert_eq!(opens, 1);
    }

    #[test]
    fn persistent_slot_drops_and_reopens_session_on_transport_error() {
        let slot = super::PersistentSlot::<MockSession, usize>::new();
        let active = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut opens = 0usize;

        let mut open_fn = || {
            opens += 1;
            active.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok::<_, MockErr>((
                MockSession {
                    id: opens,
                    active: std::sync::Arc::clone(&active),
                },
                opens,
            ))
        };

        assert_eq!(
            slot.with_session(&mut open_fn, MockErr::is_transport, |s, _| Ok(s.id)),
            Ok(1)
        );
        assert_eq!(
            slot.with_session(&mut open_fn, MockErr::is_transport, |_, _| Err::<usize, _>(
                MockErr::Transport
            )),
            Err(MockErr::Transport)
        );
        assert_eq!(active.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(
            slot.with_session(&mut open_fn, MockErr::is_transport, |s, _| Ok(s.id)),
            Ok(2)
        );
        assert_eq!(opens, 2);
        assert_eq!(active.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn persistent_slot_disconnect_and_clone_share_state() {
        let slot_a = super::PersistentSlot::<MockSession, usize>::new();
        let slot_b = slot_a.clone();
        let active = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let opens = std::cell::Cell::new(0usize);

        let open_fn = || {
            let next = opens.get() + 1;
            opens.set(next);
            active.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok::<_, MockErr>((
                MockSession {
                    id: next,
                    active: std::sync::Arc::clone(&active),
                },
                next,
            ))
        };

        assert_eq!(
            slot_a.with_session(open_fn, MockErr::is_transport, |s, _| Ok(s.id)),
            Ok(1)
        );
        assert_eq!(
            slot_b.with_session(open_fn, MockErr::is_transport, |s, _| Ok(s.id)),
            Ok(1)
        );
        assert_eq!(opens.get(), 1);

        slot_b.disconnect();
        assert_eq!(active.load(std::sync::atomic::Ordering::SeqCst), 0);

        assert_eq!(
            slot_a.with_session(open_fn, MockErr::is_transport, |s, _| Ok(s.id)),
            Ok(2)
        );
        assert_eq!(opens.get(), 2);
    }

    struct MockSlotSession {
        ops: MockOps,
        pubkey_reads: Vec<KeyCrt>,
        sign_key: Option<PublicKey>,
        decrypt_key: Option<PublicKey>,
        auth_key: Option<PublicKey>,
    }

    impl MockSlotSession {
        fn new(verified: bool, result: Vec<u8>) -> Self {
            Self {
                ops: MockOps::new(verified, result),
                pubkey_reads: Vec::new(),
                sign_key: None,
                decrypt_key: None,
                auth_key: None,
            }
        }
    }

    impl OpenPgpOps for MockSlotSession {
        fn verify_pin(&mut self, pw_ref: u8, pin: &[u8]) -> Result<(), TransportError> {
            self.ops.verify_pin(pw_ref, pin)
        }

        fn sign(&mut self, digest_info: &[u8]) -> Result<Vec<u8>, TransportError> {
            self.ops.sign(digest_info)
        }

        fn internal_authenticate(&mut self, auth_input: &[u8]) -> Result<Vec<u8>, TransportError> {
            self.ops.internal_authenticate(auth_input)
        }

        fn decrypt(&mut self, cryptogram: &[u8]) -> Result<Vec<u8>, TransportError> {
            self.ops.decrypt(cryptogram)
        }

        fn decrypt_ecdh(&mut self, ephemeral_point: &[u8]) -> Result<Vec<u8>, TransportError> {
            self.ops.decrypt_ecdh(ephemeral_point)
        }
    }

    impl OpenPgpSlotSession for MockSlotSession {
        fn read_public_key(&mut self, crt: KeyCrt) -> Result<PublicKey, TransportError> {
            self.pubkey_reads.push(crt);
            let key = match crt {
                KeyCrt::Sign => self.sign_key.clone(),
                KeyCrt::Decrypt => self.decrypt_key.clone(),
                KeyCrt::Auth => self.auth_key.clone(),
            };
            key.ok_or(TransportError::Apdu {
                label: "GET PUBLIC KEY",
                sw1: 0x6A,
                sw2: 0x88,
            })
        }
    }

    #[test]
    fn list_keys_discovers_all_three_slots_including_decrypt() {
        // EdDSA (0x16) + Ed25519 OID (1.3.6.1.4.1.11591.15.1)
        let ed25519_raw = [0x16, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01];
        // ECDH (0x12) + X25519 OID (1.3.6.1.4.1.3029.1.5.1)
        let x25519_raw = [0x12, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01];

        let aid = [
            0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x03, 0x04, 0x00, 0x06, 0x01, 0x02, 0x03, 0x04,
            0x00, 0x00,
        ];
        let status = OpenPgpStatusView {
            aid: &aid,
            sig_attrs: &ed25519_raw,
            dec_attrs: &x25519_raw,
            aut_attrs: &ed25519_raw,
            fingerprint_sig: [0x11; 20],
            fingerprint_dec: [0x22; 20],
            fingerprint_aut: [0x33; 20],
            serial: Some(0x0102_0304),
            full_serial: Some(0x0102_0304),
        };

        let mut session = MockSlotSession::new(true, vec![]);
        session.sign_key = Some(PublicKey::Ecc {
            point: vec![0xA1; 32],
        });
        session.decrypt_key = Some(PublicKey::Ecc {
            point: vec![0xB2; 32],
        });
        session.auth_key = Some(PublicKey::Ecc {
            point: vec![0xC3; 32],
        });

        let keys = list_keys_in_session(
            &mut session,
            &status,
            &[KeyCrt::Sign, KeyCrt::Decrypt, KeyCrt::Auth],
        )
        .unwrap();

        assert_eq!(
            session.pubkey_reads,
            vec![KeyCrt::Sign, KeyCrt::Decrypt, KeyCrt::Auth]
        );
        assert_eq!(keys.len(), 3);

        assert_eq!(keys[0].slot, KeyCrt::Sign);
        assert_eq!(keys[0].fingerprint, [0x11; 20]);
        assert_eq!(keys[0].aid, aid);
        assert_eq!(keys[0].serial, Some(0x0102_0304));
        assert_eq!(keys[0].full_serial, Some(0x0102_0304));
        assert_eq!(
            keys[0].attrs,
            AlgorithmAttributes::Ecc {
                kind: EccKind::EdDsa,
                curve: Curve::Ed25519,
                import_with_public_key: false,
            }
        );

        assert_eq!(keys[1].slot, KeyCrt::Decrypt);
        assert_eq!(keys[1].fingerprint, [0x22; 20]);
        assert_eq!(
            keys[1].attrs,
            AlgorithmAttributes::Ecc {
                kind: EccKind::Ecdh,
                curve: Curve::X25519,
                import_with_public_key: false,
            }
        );

        assert_eq!(keys[2].slot, KeyCrt::Auth);
        assert_eq!(keys[2].fingerprint, [0x33; 20]);
    }

    #[test]
    fn sign_raw_handles_serial_mismatch_stale_apdu_and_cancel() {
        let pinentry = MockPinentry::new(Some("123456"));
        let mut ops = MockOps::new(true, vec![0xBB; 64]);

        // Serial mismatch -> NotFound without signing
        let mismatch = sign_raw_in_session(
            &mut ops,
            KeyCrt::Auth,
            Some(88),
            Some(77),
            b"challenge",
            &pinentry,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(mismatch, CardOperationOutcome::NotFound);
        assert_eq!(ops.authenticates, 0);

        // Stale APDU (6A88) -> NotFound
        let mut stale_ops = MockOps::new(true, vec![]);
        stale_ops.error = Some(|| TransportError::Apdu {
            label: "INTERNAL AUTHENTICATE",
            sw1: 0x6A,
            sw2: 0x88,
        });
        let stale = sign_raw_in_session(
            &mut stale_ops,
            KeyCrt::Auth,
            Some(77),
            Some(77),
            b"challenge",
            &pinentry,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(stale, CardOperationOutcome::NotFound);

        // User cancel -> UserCancelled
        let mut cancel_ops = MockOps::new(false, vec![0xBB; 64]);
        let cancel_pinentry = MockPinentry::new(None);
        let cancelled = sign_raw_in_session(
            &mut cancel_ops,
            KeyCrt::Auth,
            Some(77),
            Some(77),
            b"challenge",
            &cancel_pinentry,
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(cancelled, CardOperationOutcome::UserCancelled);
        assert_eq!(cancel_pinentry.prompts(), 1);
    }

    #[test]
    fn decrypt_rsa_verifies_pw1_other_forwards_prompt_context_and_returns_plaintext() {
        let mut ops = MockOps::new(false, b"recovered-session-key".to_vec());
        let pinentry = MockPinentry::new(Some("123456"));
        let env = PinentryEnv {
            ttyname: Some("/dev/pts/1".to_owned()),
            ..Default::default()
        };

        let outcome = decrypt_rsa_in_session(
            &mut ops,
            Some(42),
            Some(42),
            b"rsa-cryptogram",
            &pinentry,
            None,
            Some("Decrypt message"),
            Some(&env),
        )
        .unwrap();

        assert_eq!(
            outcome,
            CardOperationOutcome::Completed(b"recovered-session-key".to_vec())
        );
        assert_eq!(ops.rsa_decrypts, 2);
        assert_eq!(ops.ecdh_decrypts, 0);
        assert_eq!(ops.last_input, b"rsa-cryptogram");
        assert_eq!(ops.verified_refs, vec![PW1_OTHER]);
        assert_eq!(
            pinentry.full_calls(),
            vec![PromptCall {
                allow_external_cache: false,
                error: None,
                description: Some("Decrypt message".to_owned()),
                env: Some(env),
            }]
        );
    }

    #[test]
    fn decrypt_rsa_handles_serial_mismatch_stale_apdu_and_cancel() {
        let pinentry = MockPinentry::new(Some("123456"));
        let mut ops = MockOps::new(true, b"plain".to_vec());

        assert_eq!(
            decrypt_rsa_in_session(
                &mut ops,
                Some(99),
                Some(42),
                b"ct",
                &pinentry,
                None,
                None,
                None,
            )
            .unwrap(),
            CardOperationOutcome::NotFound
        );
        assert_eq!(ops.rsa_decrypts, 0);

        let mut stale_ops = MockOps::new(true, vec![]);
        stale_ops.error = Some(|| TransportError::Apdu {
            label: "PSO:DECIPHER",
            sw1: 0x6A,
            sw2: 0x88,
        });
        assert_eq!(
            decrypt_rsa_in_session(
                &mut stale_ops,
                Some(42),
                Some(42),
                b"ct",
                &pinentry,
                None,
                None,
                None,
            )
            .unwrap(),
            CardOperationOutcome::NotFound
        );

        let mut cancel_ops = MockOps::new(false, b"plain".to_vec());
        let cancel_pinentry = MockPinentry::new(None);
        assert_eq!(
            decrypt_rsa_in_session(
                &mut cancel_ops,
                Some(42),
                Some(42),
                b"ct",
                &cancel_pinentry,
                None,
                None,
                None,
            )
            .unwrap(),
            CardOperationOutcome::UserCancelled
        );
    }

    #[test]
    fn decrypt_ecdh_verifies_pw1_other_and_returns_shared_secret() {
        let mut ops = MockOps::new(false, vec![0x55; 32]);
        let pinentry = MockPinentry::new(Some("123456"));
        let cache = PinCache::new(Duration::from_secs(60), None);

        let outcome = decrypt_ecdh_in_session(
            &mut ops,
            Some(77),
            Some(77),
            &[0x40; 33],
            &pinentry,
            Some(&cache),
            Some("Decrypt ECDH"),
            None,
        )
        .unwrap();

        assert_eq!(outcome, CardOperationOutcome::Completed(vec![0x55; 32]));
        assert_eq!(ops.ecdh_decrypts, 2);
        assert_eq!(ops.rsa_decrypts, 0);
        assert_eq!(ops.last_input, vec![0x40; 33]);
        assert_eq!(ops.verified_refs, vec![PW1_OTHER]);
        assert_eq!(
            pinentry.full_calls(),
            vec![PromptCall {
                allow_external_cache: false,
                error: None,
                description: Some("Decrypt ECDH".to_owned()),
                env: None,
            }]
        );

        // Second call hits PIN cache without re-prompting.
        let mut ops2 = MockOps::new(false, vec![0x66; 32]);
        let outcome2 = decrypt_ecdh_in_session(
            &mut ops2,
            Some(77),
            Some(77),
            &[0x41; 33],
            &pinentry,
            Some(&cache),
            Some("Decrypt ECDH"),
            None,
        )
        .unwrap();
        assert_eq!(outcome2, CardOperationOutcome::Completed(vec![0x66; 32]));
        assert_eq!(pinentry.prompts(), 1);
        assert_eq!(ops2.verified_refs, vec![PW1_OTHER]);
    }
}
