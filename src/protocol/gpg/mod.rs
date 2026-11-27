pub(crate) mod cache;
pub(crate) mod keygrip;
pub(crate) mod server;
pub(crate) mod sexp;

use std::future::Future;

use keyroost_openpgp::KeyCrt;
use tokio::net::UnixListener;
use tracing::{debug, warn};

use crate::{
    card::{
        CardOperationOutcome,
        openpgp::{OpenPgpCard, OpenPgpKeyInfo},
    },
    idle::IdleTracker,
    pin_cache::PinCache,
    pinentry::PinentryEnv,
    protocol::gpg::cache::GpgKeyCache,
};

/// Internal card backend abstraction allowing the Assuan server loop to be
/// unit-tested with a mock card.
pub(crate) trait GpgCardBackend: Clone + Send + Sync + 'static {
    fn list_keys(
        &self,
        slots: &[KeyCrt],
    ) -> impl Future<Output = Result<Vec<OpenPgpKeyInfo>, crate::Error>> + Send;

    fn sign_raw(
        &self,
        slot: KeyCrt,
        expected_serial: Option<u128>,
        data: &[u8],
        prompt_desc: Option<&str>,
        prompt_env: Option<&PinentryEnv>,
    ) -> impl Future<Output = Result<CardOperationOutcome<Vec<u8>>, crate::Error>> + Send;

    fn decrypt_rsa(
        &self,
        expected_serial: Option<u128>,
        cryptogram: &[u8],
        prompt_desc: Option<&str>,
        prompt_env: Option<&PinentryEnv>,
    ) -> impl Future<Output = Result<CardOperationOutcome<Vec<u8>>, crate::Error>> + Send;

    fn decrypt_ecdh(
        &self,
        expected_serial: Option<u128>,
        ephemeral_point: &[u8],
        prompt_desc: Option<&str>,
        prompt_env: Option<&PinentryEnv>,
    ) -> impl Future<Output = Result<CardOperationOutcome<Vec<u8>>, crate::Error>> + Send;

    fn disconnect(&self) -> impl Future<Output = ()> + Send;
}

impl GpgCardBackend for OpenPgpCard {
    fn list_keys(
        &self,
        slots: &[KeyCrt],
    ) -> impl Future<Output = Result<Vec<OpenPgpKeyInfo>, crate::Error>> + Send {
        OpenPgpCard::list_keys(self, slots)
    }

    fn sign_raw(
        &self,
        slot: KeyCrt,
        expected_serial: Option<u128>,
        data: &[u8],
        prompt_desc: Option<&str>,
        prompt_env: Option<&PinentryEnv>,
    ) -> impl Future<Output = Result<CardOperationOutcome<Vec<u8>>, crate::Error>> + Send {
        OpenPgpCard::sign_raw(self, slot, expected_serial, data, prompt_desc, prompt_env)
    }

    fn decrypt_rsa(
        &self,
        expected_serial: Option<u128>,
        cryptogram: &[u8],
        prompt_desc: Option<&str>,
        prompt_env: Option<&PinentryEnv>,
    ) -> impl Future<Output = Result<CardOperationOutcome<Vec<u8>>, crate::Error>> + Send {
        OpenPgpCard::decrypt_rsa(self, expected_serial, cryptogram, prompt_desc, prompt_env)
    }

    fn decrypt_ecdh(
        &self,
        expected_serial: Option<u128>,
        ephemeral_point: &[u8],
        prompt_desc: Option<&str>,
        prompt_env: Option<&PinentryEnv>,
    ) -> impl Future<Output = Result<CardOperationOutcome<Vec<u8>>, crate::Error>> + Send {
        OpenPgpCard::decrypt_ecdh(
            self,
            expected_serial,
            ephemeral_point,
            prompt_desc,
            prompt_env,
        )
    }

    fn disconnect(&self) -> impl Future<Output = ()> + Send {
        OpenPgpCard::disconnect(self)
    }
}

#[derive(Clone)]
#[allow(dead_code)]
pub(crate) struct GpgAgent {
    openpgp: Option<OpenPgpCard>,
    idle_tracker: IdleTracker,
    pin_cache: Option<PinCache>,
    key_cache: GpgKeyCache,
    socket_name: Option<String>,
}

#[allow(dead_code)]
impl GpgAgent {
    pub(crate) fn new(
        openpgp: Option<OpenPgpCard>,
        idle_tracker: IdleTracker,
        pin_cache: Option<PinCache>,
        socket_name: Option<String>,
    ) -> Self {
        Self {
            openpgp,
            idle_tracker,
            pin_cache,
            key_cache: GpgKeyCache::new(),
            socket_name,
        }
    }

    pub(crate) async fn disconnect(&self) {
        if let Some(openpgp) = &self.openpgp {
            openpgp.disconnect().await;
        }
    }

    pub(crate) fn clear_pin_cache(&self) {
        if let Some(pin_cache) = &self.pin_cache {
            pin_cache.clear();
        }
    }

    pub(crate) fn clear_key_cache(&self) {
        self.key_cache.clear();
    }
}

#[allow(dead_code)]
pub(crate) async fn serve(listener: UnixListener, agent: GpgAgent) -> Result<(), std::io::Error> {
    loop {
        let (stream, _addr) = listener.accept().await?;
        let conn_agent = agent.clone();
        tokio::spawn(async move {
            if let Err(err) = server::serve_connection(
                stream,
                conn_agent.openpgp,
                conn_agent.idle_tracker,
                conn_agent.pin_cache,
                conn_agent.key_cache,
                conn_agent.socket_name,
            )
            .await
            {
                match err.kind() {
                    std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::UnexpectedEof => {
                        debug!("GPG client disconnected: {err}");
                    }
                    _ => {
                        warn!("GPG connection error: {err}");
                    }
                }
            }
        });
    }
}
