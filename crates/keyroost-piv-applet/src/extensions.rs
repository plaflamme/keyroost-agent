//! Stubs for the instructions this applet does not implement yet:
//! GENERATE ASYMMETRIC KEY PAIR, IMPORT ASYMMETRIC KEY, MOVE KEY, and
//! ATTEST — each answers
//! [`keyroost_piv::SW_INS_NOT_SUPPORTED`].
//!
//! GET DATA and PUT DATA live in [`crate::data`].

use crate::constants::SW_INS_NOT_SUPPORTED;
use crate::{PivApplet, Response};

impl PivApplet {
    /// GENERATE ASYMMETRIC KEY PAIR (0x47): create a private key on-card in
    /// a slot and return its public key in the `7F 49` template.
    pub(crate) fn process_generate_key_pair(&mut self, _apdu: &[u8]) -> Response {
        Response::sw(SW_INS_NOT_SUPPORTED)
    }

    /// IMPORT ASYMMETRIC KEY (0x86, Yubico extension): import a full key
    /// pair into a slot.
    pub(crate) fn process_import_key(&mut self, _apdu: &[u8]) -> Response {
        Response::sw(SW_INS_NOT_SUPPORTED)
    }

    /// MOVE KEY (0xF6, Yubico extension): move a slot's key to another slot;
    /// `P1 = 0xFF` deletes the key instead.
    pub(crate) fn process_move_key(&mut self, _apdu: &[u8]) -> Response {
        Response::sw(SW_INS_NOT_SUPPORTED)
    }

    /// ATTEST (0xF9, Yubico extension): self-signed attestation certificate
    /// for a slot's key, proving on-card generation.
    pub(crate) fn process_attest(&mut self, _apdu: &[u8]) -> Response {
        Response::sw(SW_INS_NOT_SUPPORTED)
    }
}
