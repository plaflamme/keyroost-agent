//! Stubs for the instructions this applet does not implement yet:
//! MOVE KEY and ATTEST — each answers
//! [`keyroost_piv::SW_INS_NOT_SUPPORTED`].
//!
//! GENERATE ASYMMETRIC KEY PAIR and IMPORT ASYMMETRIC KEY live in
//! [`crate::keygen`]; GET DATA and PUT DATA live in [`crate::data`].

use crate::constants::SW_INS_NOT_SUPPORTED;
use crate::{PivApplet, Response};

impl PivApplet {
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
