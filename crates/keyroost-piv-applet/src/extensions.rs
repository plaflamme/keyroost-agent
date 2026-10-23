//! Stub for the one instruction this applet does not implement yet:
//! ATTEST — answering [`keyroost_piv::SW_INS_NOT_SUPPORTED`].
//!
//! GENERATE ASYMMETRIC KEY PAIR, IMPORT ASYMMETRIC KEY and MOVE KEY live in
//! [`crate::keygen`]; GET DATA and PUT DATA live in [`crate::data`].

use crate::constants::SW_INS_NOT_SUPPORTED;
use crate::{PivApplet, Response};

impl PivApplet {
    /// ATTEST (0xF9, Yubico extension): self-signed attestation certificate
    /// for a slot's key, proving on-card generation.
    pub(crate) fn process_attest(&mut self, _apdu: &[u8]) -> Response {
        Response::sw(SW_INS_NOT_SUPPORTED)
    }
}
