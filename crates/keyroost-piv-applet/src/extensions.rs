//! Stubs for the instructions this applet does not implement yet: GET
//! DATA, GENERATE ASYMMETRIC KEY PAIR, PUT DATA, IMPORT ASYMMETRIC KEY,
//! MOVE KEY, and ATTEST — each answers
//! [`keyroost_piv::SW_INS_NOT_SUPPORTED`], GET DATA answers
//! [`keyroost_piv::SW_NOT_FOUND`].

use crate::constants::SW_INS_NOT_SUPPORTED;
use crate::{PivApplet, Response};

impl PivApplet {
    /// GET DATA (0xCB, P1P2=`3FFF`): read a data object by its
    /// `5C`-wrapped tag — a slot certificate, the CHUID, an admin object —
    /// and return it wrapped in the `53` data template.
    pub(crate) fn process_get_data(&mut self, _apdu: &[u8]) -> Response {
        Response::sw(keyroost_piv::SW_NOT_FOUND)
    }

    /// GENERATE ASYMMETRIC KEY PAIR (0x47): create a private key on-card in
    /// a slot and return its public key in the `7F 49` template.
    pub(crate) fn process_generate_key_pair(&mut self, _apdu: &[u8]) -> Response {
        Response::sw(SW_INS_NOT_SUPPORTED)
    }

    /// PUT DATA (0xDB): write a data object — a slot certificate or another
    /// object — under its `5C`-wrapped tag.
    pub(crate) fn process_put_data(&mut self, _apdu: &[u8]) -> Response {
        Response::sw(SW_INS_NOT_SUPPORTED)
    }

    /// IMPORT ASYMMETRIC KEY (0x86, Yubico extension,
    /// [`INS_IMPORT_ASYM`](crate::INS_IMPORT_ASYM)):
    /// import a full key pair into a slot.
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
