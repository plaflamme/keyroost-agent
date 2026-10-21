//! GET VERSION (0xFD), GET SERIAL (0xF8) and GET METADATA (0xF7): the
//! read-only Yubico extension commands.

use crate::constants::{SW_CLA_NOT_SUPPORTED, SW_INS_NOT_SUPPORTED, VERSION};
use crate::{PivApplet, Response, apdu_le};

impl PivApplet {
    /// GET VERSION (0xFD, Yubico extension): the applet version as three
    /// `major.minor.patch` bytes under `9000`.
    ///
    /// Like the other Yubico extensions this accepts both the ISO CLA and
    /// the Yubico proprietary one (`0xFF`); anything else is
    /// [`SW_CLA_NOT_SUPPORTED`]. A case-2 `Le` smaller than three re-enters
    /// the usual `61xx` / GET RESPONSE continuation.
    pub(crate) fn process_get_version(&mut self, apdu: &[u8]) -> Response {
        let cla = apdu[0];
        if cla != 0x00 && cla != 0xFF {
            return Response::sw(SW_CLA_NOT_SUPPORTED);
        }
        let le = match apdu_le(&apdu[4..]) {
            Ok(le) => le,
            Err(()) => return Response::sw(keyroost_piv::SW_WRONG_LENGTH),
        };
        self.split_for_le(VERSION.to_vec(), le)
    }

    /// GET SERIAL (0xF8, Yubico extension): the card serial as four
    /// big-endian bytes under `9000`.
    ///
    /// Like the other Yubico extensions this accepts both the ISO CLA and
    /// the Yubico proprietary one (`0xFF`); anything else is
    /// [`SW_CLA_NOT_SUPPORTED`]. A case-2 `Le` smaller than four re-enters
    /// the usual `61xx` / GET RESPONSE continuation.
    pub(crate) fn process_get_serial(&mut self, apdu: &[u8]) -> Response {
        let cla = apdu[0];
        if cla != 0x00 && cla != 0xFF {
            return Response::sw(SW_CLA_NOT_SUPPORTED);
        }
        let le = match apdu_le(&apdu[4..]) {
            Ok(le) => le,
            Err(()) => return Response::sw(keyroost_piv::SW_WRONG_LENGTH),
        };
        self.split_for_le(self.serial.to_be_bytes().to_vec(), le)
    }

    /// GET METADATA (0xF7, Yubico extension): per-key/PIN metadata
    /// (algorithm, origin, policy, retries) for the P2 reference.
    pub(crate) fn process_get_metadata(&mut self, _apdu: &[u8]) -> Response {
        Response::sw(SW_INS_NOT_SUPPORTED)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::DEFAULT_SERIAL;

    #[test]
    fn get_version_answers_5_7_4() {
        let mut applet = PivApplet::new();
        // The host's case-2 form: `00 FD 00 00 00`.
        let resp = applet.process(&[0x00, 0xFD, 0x00, 0x00, 0x00]);
        assert_eq!(resp.data, [0x05, 0x07, 0x04]);
        assert_eq!(resp.sw, keyroost_piv::SW_OK);
    }

    #[test]
    fn get_version_case1_and_yubico_cla() {
        let mut applet = PivApplet::new();
        for apdu in [[0x00u8, 0xFD, 0x00, 0x00], [0xFF, 0xFD, 0x00, 0x00]] {
            let resp = applet.process(&apdu);
            assert_eq!(resp.data, [0x05, 0x07, 0x04]);
            assert_eq!(resp.sw, keyroost_piv::SW_OK);
        }
    }

    #[test]
    fn get_version_rejects_other_clas() {
        let mut applet = PivApplet::new();
        let resp = applet.process(&[0x40, 0xFD, 0x00, 0x00]);
        assert_eq!(resp.data, Vec::new());
        assert_eq!(resp.sw, SW_CLA_NOT_SUPPORTED);
    }

    #[test]
    fn get_version_small_le_truncates_and_get_response_completes() {
        let mut applet = PivApplet::new();
        let first = applet.process(&[0x00, 0xFD, 0x00, 0x00, 0x02]);
        assert_eq!(first.data, [0x05, 0x07]);
        assert_eq!(first.sw, 0x6101);
        let rest = applet.process(&[0x00, 0xC0, 0x00, 0x00, 0x00]);
        assert_eq!(rest.data, [0x04]);
        assert_eq!(rest.sw, keyroost_piv::SW_OK);
    }

    #[test]
    fn get_serial_returns_the_serial_big_endian() {
        let mut applet = PivApplet::with_serial(0x0240_8A1B);
        // The host's case-2 form: `00 F8 00 00 00`.
        let resp = applet.process(&[0x00, 0xF8, 0x00, 0x00, 0x00]);
        assert_eq!(resp.data, [0x02, 0x40, 0x8A, 0x1B]);
        assert_eq!(resp.sw, keyroost_piv::SW_OK);
    }

    #[test]
    fn get_serial_default_applet_carries_the_default_serial() {
        let mut applet = PivApplet::new();
        // Case 1: no `Le` at all.
        let resp = applet.process(&[0x00, 0xF8, 0x00, 0x00]);
        assert_eq!(resp.data, DEFAULT_SERIAL.to_be_bytes().to_vec());
        assert_eq!(resp.sw, keyroost_piv::SW_OK);
    }

    #[test]
    fn get_serial_accepts_the_yubico_cla() {
        let mut applet = PivApplet::with_serial(7);
        let resp = applet.process(&[0xFF, 0xF8, 0x00, 0x00]);
        assert_eq!(resp.data, [0x00, 0x00, 0x00, 0x07]);
        assert_eq!(resp.sw, keyroost_piv::SW_OK);
    }

    #[test]
    fn get_serial_rejects_other_clas() {
        let mut applet = PivApplet::new();
        let resp = applet.process(&[0x40, 0xF8, 0x00, 0x00]);
        assert_eq!(resp.data, Vec::new());
        assert_eq!(resp.sw, SW_CLA_NOT_SUPPORTED);
    }

    #[test]
    fn get_serial_small_le_truncates_and_get_response_completes() {
        let mut applet = PivApplet::with_serial(0xAABB_CCDD);
        let first = applet.process(&[0x00, 0xF8, 0x00, 0x00, 0x02]);
        assert_eq!(first.data, [0xAA, 0xBB]);
        assert_eq!(first.sw, 0x6102);
        let rest = applet.process(&[0x00, 0xC0, 0x00, 0x00, 0x00]);
        assert_eq!(rest.data, [0xCC, 0xDD]);
        assert_eq!(rest.sw, keyroost_piv::SW_OK);
    }
}
