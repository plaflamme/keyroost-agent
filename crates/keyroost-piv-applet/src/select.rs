//! SELECT (0xA4) and GET RESPONSE (0xC0): applet activation by AID, and
//! the `61xx` / `9000` continuation protocol for responses that do not fit
//! the requested `Le`.

use crate::constants::{
    AID_FULL, AID_RID, INS_SELECT_P1_BY_AID, SW_CLA_NOT_SUPPORTED, SW_CONDITIONS_NOT_SATISFIED,
    TAG_4F, TAG_61, TAG_79,
};
use crate::{PivApplet, Response, apdu_le};

impl PivApplet {
    /// SELECT (0xA4, P1=`04`): activate the applet by AID.
    ///
    /// The AID is matched the way a `YubiKey` matches: any prefix of
    /// [`AID_FULL`] of at least [`AID_RID`] length selects the applet, so
    /// the host's 11-byte `select_full()`, its 5-byte `select()`, and
    /// `OpenSC`'s 9-byte generic PIV AID all work. A different P1, a shorter
    /// or non-matching AID answers [`keyroost_piv::SW_NOT_FOUND`].
    ///
    /// On success the answer is the application property template a
    /// `YubiKey` 5 returns, byte for byte:
    ///
    /// ```text
    /// 61 11
    ///   4F 06 00 00 10 00 01 00   the AID after the RID
    ///   79 07
    ///     4F 05 A0 00 00 03 08   the RID
    /// 90 00
    /// ```
    ///
    /// A case-4 `Le` shorter than the template truncates the data and
    /// switches the status word to `61xx` (the remaining count); the
    /// overflow is stashed for a follow-up GET RESPONSE.
    pub(crate) fn process_select(&mut self, apdu: &[u8]) -> Response {
        let [cla, ..] = apdu else {
            // `process` guarantees the 4-byte header.
            unreachable!("process guarantees the 4-byte header");
        };
        if cla & 0x90 != 0 {
            return Response::sw(SW_CLA_NOT_SUPPORTED);
        }
        if apdu[2] != INS_SELECT_P1_BY_AID {
            return Response::sw(keyroost_piv::SW_NOT_FOUND);
        }
        // Case-1/2 APDUs carry no length byte at all: no AID to match.
        let (lc, body) = match apdu.get(4) {
            Some(&lc) => (lc, &apdu[5..]),
            None => (0, &apdu[4..]),
        };
        let Some(aid) = body.get(..usize::from(lc)) else { return Response::sw(keyroost_piv::SW_WRONG_LENGTH) };
        if !(aid.len() >= AID_RID.len() && AID_FULL.starts_with(aid)) {
            return Response::sw(keyroost_piv::SW_NOT_FOUND);
        }
        let Ok(le) = apdu_le(&body[aid.len()..]) else { return Response::sw(keyroost_piv::SW_WRONG_LENGTH) };
        self.split_for_le(Self::select_response(), le)
    }

    /// The application property template a SELECT answers with — the
    /// `YubiKey` 5 response: a `61` wrapper holding the AID after the RID
    /// (tag `4F`) and the RID itself (tag `4F` inside the `79`
    /// application-identifier template).
    #[allow(clippy::cast_possible_truncation)]
    fn select_response() -> Vec<u8> {
        let suffix = &AID_FULL[AID_RID.len()..];
        let mut body = Vec::with_capacity(suffix.len() + 2 + AID_RID.len() + 4);
        body.push(TAG_4F);
        body.push(suffix.len() as u8);
        body.extend_from_slice(suffix);
        body.push(TAG_79);
        body.push(2 + AID_RID.len() as u8);
        body.push(TAG_4F);
        body.push(AID_RID.len() as u8);
        body.extend_from_slice(&AID_RID);
        let mut out = Vec::with_capacity(body.len() + 2);
        out.push(TAG_61);
        out.push(body.len() as u8);
        out.append(&mut body);
        out
    }

    /// GET RESPONSE (0xC0): fetch the tail of a response the previous
    /// command signalled with `61xx` (large objects such as certificates
    /// arrive this way; while the crate is wiring only, SELECT is the only
    /// such producer). The stashed bytes come back under `9000`, re-capped
    /// by this command's own `Le` when it carries one; a GET RESPONSE with
    /// nothing pending answers [`SW_CONDITIONS_NOT_SATISFIED`].
    pub(crate) fn process_get_response(&mut self, apdu: &[u8]) -> Response {
        let [cla, ..] = apdu else {
            // `process` guarantees the 4-byte header; there is nothing
            // else to be malformed here.
            unreachable!("process guarantees the 4-byte header");
        };
        if cla & 0x90 != 0 {
            return Response::sw(SW_CLA_NOT_SUPPORTED);
        }
        let Some(tail) = self.get_response_tail.take() else { return Response::sw(SW_CONDITIONS_NOT_SATISFIED) };
        let Ok(le) = apdu_le(&apdu[4..]) else { return Response::sw(keyroost_piv::SW_WRONG_LENGTH) };
        self.split_for_le(tail, le)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact SELECT response a YubiKey 5 returns (body, no SW), as
    /// captured on hardware: a `61` wrapper holding the AID after the RID
    /// and the RID itself.
    const YUBIKEY5_SELECT_BODY: [u8; 19] = [
        0x61, 0x11, 0x4F, 0x06, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x79, 0x07, 0x4F, 0x05, 0xA0,
        0x00, 0x00, 0x03, 0x08,
    ];

    /// A case-3/4 SELECT-by-AID APDU with optional `Le` byte.
    fn select_with_aid(aid: &[u8], le: Option<u8>) -> Vec<u8> {
        let mut apdu = vec![0x00, 0xA4, 0x04, 0x00, aid.len() as u8];
        apdu.extend_from_slice(aid);
        if let Some(le) = le {
            apdu.push(le);
        }
        apdu
    }

    #[test]
    fn select_full_aid_answers_the_yubico_template() {
        let mut applet = PivApplet::new();
        let resp = applet.process(&select_with_aid(&AID_FULL, Some(0)));
        assert_eq!(resp.data, YUBIKEY5_SELECT_BODY);
        assert_eq!(resp.sw, keyroost_piv::SW_OK);
    }

    #[test]
    fn select_rid_prefix_selects() {
        let mut applet = PivApplet::new();
        let resp = applet.process(&select_with_aid(&AID_RID, Some(0)));
        assert_eq!(resp.data, YUBIKEY5_SELECT_BODY);
        assert_eq!(resp.sw, keyroost_piv::SW_OK);
    }

    #[test]
    fn select_generic_nine_byte_aid_selects() {
        // OpenSC's `piv_find_aid` probe: the 9-byte generic PIV AID.
        let aid: [u8; 9] = AID_FULL[..9].try_into().unwrap();
        let mut applet = PivApplet::new();
        let resp = applet.process(&select_with_aid(&aid, Some(0)));
        assert_eq!(resp.data, YUBIKEY5_SELECT_BODY);
        assert_eq!(resp.sw, keyroost_piv::SW_OK);
    }

    #[test]
    fn select_case3_sends_the_whole_template() {
        let mut applet = PivApplet::new();
        let resp = applet.process(&select_with_aid(&AID_FULL, None));
        assert_eq!(resp.data, YUBIKEY5_SELECT_BODY);
        assert_eq!(resp.sw, keyroost_piv::SW_OK);
    }

    #[test]
    fn select_aid_shorter_than_rid_is_not_found() {
        let mut applet = PivApplet::new();
        let resp = applet.process(&select_with_aid(&AID_FULL[..4], Some(0)));
        assert_eq!(resp.data, Vec::new());
        assert_eq!(resp.sw, keyroost_piv::SW_NOT_FOUND);
    }

    #[test]
    fn select_aid_longer_than_full_is_not_found() {
        let mut long = AID_FULL.to_vec();
        long.push(0x00);
        let mut applet = PivApplet::new();
        let resp = applet.process(&select_with_aid(&long, Some(0)));
        assert_eq!(resp.sw, keyroost_piv::SW_NOT_FOUND);
    }

    #[test]
    fn select_non_matching_aid_is_not_found() {
        let aid = [0xA0, 0x00, 0x00, 0x03, 0x09];
        let mut applet = PivApplet::new();
        let resp = applet.process(&select_with_aid(&aid, Some(0)));
        assert_eq!(resp.sw, keyroost_piv::SW_NOT_FOUND);
    }

    #[test]
    fn select_not_by_aid_is_not_found() {
        let mut applet = PivApplet::new();
        let resp = applet.process(&[0x00, 0xA4, 0x00, 0x00]);
        assert_eq!(resp.sw, keyroost_piv::SW_NOT_FOUND);
    }

    #[test]
    fn select_with_cla_bits_is_rejected() {
        let mut applet = PivApplet::new();
        for cla in [0x80u8, 0x10u8] {
            let mut apdu = select_with_aid(&AID_FULL, Some(0));
            apdu[0] = cla;
            let resp = applet.process(&apdu);
            assert_eq!(resp.sw, SW_CLA_NOT_SUPPORTED);
        }
    }

    #[test]
    fn select_lc_overrunning_the_apdu_is_wrong_length() {
        let mut applet = PivApplet::new();
        // Lc claims 11 bytes, only 5 AID bytes are present.
        let resp = applet.process(&[0x00, 0xA4, 0x04, 0x00, 0x0B, 0xA0, 0x00, 0x00, 0x03, 0x08]);
        assert_eq!(resp.sw, keyroost_piv::SW_WRONG_LENGTH);
    }

    #[test]
    fn select_small_le_truncates_and_get_response_completes() {
        let mut applet = PivApplet::new();
        let first = applet.process(&select_with_aid(&AID_FULL, Some(5)));
        assert_eq!(first.data, &YUBIKEY5_SELECT_BODY[..5]);
        assert_eq!(first.sw, 0x610E); // 19 - 5 = 14 remain
        let rest = applet.process(&[0x00, 0xC0, 0x00, 0x00, 0x00]);
        assert_eq!(rest.data, &YUBIKEY5_SELECT_BODY[5..]);
        assert_eq!(rest.sw, keyroost_piv::SW_OK);
        // Nothing pending any more.
        let none = applet.process(&[0x00, 0xC0, 0x00, 0x00, 0x00]);
        assert_eq!(none.data, Vec::new());
        assert_eq!(none.sw, SW_CONDITIONS_NOT_SATISFIED);
    }

    #[test]
    fn get_response_with_own_le_re_caps_the_tail() {
        let mut applet = PivApplet::new();
        applet.process(&select_with_aid(&AID_FULL, Some(5)));
        let first = applet.process(&[0x00, 0xC0, 0x00, 0x00, 0x04]);
        assert_eq!(first.data, &YUBIKEY5_SELECT_BODY[5..9]);
        assert_eq!(first.sw, 0x610A); // 14 - 4 = 10 remain
        let rest = applet.process(&[0x00, 0xC0, 0x00, 0x00, 0x00]);
        assert_eq!(rest.data, &YUBIKEY5_SELECT_BODY[9..]);
        assert_eq!(rest.sw, keyroost_piv::SW_OK);
    }
}
