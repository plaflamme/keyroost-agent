//! VERIFY (0x20), CHANGE REFERENCE DATA (0x24) and RESET RETRY COUNTER
//! (0x2C): the PIN/PUK reference-data commands.

use crate::{PivApplet, Response};

/// PIN reference (P2) for the PIV application PIN.
const PIN_REF_APPLICATION: u8 = 0x80;
/// PIN reference (P2) for the PUK.
const PIN_REF_PUK: u8 = 0x81;

impl PivApplet {
    /// VERIFY (0x20): present the application PIN (P2=`80`) against the
    /// stored value, or query its retry status with an empty body.
    ///
    /// Mirrors the card's `processVerify`:
    ///
    /// - P1 `00` with an 8-byte body presents the PIN: `9000` on a match
    ///   (the session becomes verified), `63Cx` otherwise (x tries
    ///   remaining; the last wrong try answers `63C0`, the next command
    ///   `6983`).
    /// - P1 `00` with no body queries the status: `9000` when already
    ///   verified, `63Cx` otherwise, `6983` when blocked.
    /// - P1 `FF` (Yubico extension) clears the verified state — resetting
    ///   the counter to its limit when the PIN was verified, leaving an
    ///   unverified counter alone — and answers `9000`.
    /// - Only the application PIN exists: the card's last commit removed
    ///   PUK verification, so any other P2 answers `6A88`.
    ///
    /// The card also syncs the key slots' security status from the verified
    /// state on every VERIFY; this applet has no key slots yet.
    pub(crate) fn process_verify(&mut self, command: &crate::apdu::CommandView<'_>) -> Response {
        if command.p1 != 0x00 && command.p1 != 0xFF {
            return iso7816::Status::IncorrectP1OrP2Parameter.into();
        }
        let pin = if command.p2 == PIN_REF_APPLICATION {
            &mut self.pin
        } else {
            return iso7816::Status::KeyReferenceNotFound.into();
        };
        let body = command.data();
        let lc = body.len();
        if pin.tries() == 0 {
            return iso7816::Status::OperationBlocked.into();
        }
        if command.p1 == 0xFF {
            // "Set security status to false": a verified PIN is reset
            // (counter and flag); an unverified one is left alone.
            if pin.verified() {
                pin.reset();
            }
            return iso7816::Status::Success.into();
        }
        if lc == 0 {
            // Status query: `9000` when verified, else `63Cx`.
            return if pin.verified() {
                return iso7816::Status::Success.into();
            } else {
                iso7816::Status::RemainingRetries(pin.tries()).into()
            };
        }
        if lc != 8 {
            return iso7816::Status::IncorrectDataParameter.into();
        }
        if pin.check(body) {
            // A successful VERIFY arms the PIN/ALWAYS latch: an
            // `ALWAYS`-policy slot operation must follow it immediately.
            // The latch is consumed by the next non-chained APDU — cleared
            // in `process`, where the APDU that armed it survives intact.
            self.pin_always_armed = true;
            iso7816::Status::Success.into()
        } else {
            // The card would also wipe the key slots here if this try
            // blocked both PIN and PUK; the applet has no key slots yet.
            iso7816::Status::RemainingRetries(pin.tries()).into()
        }
    }

    /// CHANGE REFERENCE DATA (0x24): change the application PIN (P2=`80`) or
    /// the PUK (P2=`81`), old value first.
    ///
    /// Mirrors the card's `processChangePin`: the body is the 8-byte old
    /// value followed by the 8-byte new one. The body length is checked
    /// first (`6A86`), then the blocked state (`6983`); the old value is
    /// checked next (a wrong one burns a retry and answers `63Cx`); the new
    /// value must be six to eight ASCII digits — the last two bytes digits
    /// or 0xFF — or the card answers `6A86` without changing anything. A
    /// successful change leaves the session verified (the check that set
    /// it).
    pub(crate) fn process_change_reference(
        &mut self,
        command: &crate::apdu::CommandView<'_>,
    ) -> Response {
        if command.p1 != 0x00 {
            return iso7816::Status::IncorrectP1OrP2Parameter.into();
        }
        let target = match command.p2 {
            PIN_REF_APPLICATION => &mut self.pin,
            PIN_REF_PUK => &mut self.puk,
            _ => return iso7816::Status::KeyReferenceNotFound.into(),
        };
        let body = command.data();
        if body.len() != 16 {
            return iso7816::Status::IncorrectDataParameter.into();
        }
        if target.tries() == 0 {
            return iso7816::Status::OperationBlocked.into();
        }
        let new_value: [u8; 8] = body[8..].try_into().unwrap();
        if !target.check(&body[..8]) {
            // The card would also wipe the key slots here if this try
            // blocked both PIN and PUK; this applet has no key slots yet.
            return iso7816::Status::RemainingRetries(target.tries()).into();
        }
        if !is_valid_pin(new_value) {
            return iso7816::Status::IncorrectDataParameter.into();
        }
        target.set_value(new_value);
        iso7816::Status::Success.into()
    }

    /// RESET RETRY COUNTER (0x2C): unblock the PIN (P2=`80`) using the PUK
    /// and set the new PIN in one command.
    ///
    /// Mirrors the card's `processResetPin`: the body is the 8-byte PUK
    /// followed by the 8-byte new PIN. The body length is checked first
    /// (`6A86`), then the PUK's blocked state (`6983`); the PUK is checked
    /// next (a wrong one burns a PUK retry and answers `63Cx`); the new PIN
    /// must be six to eight ASCII digits or the card answers `6A86`. On
    /// success the PIN takes the new value, its counter resets to its
    /// limit, and its verified state is cleared. (The card's `is_default`
    /// flag is not cleared by an unblock — a quirk worth keeping if GET
    /// METADATA ever reports it.)
    pub(crate) fn process_reset_retry_counter(
        &mut self,
        command: &crate::apdu::CommandView<'_>,
    ) -> Response {
        if command.p1 != 0x00 {
            return iso7816::Status::IncorrectP1OrP2Parameter.into();
        }
        if command.p2 != PIN_REF_APPLICATION {
            return iso7816::Status::KeyReferenceNotFound.into();
        }
        let body = command.data();
        if body.len() != 16 {
            return iso7816::Status::IncorrectDataParameter.into();
        }
        if self.puk.tries() == 0 {
            return iso7816::Status::OperationBlocked.into();
        }
        let new_pin: [u8; 8] = body[8..].try_into().unwrap();
        if !self.puk.check(&body[..8]) {
            // The card would also wipe the key slots here if this try
            // blocked both PIN and PUK; this applet has no key slots yet.
            return iso7816::Status::RemainingRetries(self.puk.tries()).into();
        }
        if !is_valid_pin(new_pin) {
            return iso7816::Status::IncorrectDataParameter.into();
        }
        self.pin.set_value(new_pin);
        self.pin.reset();
        iso7816::Status::Success.into()
    }
}

/// The card's new-PIN/PUK validation: six to eight ASCII digits — the first
/// six bytes must be digits, the last two are digits or 0xFF padding.
fn is_valid_pin(value: [u8; 8]) -> bool {
    value[0..6].iter().all(u8::is_ascii_digit)
        && value[6..].iter().all(|b| *b == 0xFF || b.is_ascii_digit())
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
pub(crate) mod tests {
    use iso7816::Status;

    use super::*;
    use crate::constants::{DEFAULT_PIN_TRIES, DEFAULT_PUK_TRIES};

    // The PIN/PUK tests build APDUs straight, the host byte layer's
    // builders are the host side of the same wire format.

    /// A case-3 APDU `00 INS P1 P2 Lc body` whose `body_len` body bytes are
    /// the ASCII digit `0`.
    fn case3(ins: u8, p1: u8, p2: u8, body_len: usize) -> Vec<u8> {
        let mut apdu = vec![0x00, ins, p1, p2, body_len as u8];
        apdu.extend(std::iter::repeat_n(0x30, body_len));
        apdu
    }

    /// Burn every PIN retry with wrong PINs, asserting each `63Cx` along the
    /// way; afterwards the PIN is blocked.
    pub(crate) fn block_pin(applet: &mut PivApplet) {
        for tries in (1..=DEFAULT_PIN_TRIES).rev() {
            let resp = applet.process(&keyroost_piv::verify_pin(b"000000").unwrap());
            assert_eq!(resp.status(), iso7816::Status::RemainingRetries(tries - 1));
        }
    }

    #[test]
    fn verify_factory_pin_succeeds() {
        let mut applet = PivApplet::new();
        let resp = applet.process(&keyroost_piv::verify_pin(b"123456").unwrap());
        assert_eq!(resp.status(), Status::Success);
    }

    #[test]
    fn verify_status_queries_the_retry_counter() {
        let mut applet = PivApplet::new();
        // Case-1 and case-3 `Le` = 0 both read as an empty body.
        let resp = applet.process(&[0x00, 0x20, 0x00, 0x80]);
        assert_eq!(
            resp.status(),
            iso7816::Status::RemainingRetries(DEFAULT_PIN_TRIES)
        );
        let resp = applet.process(&[0x00, 0x20, 0x00, 0x80, 0x00]);
        assert_eq!(
            resp.status(),
            iso7816::Status::RemainingRetries(DEFAULT_PIN_TRIES)
        );
    }

    #[test]
    fn verify_status_is_ok_after_a_verify() {
        let mut applet = PivApplet::new();
        let resp = applet.process(&keyroost_piv::verify_pin(b"123456").unwrap());
        assert_eq!(resp.status(), Status::Success);
        let resp = applet.process(&[0x00, 0x20, 0x00, 0x80]);
        assert_eq!(resp.status(), Status::Success);
    }

    #[test]
    fn verify_wrong_pin_burns_a_try() {
        let mut applet = PivApplet::new();
        let resp = applet.process(&keyroost_piv::verify_pin(b"000000").unwrap());
        assert_eq!(
            resp.status(),
            iso7816::Status::RemainingRetries(DEFAULT_PIN_TRIES - 1)
        );
    }

    #[test]
    fn verify_failed_try_keeps_a_verified_session() {
        let mut applet = PivApplet::new();
        let resp = applet.process(&keyroost_piv::verify_pin(b"123456").unwrap());
        assert_eq!(resp.status(), Status::Success);
        let resp = applet.process(&keyroost_piv::verify_pin(b"000000").unwrap());
        assert_eq!(
            resp.status(),
            iso7816::Status::RemainingRetries(DEFAULT_PIN_TRIES - 1)
        );
        let resp = applet.process(&[0x00, 0x20, 0x00, 0x80]);
        assert_eq!(resp.status(), Status::Success);
    }

    #[test]
    fn verify_last_try_answers_63c0_then_blocked() {
        let mut applet = PivApplet::new();
        block_pin(&mut applet);
        // Every form of the command now answers `6983`, P1 = FF included.
        let forms: [&[u8]; 3] = [
            &[0x00, 0x20, 0x00, 0x80],
            &[0x00, 0x20, 0x00, 0x80, 0x00],
            &[0x00, 0x20, 0xFF, 0x80],
        ];
        for form in forms {
            let resp = applet.process(form);
            assert_eq!(resp.status(), Status::OperationBlocked);
        }
    }

    #[test]
    fn verify_unverify_clears_a_verified_pin() {
        let mut applet = PivApplet::new();
        let resp = applet.process(&keyroost_piv::verify_pin(b"123456").unwrap());
        assert_eq!(resp.status(), Status::Success);
        let resp = applet.process(&[0x00, 0x20, 0xFF, 0x80]);
        assert_eq!(resp.status(), Status::Success);
        let resp = applet.process(&[0x00, 0x20, 0x00, 0x80]);
        assert_eq!(
            resp.status(),
            iso7816::Status::RemainingRetries(DEFAULT_PIN_TRIES)
        );
    }

    #[test]
    fn verify_unverify_leaves_an_unverified_counter_alone() {
        let mut applet = PivApplet::new();
        let resp = applet.process(&keyroost_piv::verify_pin(b"000000").unwrap());
        assert_eq!(
            resp.status(),
            iso7816::Status::RemainingRetries(DEFAULT_PIN_TRIES - 1)
        );
        let resp = applet.process(&keyroost_piv::verify_pin(b"000000").unwrap());
        assert_eq!(
            resp.status(),
            iso7816::Status::RemainingRetries(DEFAULT_PIN_TRIES - 2)
        );
        let resp = applet.process(&[0x00, 0x20, 0xFF, 0x80]);
        assert_eq!(resp.status(), Status::Success);
        let resp = applet.process(&[0x00, 0x20, 0x00, 0x80]);
        assert_eq!(
            resp.status(),
            iso7816::Status::RemainingRetries(DEFAULT_PIN_TRIES - 2)
        );
    }

    #[test]
    fn verify_rejects_the_puk_reference() {
        let mut applet = PivApplet::new();
        let resp = applet.process(&case3(0x20, 0x00, PIN_REF_PUK, 8));
        assert_eq!(resp.status(), Status::KeyReferenceNotFound);
    }

    #[test]
    fn verify_rejects_other_p1s() {
        let mut applet = PivApplet::new();
        for p1 in [0x01u8, 0x80u8] {
            let resp = applet.process(&case3(0x20, p1, PIN_REF_APPLICATION, 8));
            assert_eq!(resp.status(), Status::IncorrectP1OrP2Parameter);
        }
    }

    #[test]
    fn verify_wrong_length_body_is_wrong_data() {
        let mut applet = PivApplet::new();
        let resp = applet.process(&case3(0x20, 0x00, PIN_REF_APPLICATION, 7));
        assert_eq!(resp.status(), Status::IncorrectDataParameter);
    }

    #[test]
    fn verify_lc_overrun_is_wrong_length() {
        let mut applet = PivApplet::new();
        let resp = applet.process(&[0x00, 0x20, 0x00, 0x80, 0x09, 0x31, 0x32, 0x33, 0x34]);
        assert_eq!(resp.status(), iso7816::Status::WrongLength);
    }

    #[test]
    fn change_reference_changes_the_pin() {
        let mut applet = PivApplet::new();
        let resp = applet.process(
            &keyroost_piv::change_reference(PIN_REF_APPLICATION, b"123456", b"654321").unwrap(),
        );
        assert_eq!(resp.status(), Status::Success);
        let resp = applet.process(&keyroost_piv::verify_pin(b"654321").unwrap());
        assert_eq!(resp.status(), Status::Success);
    }

    #[test]
    fn change_reference_changes_the_puk() {
        let mut applet = PivApplet::new();
        let resp = applet.process(
            &keyroost_piv::change_reference(PIN_REF_PUK, b"12345678", b"87654321").unwrap(),
        );
        assert_eq!(resp.status(), Status::Success);
        let resp = applet.process(&keyroost_piv::unblock_pin(b"87654321", b"111111").unwrap());
        assert_eq!(resp.status(), Status::Success);
    }

    #[test]
    fn change_reference_wrong_old_value_burns_a_try() {
        let mut applet = PivApplet::new();
        let resp = applet.process(
            &keyroost_piv::change_reference(PIN_REF_APPLICATION, b"000000", b"654321").unwrap(),
        );
        assert_eq!(
            resp.status(),
            iso7816::Status::RemainingRetries(DEFAULT_PIN_TRIES - 1)
        );
        let resp = applet.process(&keyroost_piv::verify_pin(b"123456").unwrap());
        assert_eq!(resp.status(), Status::Success);
    }

    #[test]
    fn change_reference_invalid_new_value_is_wrong_data() {
        let mut applet = PivApplet::new();
        // A non-digit in the first six bytes of the new value.
        let body = [
            b"123456".as_slice(),
            &[0xFF, 0xFF],
            b"65432a".as_slice(),
            &[0xFF, 0xFF],
        ]
        .concat();
        assert_change_reference_body(&mut applet, &body, Status::IncorrectDataParameter);
        // A five-digit new value: 0xFF lands in the sixth position, which
        // must be a digit. The host builder refuses to build it, so the
        // body is hand-rolled.
        let body = [
            b"123456".as_slice(),
            &[0xFF, 0xFF],
            b"65432".as_slice(),
            &[0xFF; 3],
        ]
        .concat();
        assert_change_reference_body(&mut applet, &body, Status::IncorrectDataParameter);
        // The PIN is unchanged; nothing was burned (the old value was
        // correct and the new one was never stored).
        let resp = applet.process(&keyroost_piv::verify_pin(b"123456").unwrap());
        assert_eq!(resp.status(), Status::Success);
    }

    /// Send a CHANGE REFERENCE DATA APDU with the given 16-byte body and
    /// assert the status word.
    fn assert_change_reference_body(applet: &mut PivApplet, body: &[u8], sw: Status) {
        let mut apdu = vec![0x00, 0x24, 0x00, 0x80, body.len() as u8];
        apdu.extend_from_slice(body);
        let resp = applet.process(&apdu);
        assert_eq!(resp.status(), sw);
    }

    #[test]
    fn change_reference_rejects_a_non_digit_new_pin_byte() {
        let mut applet = PivApplet::new();
        // The last two bytes of the new value may be digits (a seven- or
        // eight-digit PIN) or 0xFF — anything else is rejected.
        let body = [
            b"123456".as_slice(),
            &[0xFF, 0xFF],
            b"654321".as_slice(),
            &[0x61, 0x61],
        ]
        .concat();
        assert_change_reference_body(&mut applet, &body, Status::IncorrectDataParameter);
    }

    #[test]
    fn change_reference_accepts_a_seven_digit_pin() {
        let mut applet = PivApplet::new();
        let resp = applet.process(
            &keyroost_piv::change_reference(PIN_REF_APPLICATION, b"123456", b"6543217").unwrap(),
        );
        assert_eq!(resp.status(), Status::Success);
        let resp = applet.process(&keyroost_piv::verify_pin(b"6543217").unwrap());
        assert_eq!(resp.status(), Status::Success);
    }

    #[test]
    fn change_reference_wrong_length_body_is_wrong_data() {
        let mut applet = PivApplet::new();
        let resp = applet.process(&case3(0x24, 0x00, PIN_REF_APPLICATION, 15));
        assert_eq!(resp.status(), Status::IncorrectDataParameter);
    }

    #[test]
    fn change_reference_blocked_reference_is_blocked() {
        let mut applet = PivApplet::new();
        block_pin(&mut applet);
        let resp = applet.process(
            &keyroost_piv::change_reference(PIN_REF_APPLICATION, b"123456", b"654321").unwrap(),
        );
        assert_eq!(resp.status(), Status::OperationBlocked);
        // The card checks the body length before the blocked state.
        let resp = applet.process(&case3(0x24, 0x00, PIN_REF_APPLICATION, 15));
        assert_eq!(resp.status(), Status::IncorrectDataParameter);
    }

    #[test]
    fn change_reference_rejects_bad_p1_p2() {
        let mut applet = PivApplet::new();
        let resp = applet.process(&case3(0x24, 0x01, PIN_REF_APPLICATION, 16));
        assert_eq!(resp.status(), Status::IncorrectP1OrP2Parameter);
        let resp = applet.process(&case3(0x24, 0x00, 0x82, 16));
        assert_eq!(resp.status(), Status::KeyReferenceNotFound);
    }

    #[test]
    fn change_reference_lc_overrun_is_wrong_length() {
        let mut applet = PivApplet::new();
        let mut apdu = vec![0x00, 0x24, 0x00, 0x80, 0x11];
        apdu.extend_from_slice(&[0x31u8; 10]);
        let resp = applet.process(&apdu);
        assert_eq!(resp.status(), iso7816::Status::WrongLength);
    }

    #[test]
    fn unblock_pin_unblocks_and_sets_the_new_pin() {
        let mut applet = PivApplet::new();
        block_pin(&mut applet);
        let resp = applet.process(&keyroost_piv::unblock_pin(b"12345678", b"999999").unwrap());
        assert_eq!(resp.status(), Status::Success);
        let resp = applet.process(&keyroost_piv::verify_pin(b"999999").unwrap());
        assert_eq!(resp.status(), Status::Success);
        let resp = applet.process(&[0x00, 0x20, 0x00, 0x80]);
        assert_eq!(resp.status(), Status::Success);
    }

    #[test]
    fn unblock_pin_wrong_puk_burns_a_puk_try() {
        let mut applet = PivApplet::new();
        let resp = applet.process(&keyroost_piv::unblock_pin(b"00000000", b"999999").unwrap());
        assert_eq!(
            resp.status(),
            iso7816::Status::RemainingRetries(DEFAULT_PUK_TRIES - 1)
        );
        let resp = applet.process(&keyroost_piv::unblock_pin(b"12345678", b"999999").unwrap());
        assert_eq!(resp.status(), Status::Success);
    }

    #[test]
    fn unblock_pin_puk_blocks_after_three_tries() {
        let mut applet = PivApplet::new();
        for tries in (1..=DEFAULT_PUK_TRIES).rev() {
            let resp = applet.process(&keyroost_piv::unblock_pin(b"00000000", b"999999").unwrap());
            assert_eq!(resp.status(), iso7816::Status::RemainingRetries(tries - 1));
        }
        let resp = applet.process(&keyroost_piv::unblock_pin(b"12345678", b"999999").unwrap());
        assert_eq!(resp.status(), Status::OperationBlocked);
    }

    #[test]
    fn unblock_pin_invalid_new_pin_is_wrong_data() {
        let mut applet = PivApplet::new();
        block_pin(&mut applet);
        let resp = applet.process(&keyroost_piv::unblock_pin(b"12345678", b"99999a").unwrap());
        assert_eq!(resp.status(), Status::IncorrectDataParameter);
        // The PIN is still blocked; nothing was set.
        let resp = applet.process(&keyroost_piv::verify_pin(b"99999a").unwrap());
        assert_eq!(resp.status(), Status::OperationBlocked);
    }

    #[test]
    fn unblock_pin_resets_the_puk_counter() {
        let mut applet = PivApplet::new();
        let resp = applet.process(&keyroost_piv::unblock_pin(b"00000000", b"999999").unwrap());
        assert_eq!(
            resp.status(),
            iso7816::Status::RemainingRetries(DEFAULT_PUK_TRIES - 1)
        );
        let resp = applet.process(&keyroost_piv::unblock_pin(b"12345678", b"999999").unwrap());
        assert_eq!(resp.status(), Status::Success);
        // The counter was reset to its limit: one wrong PUK answers `63C2`,
        // not `63C0`.
        let resp = applet.process(&keyroost_piv::unblock_pin(b"00000000", b"111111").unwrap());
        assert_eq!(
            resp.status(),
            iso7816::Status::RemainingRetries(DEFAULT_PUK_TRIES - 1)
        );
    }

    #[test]
    fn unblock_pin_rejects_bad_p1_p2_and_length() {
        let mut applet = PivApplet::new();
        let resp = applet.process(&case3(0x2C, 0x01, PIN_REF_APPLICATION, 16));
        assert_eq!(resp.status(), Status::IncorrectP1OrP2Parameter);
        let resp = applet.process(&case3(0x2C, 0x00, PIN_REF_PUK, 16));
        assert_eq!(resp.status(), Status::KeyReferenceNotFound);
        let resp = applet.process(&case3(0x2C, 0x00, PIN_REF_APPLICATION, 15));
        assert_eq!(resp.status(), Status::IncorrectDataParameter);
    }

    #[test]
    fn pin_and_puk_counters_are_independent() {
        let mut applet = PivApplet::new();
        let resp = applet.process(&keyroost_piv::verify_pin(b"000000").unwrap());
        assert_eq!(
            resp.status(),
            iso7816::Status::RemainingRetries(DEFAULT_PIN_TRIES - 1)
        );
        let resp = applet.process(&keyroost_piv::verify_pin(b"000000").unwrap());
        assert_eq!(
            resp.status(),
            iso7816::Status::RemainingRetries(DEFAULT_PIN_TRIES - 2)
        );
        let resp = applet.process(&keyroost_piv::unblock_pin(b"00000000", b"999999").unwrap());
        assert_eq!(
            resp.status(),
            iso7816::Status::RemainingRetries(DEFAULT_PUK_TRIES - 1)
        );
        let resp = applet.process(&keyroost_piv::verify_pin(b"123456").unwrap());
        assert_eq!(resp.status(), Status::Success);
        let resp = applet.process(&keyroost_piv::unblock_pin(b"00000000", b"111111").unwrap());
        assert_eq!(
            resp.status(),
            iso7816::Status::RemainingRetries(DEFAULT_PUK_TRIES - 2)
        );
        let resp = applet.process(&keyroost_piv::unblock_pin(b"00000000", b"111111").unwrap());
        assert_eq!(resp.status(), iso7816::Status::RemainingRetries(0));
        let resp = applet.process(&keyroost_piv::unblock_pin(b"00000000", b"111111").unwrap());
        assert_eq!(resp.status(), Status::OperationBlocked);
    }

    #[test]
    fn pin_commands_reject_cla_bits() {
        let mut applet = PivApplet::new();
        for (cla, ins) in [(0x80u8, 0x20u8), (0x80u8, 0x24u8), (0x80u8, 0x2Cu8)] {
            let apdu = [cla, ins, 0x00, 0x80];
            let resp = applet.process(&apdu);
            assert_eq!(resp.status(), iso7816::Status::ClaNotSupported);
        }
    }
}
