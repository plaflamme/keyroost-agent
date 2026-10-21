//! Management commands (Yubico extensions): SET MANAGEMENT KEY (0xFF),
//! SET PIN RETRIES (0xFA), and RESET (0xFB) — the commands that mutate the
//! 9B management key and the PIN/PUK retry counters.

use crate::constants::{
    DEFAULT_MGMT_KEY, DEFAULT_PIN_TRIES, DEFAULT_PIN_VALUE, DEFAULT_PUK_TRIES, DEFAULT_PUK_VALUE,
    SW_CLA_NOT_SUPPORTED, SW_INCORRECT_P1P2, SW_OK, SW_SECURITY_STATUS_NOT_SATISFIED,
    SW_WRONG_DATA, SW_WRONG_LENGTH,
};
use crate::{Pin, PivApplet, Response, apdu_lc_body};
use keyroost_piv::{KEY_REF_MANAGEMENT, MgmtAlg};

impl PivApplet {
    /// SET MANAGEMENT KEY (0xFF, Yubico extension): replace the 9B
    /// management key with the body's `alg | key-ref | key-length | key` —
    /// P1P2 must be `FF FF`, and the session must be unlocked (management-
    /// authenticated via GENERAL AUTHENTICATE).
    ///
    /// Mirrors the card's `processSetMgmtKey`: `6B00` on a bad P1P2, `6986`
    /// while the 9B slot is locked, `6A86` for a body shorter than
    /// `alg|key-ref|key-length`, shorter than the declared key, a key
    /// reference that is not `9B`, an unknown algorithm, or a key length the
    /// algorithm does not take (`03`→24, `08`→16, `0A`→24, `0C`→32); on
    /// success the key is replaced (old material zeroed first) and `9000`
    /// is answered.
    pub(crate) fn process_set_management_key(&mut self, apdu: &[u8]) -> Response {
        let [cla, _, p1, p2, ..] = apdu else {
            // `process` guarantees the 4-byte header.
            unreachable!("process guarantees the 4-byte header");
        };
        if cla & 0x90 != 0 {
            return Response::sw(SW_CLA_NOT_SUPPORTED);
        }
        if *p1 != 0xFF || *p2 != 0xFF {
            return Response::sw(SW_INCORRECT_P1P2);
        }
        if !self.mgmt_unlocked {
            return Response::sw(SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        let (_lc, body) = match apdu_lc_body(apdu) {
            Ok(pair) => pair,
            Err(()) => return Response::sw(SW_WRONG_LENGTH),
        };
        if body.len() < 4 {
            return Response::sw(SW_WRONG_DATA);
        }
        let key_len = usize::from(body[2]);
        if body.len() < key_len + 3 {
            return Response::sw(SW_WRONG_DATA);
        }
        if body[1] != KEY_REF_MANAGEMENT {
            return Response::sw(SW_WRONG_DATA);
        }
        let alg = match MgmtAlg::from_id(body[0]) {
            Some(alg) if alg.key_len() == key_len => alg,
            _ => return Response::sw(SW_WRONG_DATA),
        };
        let key = &body[3..3 + key_len];
        self.set_management_key(alg, key);
        Response::sw(SW_OK)
    }

    /// SET PIN RETRIES (0xFA, Yubico extension): set the PIN and PUK retry
    /// limits to P1 and P2 — needs the unlocked session and the verified
    /// PIN.
    ///
    /// Mirrors the card's `processSetPinRetries`: on success the PIN and
    /// PUK are each replaced with a fresh counter at the requested count
    /// and the *value* reset to the factory default (`123456` / `12345678`),
    /// the verified state cleared. A count of `00` blocks the counter
    /// immediately. `6986` until the 9B slot is unlocked and the PIN is
    /// verified in this session; `6400` on a non-standard CLA.
    pub(crate) fn process_set_pin_retries(&mut self, apdu: &[u8]) -> Response {
        let [cla, _, p1, p2, ..] = apdu else {
            // `process` guarantees the 4-byte header.
            unreachable!("process guarantees the 4-byte header");
        };
        if cla & 0x90 != 0 {
            return Response::sw(SW_CLA_NOT_SUPPORTED);
        }
        if !self.mgmt_unlocked {
            return Response::sw(SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        if !self.pin.verified {
            return Response::sw(SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        self.pin = Pin::factory(DEFAULT_PIN_VALUE, *p1);
        self.puk = Pin::factory(DEFAULT_PUK_VALUE, *p2);
        Response::sw(SW_OK)
    }

    /// RESET (0xFB, Yubico extension): factory-reset the applet; allowed
    /// only when PIN and PUK are both blocked.
    ///
    /// Mirrors the card's `processReset`: on success the PIN and PUK return
    /// to the factory defaults (values and full retry counters, nothing
    /// verified), the 9B management key returns to 3DES with the Yubico
    /// default key, and `9000` is answered. The 9B slot's unlocked status
    /// is kept (the reference does not touch `F_UNLOCKED`), the serial is
    /// kept (the reference regenerates the GUID/card ID, which this applet
    /// does not model), and the pending GA challenge is left alone.
    /// `6986` until both counters are blocked; `6400` on a non-standard
    /// CLA.
    pub(crate) fn process_reset(&mut self, apdu: &[u8]) -> Response {
        let [cla, ..] = apdu else {
            // `process` guarantees the 4-byte header.
            unreachable!("process guarantees the 4-byte header");
        };
        if cla & 0x90 != 0 {
            return Response::sw(SW_CLA_NOT_SUPPORTED);
        }
        if self.pin.tries != 0 || self.puk.tries != 0 {
            // Yubico's documented answer for this precondition is 6985
            // (conditions of use not satisfied); the host only recognises
            // 6982/6983/6985 as "block the PIN and PUK first".
            return Response::sw(keyroost_piv::SW_CONDITIONS_NOT_SATISFIED);
        }
        self.set_management_key(MgmtAlg::TripleDes, &DEFAULT_MGMT_KEY);
        self.pin = Pin::factory(DEFAULT_PIN_VALUE, DEFAULT_PIN_TRIES);
        self.puk = Pin::factory(DEFAULT_PUK_VALUE, DEFAULT_PUK_TRIES);
        Response::sw(SW_OK)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::auth::tests::block_pin;
    use crate::general_auth::tests::{block_puk, ga_apdu, ga_body, mgmt_handshake};
    use crate::tries_sw;

    #[test]
    fn set_management_key_locked_is_security_status() {
        let mut applet = PivApplet::new();
        // 0C | 9B | 20 | 32-byte AES-256 key — refused while locked.
        let mut apdu = vec![0x00, 0xFF, 0xFF, 0xFF, 4];
        apdu.extend_from_slice(&[0x0C, KEY_REF_MANAGEMENT, 0x20]);
        let r = applet.process(&apdu);
        assert_eq!(r.sw, SW_SECURITY_STATUS_NOT_SATISFIED);
        // A handshake with the unchanged factory key still works.
        mgmt_handshake(&mut applet);
    }

    #[test]
    fn set_management_key_bad_p1p2_is_incorrect_p1p2() {
        let mut applet = PivApplet::new();
        mgmt_handshake(&mut applet);
        let apdu = [0x00u8, 0xFF, 0x00, 0x00, 0];
        let r = applet.process(&apdu);
        assert_eq!(r.sw, SW_INCORRECT_P1P2);
    }

    #[test]
    fn set_management_key_replaces_the_key_and_algorithm() {
        let mut applet = PivApplet::new();
        mgmt_handshake(&mut applet);
        // Install a 32-byte AES-256 key.
        let mut body = vec![0x0C, KEY_REF_MANAGEMENT, 0x20];
        body.extend(0u8..=31u8);
        let mut apdu = vec![0x00, 0xFF, 0xFF, 0xFF, body.len() as u8];
        apdu.extend_from_slice(&body);
        let r = applet.process(&apdu);
        assert_eq!(r.sw, SW_OK);
        // The old algorithm is gone.
        let r = applet.process(&ga_apdu(0x03, &ga_body(&[&[0x80, 0x00]])));
        assert_eq!(r.sw, SW_INCORRECT_P1P2);
        // The new algorithm answers a 16-byte witness.
        let r = applet.process(&ga_apdu(0x0C, &ga_body(&[&[0x80, 0x00]])));
        assert_eq!(r.sw, SW_OK);
        assert_eq!(r.data[1], 18);
        assert_eq!(r.data[3], 16);
        assert_eq!(r.data.len(), 20);
    }

    #[test]
    fn set_management_key_rejects_bad_bodies() {
        let mut applet = PivApplet::new();
        mgmt_handshake(&mut applet);
        // A key reference that is not 9B.
        let mut apdu = vec![0x00, 0xFF, 0xFF, 0xFF, 27];
        apdu.extend_from_slice(&[0x03, 0x58, 0x18]);
        apdu.extend_from_slice(&[0x00u8; 24]);
        let r = applet.process(&apdu);
        assert_eq!(r.sw, SW_WRONG_DATA);
        // A declared key length the algorithm does not take.
        let mut body = vec![0x03, KEY_REF_MANAGEMENT, 0x10];
        body.extend_from_slice(&[0x00u8; 16]);
        let mut apdu = vec![0x00, 0xFF, 0xFF, 0xFF, body.len() as u8];
        apdu.extend_from_slice(&body);
        let r = applet.process(&apdu);
        assert_eq!(r.sw, SW_WRONG_DATA);
        // A body shorter than the header: `lc < 4` in the reference.
        let r = applet.process(&[0x00, 0xFF, 0xFF, 0xFF, 0x03, 0x03, KEY_REF_MANAGEMENT, 0x18]);
        assert_eq!(r.sw, SW_WRONG_DATA);
    }

    #[test]
    fn set_pin_retries_needs_the_unlocked_session_and_verified_pin() {
        let mut applet = PivApplet::new();
        let r = applet.process(&[0x00, 0xFA, 0x08, 0x08]);
        assert_eq!(r.sw, SW_SECURITY_STATUS_NOT_SATISFIED);
        mgmt_handshake(&mut applet);
        // Unlocked but the PIN is not verified yet.
        let r = applet.process(&[0x00, 0xFA, 0x08, 0x08]);
        assert_eq!(r.sw, SW_SECURITY_STATUS_NOT_SATISFIED);
        let r = applet.process(&keyroost_piv::verify_pin(b"123456").unwrap());
        assert_eq!(r.sw, SW_OK);
        let r = applet.process(&[0x00, 0xFA, 0x01, 0x05]);
        assert_eq!(r.sw, SW_OK);
        // The counters are set and the values reset to the factory defaults:
        // one PIN try left, and a wrong PIN burns it (blocking the counter).
        let r = applet.process(&keyroost_piv::verify_pin(b"000000").unwrap());
        assert_eq!(r.sw, tries_sw(0));
        // The PUK counter too.
        for tries in (2..=5).rev() {
            let r = applet.process(&keyroost_piv::unblock_pin(b"00000000", b"12345678").unwrap());
            assert_eq!(r.sw, tries_sw(tries - 1));
        }
    }

    #[test]
    fn reset_needs_both_counters_blocked() {
        let mut applet = PivApplet::new();
        let r = applet.process(&[0x00, 0xFB, 0x00, 0x00]);
        assert_eq!(r.sw, keyroost_piv::SW_CONDITIONS_NOT_SATISFIED);
        block_pin(&mut applet);
        // PIN blocked, PUK not.
        let r = applet.process(&[0x00, 0xFB, 0x00, 0x00]);
        assert_eq!(r.sw, keyroost_piv::SW_CONDITIONS_NOT_SATISFIED);
        block_puk(&mut applet);
        let r = applet.process(&[0x00, 0xFB, 0x00, 0x00]);
        assert_eq!(r.sw, SW_OK);
        // Factory state: PIN and PUK restored, management key back to the
        // Yubico 3DES default.
        let r = applet.process(&keyroost_piv::verify_pin(b"123456").unwrap());
        assert_eq!(r.sw, SW_OK);
        mgmt_handshake(&mut applet);
    }

    #[test]
    fn reset_restores_the_factory_management_key() {
        let mut applet = PivApplet::new();
        mgmt_handshake(&mut applet);
        // Install a new AES-128 key and block the PIN and PUK.
        let mut body = vec![0x08, KEY_REF_MANAGEMENT, 0x10];
        body.extend_from_slice(&[0x42u8; 16]);
        let mut apdu = vec![0x00, 0xFF, 0xFF, 0xFF, body.len() as u8];
        apdu.extend_from_slice(&body);
        let r = applet.process(&apdu);
        assert_eq!(r.sw, SW_OK);
        block_pin(&mut applet);
        block_puk(&mut applet);
        let r = applet.process(&[0x00, 0xFB, 0x00, 0x00]);
        assert_eq!(r.sw, SW_OK);
        // The AES-128 key is gone — the factory 3DES one answers again.
        let r = applet.process(&ga_apdu(0x08, &ga_body(&[&[0x80, 0x00]])));
        assert_eq!(r.sw, SW_INCORRECT_P1P2);
        let r = applet.process(&ga_apdu(0x03, &ga_body(&[&[0x80, 0x00]])));
        assert_eq!(r.sw, SW_OK);
        assert_eq!(r.data[3], 8);
    }
}
