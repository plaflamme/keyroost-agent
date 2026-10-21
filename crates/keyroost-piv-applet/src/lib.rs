//! PIV (Personal Identity Verification — NIST SP 800-73-4 / FIPS 201)
//! card-side applet, in pure Rust.
//!
//! This is the *applet* half of the PIV protocol. [`keyroost-piv`] is the
//! host-side byte layer (intentions → APDU byte vectors, response bytes →
//! typed values); this crate is its mirror: it takes a host APDU as it
//! arrives on the wire and produces the card's response data plus the 2-byte
//! ISO 7816-4 status word. It performs **no I/O** — the card is this crate,
//! driven by whatever embeds it (a reader front-end, a test harness, or a
//! device firmware), the same way `keyroost-transport`'s `PivSession` drives
//! a real card from the host side. A ready front end ships in this crate as
//! the `piv-vsmartcard` binary: it hosts the applet on PC/SC through the
//! VSmartCard protocol, behind the `vpcd` reader driver.
//!
//! # Reference
//!
//! The behaviour being reimplemented here is the one of PivApplet, the
//! JavaCard PIV applet (YubiKey-PIV-compatible, including the Yubico
//! extension instructions) — done in pure Rust, so the crate itself needs no
//! JavaCard toolchain or JVM; an engine front-end (e.g. jCardEngine) can
//! drive [`PivApplet::process`] directly.
//!
//! # Scope
//!
//! [`PivApplet::process`] dispatches a received APDU to one handler per PIV
//! instruction. SELECT (and its `61xx` / GET RESPONSE follow-up),
//! GET SERIAL / GET VERSION, and the reference-data commands (VERIFY, CHANGE
//! REFERENCE DATA, RESET RETRY COUNTER) are implemented. So are the
//! management-key half of GENERAL AUTHENTICATE (the 9B mutual
//! witness/challenge exchange) and the management commands it gates:
//! SET MANAGEMENT KEY, SET PIN RETRIES, and RESET. The remaining handlers
//! are stubs answering `6D00` (instruction not supported) — GET DATA
//! answers `6A82` (no objects yet). The rest of the card state (key slots,
//! certificates, CHUID, admin data) and the crypto it will carry (key
//! generation, signing, ECDH) land with the command implementations.
//!
//! The application PIN, PUK, and the 9B management key — values, retry
//! counters, verified/unlocked state — live on the applet instance: fresh
//! per instance, the session model of the PIV applet on real hardware
//! (nothing survives a power-off).
//!
//! The instruction surface is the union of SP 800-73-4's PIV commands and
//! the Yubico extensions PivApplet implements — the same set
//! [`keyroost_piv::Instruction`] enumerates for the host side, plus IMPORT
//! ASYMMETRIC KEY ([`INS_IMPORT_ASYM`]), which the host byte layer does not
//! build yet.

#![forbid(unsafe_code)]

mod auth;
mod constants;
mod general_auth;
mod identity;
mod select;
mod state;

pub use constants::{AID_FULL, AID_RID, DEFAULT_SERIAL, INS_IMPORT_ASYM, VERSION};
// The remaining constants are crate-private; the glob keeps lib.rs's own
// code (the handlers still living here) working until each group moves to
// its module with an explicit import list.
use constants::*;

use keyroost_piv::{Instruction, KEY_REF_MANAGEMENT, MgmtAlg};
use state::Pin;
use zeroize::Zeroizing;

/// A card response: the data the applet returns plus the 2-byte ISO 7816-4
/// status word that always terminates the answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// Response data (empty for a status-only answer).
    pub data: Vec<u8>,
    /// The ISO 7816-4 status word (`0x9000` for success).
    pub sw: u16,
}

impl Response {
    /// A success (`0x9000`) response carrying `data`.
    #[must_use]
    pub fn ok(data: Vec<u8>) -> Self {
        Self {
            data,
            sw: keyroost_piv::SW_OK,
        }
    }

    /// A status-only response (no data).
    #[must_use]
    pub fn sw(sw: u16) -> Self {
        Self {
            data: Vec::new(),
            sw,
        }
    }
}

/// A PIV applet instance: the card side of NIST SP 800-73-4.
///
/// Owns the card's state — the application PIN and PUK with their retry
/// counters, the management (9B) key, the per-slot private key material and
/// certificates, the CHUID, the admin data, and the applet version/serial —
/// and answers host APDUs through [`PivApplet::process`].
///
/// The state implemented so far is the response tail plus the PIN and PUK
/// (values, retry counters, verified flags), fresh per instance — one
/// instance per card, one instance per connection, fresh on every
/// power-on. The rest of the card state lands with the command
/// implementations.
pub struct PivApplet {
    /// The card serial GET SERIAL presents: a 32-bit value, big-endian on
    /// the wire.
    pub(crate) serial: u32,
    /// The tail of a response the previous command signalled with `61xx`
    /// because it did not fit in the requested `Le`, pending for a GET
    /// RESPONSE (0xC0). `None` when nothing is pending.
    pub(crate) get_response_tail: Option<Vec<u8>>,
    /// The application PIN (reference `80`).
    pub(crate) pin: Pin,
    /// The PUK (reference `81`).
    pub(crate) puk: Pin,
    /// The 9B management key as stored: the cipher algorithm plus the key
    /// material, zero-padded into the fixed 32-byte array. Factory state is
    /// 3DES with the Yubico default key.
    pub(crate) mgmt_alg: MgmtAlg,
    pub(crate) mgmt_key: Zeroizing<[u8; 32]>,

    /// The last witness/challenge issued for a 9B symmetric GA, plus whether
    /// it is still valid — a new issuance invalidates the old one, the
    /// card's single-challenge-transient model.
    pub(crate) mgmt_challenge: [u8; 16],
    pub(crate) mgmt_challenge_valid: bool,
    /// The 9B slot's GA security status: set by a successful witness or
    /// response verification, retained until the session ends, and never
    /// cleared by RESET (the reference keeps `F_UNLOCKED` through it too).
    pub(crate) mgmt_unlocked: bool,
}

impl Default for PivApplet {
    fn default() -> Self {
        Self::new()
    }
}

impl PivApplet {
    /// A factory-fresh applet: the default PIN/PUK with full retry counters,
    /// nothing verified, the [`DEFAULT_SERIAL`] serial.
    #[must_use]
    pub fn new() -> Self {
        Self::with_serial(DEFAULT_SERIAL)
    }

    /// A factory-fresh applet with the given card serial, everything else as
    /// in [`PivApplet::new`].
    #[must_use]
    pub fn with_serial(serial: u32) -> Self {
        let mut mgmt_key = [0u8; 32];
        mgmt_key[..24].copy_from_slice(&DEFAULT_MGMT_KEY);
        Self {
            serial,
            get_response_tail: None,
            pin: Pin::factory(DEFAULT_PIN_VALUE, DEFAULT_PIN_TRIES),
            puk: Pin::factory(DEFAULT_PUK_VALUE, DEFAULT_PUK_TRIES),
            mgmt_alg: MgmtAlg::TripleDes,
            mgmt_key: Zeroizing::new(mgmt_key),
            mgmt_challenge: [0u8; 16],
            mgmt_challenge_valid: false,
            mgmt_unlocked: false,
        }
    }

    /// The applet's entry point: dispatch a received host APDU to its
    /// instruction handler.
    ///
    /// The whole wire APDU (`CLA INS P1 P2 [Lc data] [Le]`) is handed to the
    /// handler, which parses what it needs from it. An instruction this
    /// applet does not implement answers [`SW_INS_NOT_SUPPORTED`].
    ///
    /// # Panics
    ///
    /// Panics if `apdu` is shorter than the 4-byte ISO 7816-4 header.
    pub fn process(&mut self, apdu: &[u8]) -> Response {
        let [_, ins, _, _, ..] = apdu else {
            panic!(
                "PIV applet APDU shorter than the 4-byte header: {} byte(s)",
                apdu.len()
            );
        };
        match Instruction::from_code(*ins) {
            Some(Instruction::Select) => self.process_select(apdu),
            Some(Instruction::Verify) => self.process_verify(apdu),
            Some(Instruction::GetData) => self.process_get_data(apdu),
            Some(Instruction::GetResponse) => self.process_get_response(apdu),
            Some(Instruction::GeneralAuthenticate) => self.process_general_authenticate(apdu),
            Some(Instruction::GenerateKeyPair) => self.process_generate_key_pair(apdu),
            Some(Instruction::PutData) => self.process_put_data(apdu),
            Some(Instruction::ChangeReference) => self.process_change_reference(apdu),
            Some(Instruction::ResetRetryCounter) => self.process_reset_retry_counter(apdu),
            Some(Instruction::GetVersion) => self.process_get_version(apdu),
            Some(Instruction::GetSerial) => self.process_get_serial(apdu),
            Some(Instruction::GetMetadata) => self.process_get_metadata(apdu),
            Some(Instruction::MoveKey) => self.process_move_key(apdu),
            Some(Instruction::SetManagementKey) => self.process_set_management_key(apdu),
            Some(Instruction::SetPinRetries) => self.process_set_pin_retries(apdu),
            Some(Instruction::Reset) => self.process_reset(apdu),
            Some(Instruction::Attest) => self.process_attest(apdu),
            // Not in `Instruction`: the host byte layer has no builder for
            // it yet, so `from_code` cannot name it.
            None if *ins == INS_IMPORT_ASYM => self.process_import_key(apdu),
            _ => Response::sw(SW_INS_NOT_SUPPORTED),
        }
    }

    /// Apply a case-4 `Le` cap to a full response: send it whole under
    /// `9000` when it fits (or no length was requested), otherwise stash
    /// the overflow for GET RESPONSE and answer with the first bytes under
    /// a `61xx` status word carrying the remaining count.
    pub(crate) fn split_for_le(&mut self, full: Vec<u8>, le: Option<u8>) -> Response {
        let cap = match le {
            None => None,
            Some(0) => Some(256),
            Some(n) => Some(usize::from(n)),
        };
        match cap {
            Some(cap) if full.len() > cap => {
                self.get_response_tail = Some(full[cap..].to_vec());
                let remaining = u16::from((full.len() - cap).min(255) as u8);
                Response {
                    data: full[..cap].to_vec(),
                    sw: (u16::from(keyroost_piv::SW_MORE_DATA) << 8) | remaining,
                }
            }
            _ => Response::ok(full),
        }
    }

    /// GET DATA (0xCB, P1P2=`3FFF`): read a data object by its
    /// `5C`-wrapped tag — a slot certificate, the CHUID, an admin object —
    /// and return it wrapped in the `53` data template.
    fn process_get_data(&mut self, _apdu: &[u8]) -> Response {
        Response::sw(keyroost_piv::SW_NOT_FOUND)
    }

    /// GENERATE ASYMMETRIC KEY PAIR (0x47): create a private key on-card in
    /// a slot and return its public key in the `7F 49` template.
    fn process_generate_key_pair(&mut self, _apdu: &[u8]) -> Response {
        Response::sw(SW_INS_NOT_SUPPORTED)
    }

    /// PUT DATA (0xDB): write a data object — a slot certificate or another
    /// object — under its `5C`-wrapped tag.
    fn process_put_data(&mut self, _apdu: &[u8]) -> Response {
        Response::sw(SW_INS_NOT_SUPPORTED)
    }

    /// IMPORT ASYMMETRIC KEY (0x86, Yubico extension, [`INS_IMPORT_ASYM`]):
    /// import a full key pair into a slot.
    fn process_import_key(&mut self, _apdu: &[u8]) -> Response {
        Response::sw(SW_INS_NOT_SUPPORTED)
    }

    /// MOVE KEY (0xF6, Yubico extension): move a slot's key to another slot;
    /// `P1 = 0xFF` deletes the key instead.
    fn process_move_key(&mut self, _apdu: &[u8]) -> Response {
        Response::sw(SW_INS_NOT_SUPPORTED)
    }

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
    fn process_set_management_key(&mut self, apdu: &[u8]) -> Response {
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
    fn process_set_pin_retries(&mut self, apdu: &[u8]) -> Response {
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
    fn process_reset(&mut self, apdu: &[u8]) -> Response {
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

    /// ATTEST (0xF9, Yubico extension): self-signed attestation certificate
    /// for a slot's key, proving on-card generation.
    fn process_attest(&mut self, _apdu: &[u8]) -> Response {
        Response::sw(SW_INS_NOT_SUPPORTED)
    }
}

/// The case-4 `Le` in an APDU tail, the bytes after the command data:
/// `Ok(None)` when the APDU carries no length (case 3 — the response is
/// uncapped), `Ok(Some(le))` for the requested length byte, `Err(())` for a
/// malformed tail (two or more bytes) the caller answers with
/// [`keyroost_piv::SW_WRONG_LENGTH`].
pub(crate) fn apdu_le(tail: &[u8]) -> Result<Option<u8>, ()> {
    match tail {
        [] => Ok(None),
        [le] => Ok(Some(*le)),
        _ => Err(()),
    }
}

/// The `Lc` and body of a case-3 APDU: `Ok((lc, body))`, `Err(())` when
/// `Lc` overruns the APDU — the caller answers
/// [`keyroost_piv::SW_WRONG_LENGTH`]. A case-1/2 APDU carries no length byte
/// at all and reads as an empty body.
pub(crate) fn apdu_lc_body(apdu: &[u8]) -> Result<(u8, &[u8]), ()> {
    let lc = match apdu.get(4) {
        Some(&lc) => lc,
        None => return Ok((0, &[])),
    };
    apdu.get(5..5 + usize::from(lc))
        .map(|body| (lc, body))
        .ok_or(())
}

/// The `63Cx` status word carrying `tries` remaining in the low nibble of
/// the second byte — the form the host's `sw_tries_remaining` decodes.
pub(crate) fn tries_sw(tries: u8) -> u16 {
    0x63C0 | u16::from(tries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::tests::block_pin;
    use crate::general_auth::tests::{block_puk, ga_apdu, ga_body, mgmt_handshake};

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
