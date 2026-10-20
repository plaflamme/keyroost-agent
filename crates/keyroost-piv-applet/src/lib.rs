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
//! REFERENCE DATA, RESET RETRY COUNTER) are implemented; the remaining
//! handlers are stubs answering `6D00` (instruction not supported) — GET
//! DATA answers `6A82` (no objects yet). The rest of the card state
//! (management key, key slots, certificates, CHUID, admin data) and the
//! crypto it will carry (key generation, signing, ECDH, block ciphers for
//! management-key auth) land with the command implementations; the
//! RustCrypto dependencies they need are deliberately not in the dependency
//! tree yet.
//!
//! The application PIN and PUK — values, retry counters, verified state —
//! live on the applet instance: fresh per instance, the session model of the
//! PIV applet on real hardware (nothing survives a power-off).
//!
//! The instruction surface is the union of SP 800-73-4's PIV commands and
//! the Yubico extensions PivApplet implements — the same set
//! [`keyroost_piv::Instruction`] enumerates for the host side, plus IMPORT
//! ASYMMETRIC KEY ([`INS_IMPORT_ASYM`]), which the host byte layer does not
//! build yet.

#![forbid(unsafe_code)]

use keyroost_piv::{Instruction, PIN_REF_APPLICATION, PIN_REF_PUK};
use zeroize::Zeroizing;

/// Yubico extension: IMPORT ASYMMETRIC KEY. PivApplet implements it, but
/// `keyroost-piv` has no host-side builder for it, so the byte is local
/// rather than a variant of [`keyroost_piv::Instruction`].
pub const INS_IMPORT_ASYM: u8 = 0x86;

/// ISO 7816-4 status word: instruction not supported.
const SW_INS_NOT_SUPPORTED: u16 = 0x6D00;
/// ISO 7816-4 status word: CLA not supported.
const SW_CLA_NOT_SUPPORTED: u16 = 0x6400;
/// ISO 7816-4 status word: conditions not satisfied — the standard form
/// (a GET RESPONSE with nothing pending). Note `keyroost-piv` carries its
/// own `SW_CONDITIONS_NOT_SATISFIED` = `0x6985`; this is the `0x6900` one.
const SW_CONDITIONS_NOT_SATISFIED: u16 = 0x6900;
/// ISO 7816-4 status word: incorrect P1/P2 — the JavaCard
/// `ISO7816.SW_INCORRECT_P1P2` word the card answers for an unexpected P1.
const SW_INCORRECT_P1P2: u16 = 0x6B00;
/// ISO 7816-4 status word: wrong data — the JavaCard
/// `ISO7816.SW_WRONG_DATA` word the card answers for a wrong-length or
/// invalid reference-data body.
const SW_WRONG_DATA: u16 = 0x6A86;

/// SELECT P1: select by DF name (the AID). Anything else on a PIV card is
/// a file select this applet has no answer for.
const INS_SELECT_P1_BY_AID: u8 = 0x04;

/// The default serial a factory-fresh applet presents: a placeholder until
/// the virtual card has a real source of serial identity.
pub const DEFAULT_SERIAL: u32 = 0x0102_0304;

/// The applet version GET VERSION presents: `major.minor.patch`, tracking
/// the Yubico PIV firmware line the behaviour is being reimplemented from.
pub const VERSION: [u8; 3] = [0x04, 0x03, 0x07];

/// The AID this applet is registered under: the NIST PIV card application
/// AID, the 5-byte RID `A0 00 00 03 08` plus the PIX `00 00 10 00 01 00`.
/// The same constant `keyroost-piv`'s `select_full()` sends.
pub const AID_FULL: [u8; 11] = [
    0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
];

/// The 5-byte RID/PIX prefix of [`AID_FULL`] — the shortest SELECT AID this
/// applet accepts, and the whole of `keyroost-piv`'s `AID`.
pub const AID_RID: [u8; 5] = [0xA0, 0x00, 0x00, 0x03, 0x08];

/// TLV tag of the response wrapper the SELECT template is nested in.
const TAG_61: u8 = 0x61;
/// TLV tag of the application identifier (AID/PIX) object.
const TAG_4F: u8 = 0x4F;
/// TLV tag of the application identifier template (SP 800-73-4) carrying
/// the RID form of the AID.
const TAG_79: u8 = 0x79;

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

/// One PIV reference-data secret — the application PIN or the PUK — as the
/// card's JavaCard `OwnerPIN` objects model it: the stored 8-byte value, the
/// tries-remaining counter, and the session-verified flag.
///
/// The value and the counter live for the applet's life; `verified` lives
/// only as long as the session — set by a successful check, cleared by the
/// card's reset points (an unverify, an unblock, a fresh instance) — and is
/// what the card's security-status sync consults when the key slots land.
struct Pin {
    /// The stored value: six ASCII digits plus two 0xFF padding bytes (the
    /// eight-character PUK has no padding).
    value: Zeroizing<[u8; 8]>,
    /// The retry limit the factory (or SET PIN RETRIES) configured.
    max_tries: u8,
    /// Tries remaining; 0 means blocked.
    tries: u8,
    /// Session-verified: set by a successful check, cleared by the card's
    /// reset points.
    verified: bool,
}

impl Pin {
    /// Factory-fresh state: the stored value, the counter at its limit, not
    /// verified.
    fn factory(value: [u8; 8], max_tries: u8) -> Self {
        Self {
            value: Zeroizing::new(value),
            max_tries,
            tries: max_tries,
            verified: false,
        }
    }

    /// JavaCard `OwnerPIN.check`: compare `presented` to the stored value in
    /// constant time. A correct value sets `verified` and restores the
    /// counter to its limit; a wrong one burns a try and leaves `verified`
    /// untouched. Callers must not call this while blocked.
    fn check(&mut self, presented: &[u8]) -> bool {
        let ok = ct_eq(presented, &self.value[..]);
        if ok {
            self.verified = true;
            self.tries = self.max_tries;
        } else {
            self.tries -= 1;
        }
        ok
    }

    /// JavaCard `OwnerPIN.reset` / `resetAndUnblock`: the counter back to
    /// its limit, `verified` cleared.
    fn reset(&mut self) {
        self.tries = self.max_tries;
        self.verified = false;
    }

    /// JavaCard `OwnerPIN.update`: replace the stored value; the counter and
    /// `verified` are untouched.
    fn set_value(&mut self, value: [u8; 8]) {
        *self.value = value;
    }
}

/// The factory application PIN: "123456" 0xFF-padded to 8 bytes.
const DEFAULT_PIN_VALUE: [u8; 8] = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF];
/// The factory PUK: "12345678".
const DEFAULT_PUK_VALUE: [u8; 8] = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38];
/// The factory PIN retry limit (PivApplet's `pinRetries`).
const DEFAULT_PIN_TRIES: u8 = 5;
/// The factory PUK retry limit (PivApplet's `pukRetries`).
const DEFAULT_PUK_TRIES: u8 = 3;

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
    serial: u32,
    /// The tail of a response the previous command signalled with `61xx`
    /// because it did not fit in the requested `Le`, pending for a GET
    /// RESPONSE (0xC0). `None` when nothing is pending.
    get_response_tail: Option<Vec<u8>>,
    /// The application PIN (reference `80`).
    pin: Pin,
    /// The PUK (reference `81`).
    puk: Pin,
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
        Self {
            serial,
            get_response_tail: None,
            pin: Pin::factory(DEFAULT_PIN_VALUE, DEFAULT_PIN_TRIES),
            puk: Pin::factory(DEFAULT_PUK_VALUE, DEFAULT_PUK_TRIES),
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

    /// SELECT (0xA4, P1=`04`): activate the applet by AID.
    ///
    /// The AID is matched the way a YubiKey matches: any prefix of
    /// [`AID_FULL`] of at least [`AID_RID`] length selects the applet, so
    /// the host's 11-byte `select_full()`, its 5-byte `select()`, and
    /// OpenSC's 9-byte generic PIV AID all work. A different P1, a shorter
    /// or non-matching AID answers [`keyroost_piv::SW_NOT_FOUND`].
    ///
    /// On success the answer is the application property template a
    /// YubiKey 5 returns, byte for byte:
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
    fn process_select(&mut self, apdu: &[u8]) -> Response {
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
        let aid = match body.get(..usize::from(lc)) {
            Some(aid) => aid,
            None => return Response::sw(keyroost_piv::SW_WRONG_LENGTH),
        };
        if !(aid.len() >= AID_RID.len() && AID_FULL.starts_with(aid)) {
            return Response::sw(keyroost_piv::SW_NOT_FOUND);
        }
        let le = match apdu_le(&body[aid.len()..]) {
            Ok(le) => le,
            Err(()) => return Response::sw(keyroost_piv::SW_WRONG_LENGTH),
        };
        self.split_for_le(Self::select_response(), le)
    }

    /// The application property template a SELECT answers with — the
    /// YubiKey 5 response: a `61` wrapper holding the AID after the RID
    /// (tag `4F`) and the RID itself (tag `4F` inside the `79`
    /// application-identifier template).
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

    /// Apply a case-4 `Le` cap to a full response: send it whole under
    /// `9000` when it fits (or no length was requested), otherwise stash
    /// the overflow for GET RESPONSE and answer with the first bytes under
    /// a `61xx` status word carrying the remaining count.
    fn split_for_le(&mut self, full: Vec<u8>, le: Option<u8>) -> Response {
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
    fn process_verify(&mut self, apdu: &[u8]) -> Response {
        let [cla, _, p1, p2, ..] = apdu else {
            // `process` guarantees the 4-byte header.
            unreachable!("process guarantees the 4-byte header");
        };
        if cla & 0x90 != 0 {
            return Response::sw(SW_CLA_NOT_SUPPORTED);
        }
        if *p1 != 0x00 && *p1 != 0xFF {
            return Response::sw(SW_INCORRECT_P1P2);
        }
        let pin = if *p2 == PIN_REF_APPLICATION {
            &mut self.pin
        } else {
            return Response::sw(keyroost_piv::SW_REFERENCE_NOT_FOUND);
        };
        let (lc, body) = match apdu_lc_body(apdu) {
            Ok(pair) => pair,
            Err(()) => return Response::sw(keyroost_piv::SW_WRONG_LENGTH),
        };
        if pin.tries == 0 {
            return Response::sw(keyroost_piv::SW_AUTH_BLOCKED);
        }
        if *p1 == 0xFF {
            // "Set security status to false": a verified PIN is reset
            // (counter and flag); an unverified one is left alone.
            if pin.verified {
                pin.reset();
            }
            return Response::sw(keyroost_piv::SW_OK);
        }
        if usize::from(lc) == 0 {
            // Status query: `9000` when verified, else `63Cx`.
            return if pin.verified {
                Response::sw(keyroost_piv::SW_OK)
            } else {
                Response::sw(tries_sw(pin.tries))
            };
        }
        if usize::from(lc) != 8 {
            return Response::sw(SW_WRONG_DATA);
        }
        if pin.check(body) {
            Response::sw(keyroost_piv::SW_OK)
        } else {
            // The card would also wipe the key slots here if this try
            // blocked both PIN and PUK; this applet has no key slots yet.
            Response::sw(tries_sw(pin.tries))
        }
    }

    /// GET DATA (0xCB, P1P2=`3FFF`): read a data object by its
    /// `5C`-wrapped tag — a slot certificate, the CHUID, an admin object —
    /// and return it wrapped in the `53` data template.
    fn process_get_data(&mut self, _apdu: &[u8]) -> Response {
        Response::sw(keyroost_piv::SW_NOT_FOUND)
    }

    /// GET RESPONSE (0xC0): fetch the tail of a response the previous
    /// command signalled with `61xx` (large objects such as certificates
    /// arrive this way; while the crate is wiring only, SELECT is the only
    /// such producer). The stashed bytes come back under `9000`, re-capped
    /// by this command's own `Le` when it carries one; a GET RESPONSE with
    /// nothing pending answers [`SW_CONDITIONS_NOT_SATISFIED`].
    fn process_get_response(&mut self, apdu: &[u8]) -> Response {
        let [cla, ..] = apdu else {
            // `process` guarantees the 4-byte header; there is nothing
            // else to be malformed here.
            unreachable!("process guarantees the 4-byte header");
        };
        if cla & 0x90 != 0 {
            return Response::sw(SW_CLA_NOT_SUPPORTED);
        }
        let tail = match self.get_response_tail.take() {
            Some(tail) => tail,
            None => return Response::sw(SW_CONDITIONS_NOT_SATISFIED),
        };
        let le = match apdu_le(&apdu[4..]) {
            Ok(le) => le,
            Err(()) => return Response::sw(keyroost_piv::SW_WRONG_LENGTH),
        };
        self.split_for_le(tail, le)
    }

    /// GENERAL AUTHENTICATE (0x87): the slot engine. Management-key (9B)
    /// mutual authentication via witness/challenge, and per-slot signing /
    /// key agreement (RSA, ECDSA, ECDH) with the `7C` dynamic-authentication
    /// template.
    fn process_general_authenticate(&mut self, _apdu: &[u8]) -> Response {
        Response::sw(SW_INS_NOT_SUPPORTED)
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
    fn process_change_reference(&mut self, apdu: &[u8]) -> Response {
        let [cla, _, p1, p2, ..] = apdu else {
            unreachable!("process guarantees the 4-byte header");
        };
        if cla & 0x90 != 0 {
            return Response::sw(SW_CLA_NOT_SUPPORTED);
        }
        if *p1 != 0x00 {
            return Response::sw(SW_INCORRECT_P1P2);
        }
        let target = match *p2 {
            PIN_REF_APPLICATION => &mut self.pin,
            PIN_REF_PUK => &mut self.puk,
            _ => return Response::sw(keyroost_piv::SW_REFERENCE_NOT_FOUND),
        };
        let (_, body) = match apdu_lc_body(apdu) {
            Ok(pair) => pair,
            Err(()) => return Response::sw(keyroost_piv::SW_WRONG_LENGTH),
        };
        if body.len() != 16 {
            return Response::sw(SW_WRONG_DATA);
        }
        if target.tries == 0 {
            return Response::sw(keyroost_piv::SW_AUTH_BLOCKED);
        }
        let new_value: [u8; 8] = body[8..].try_into().unwrap();
        if !target.check(&body[..8]) {
            // The card would also wipe the key slots here if this try
            // blocked both PIN and PUK; this applet has no key slots yet.
            return Response::sw(tries_sw(target.tries));
        }
        if !is_valid_pin(&new_value) {
            return Response::sw(SW_WRONG_DATA);
        }
        target.set_value(new_value);
        Response::sw(keyroost_piv::SW_OK)
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
    fn process_reset_retry_counter(&mut self, apdu: &[u8]) -> Response {
        let [cla, _, p1, p2, ..] = apdu else {
            unreachable!("process guarantees the 4-byte header");
        };
        if cla & 0x90 != 0 {
            return Response::sw(SW_CLA_NOT_SUPPORTED);
        }
        if *p1 != 0x00 {
            return Response::sw(SW_INCORRECT_P1P2);
        }
        if *p2 != PIN_REF_APPLICATION {
            return Response::sw(keyroost_piv::SW_REFERENCE_NOT_FOUND);
        }
        let (_, body) = match apdu_lc_body(apdu) {
            Ok(pair) => pair,
            Err(()) => return Response::sw(keyroost_piv::SW_WRONG_LENGTH),
        };
        if body.len() != 16 {
            return Response::sw(SW_WRONG_DATA);
        }
        if self.puk.tries == 0 {
            return Response::sw(keyroost_piv::SW_AUTH_BLOCKED);
        }
        let new_pin: [u8; 8] = body[8..].try_into().unwrap();
        if !self.puk.check(&body[..8]) {
            // The card would also wipe the key slots here if this try
            // blocked both PIN and PUK; this applet has no key slots yet.
            return Response::sw(tries_sw(self.puk.tries));
        }
        if !is_valid_pin(&new_pin) {
            return Response::sw(SW_WRONG_DATA);
        }
        self.pin.set_value(new_pin);
        self.pin.reset();
        Response::sw(keyroost_piv::SW_OK)
    }

    /// GET VERSION (0xFD, Yubico extension): the applet version as three
    /// `major.minor.patch` bytes under `9000`.
    ///
    /// Like the other Yubico extensions this accepts both the ISO CLA and
    /// the Yubico proprietary one (`0xFF`); anything else is
    /// [`SW_CLA_NOT_SUPPORTED`]. A case-2 `Le` smaller than three re-enters
    /// the usual `61xx` / GET RESPONSE continuation.
    fn process_get_version(&mut self, apdu: &[u8]) -> Response {
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
    fn process_get_serial(&mut self, apdu: &[u8]) -> Response {
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
    fn process_get_metadata(&mut self, _apdu: &[u8]) -> Response {
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

    /// SET MANAGEMENT KEY (0xFF, Yubico extension): replace the 9B key
    /// (authenticated by the current one) and set its touch requirement.
    fn process_set_management_key(&mut self, _apdu: &[u8]) -> Response {
        Response::sw(SW_INS_NOT_SUPPORTED)
    }

    /// SET PIN RETRIES (0xFA, Yubico extension): set the PIN/PUK retry
    /// limits.
    fn process_set_pin_retries(&mut self, _apdu: &[u8]) -> Response {
        Response::sw(SW_INS_NOT_SUPPORTED)
    }

    /// RESET (0xFB, Yubico extension): factory-reset the applet; allowed
    /// only when PIN and PUK are both blocked.
    fn process_reset(&mut self, _apdu: &[u8]) -> Response {
        Response::sw(SW_INS_NOT_SUPPORTED)
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
fn apdu_le(tail: &[u8]) -> Result<Option<u8>, ()> {
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
fn apdu_lc_body(apdu: &[u8]) -> Result<(u8, &[u8]), ()> {
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
fn tries_sw(tries: u8) -> u16 {
    0x63C0 | u16::from(tries)
}

/// The card's new-PIN/PUK validation: six to eight ASCII digits — the first
/// six bytes must be digits, the last two are digits or 0xFF padding.
fn is_valid_pin(value: &[u8; 8]) -> bool {
    value[0..6].iter().all(|b| b.is_ascii_digit())
        && value[6..].iter().all(|b| *b == 0xFF || b.is_ascii_digit())
}

/// Byte-wise equality, constant time over the input — the same fold the
/// transport layer uses, so a wrong reference leaks neither which byte
/// differs nor how far the match ran.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
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

    #[test]
    fn get_version_answers_4_3_7() {
        let mut applet = PivApplet::new();
        // The host's case-2 form: `00 FD 00 00 00`.
        let resp = applet.process(&[0x00, 0xFD, 0x00, 0x00, 0x00]);
        assert_eq!(resp.data, [0x04, 0x03, 0x07]);
        assert_eq!(resp.sw, keyroost_piv::SW_OK);
    }

    #[test]
    fn get_version_case1_and_yubico_cla() {
        let mut applet = PivApplet::new();
        for apdu in [[0x00u8, 0xFD, 0x00, 0x00], [0xFF, 0xFD, 0x00, 0x00]] {
            let resp = applet.process(&apdu);
            assert_eq!(resp.data, [0x04, 0x03, 0x07]);
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
        assert_eq!(first.data, [0x04, 0x03]);
        assert_eq!(first.sw, 0x6101);
        let rest = applet.process(&[0x00, 0xC0, 0x00, 0x00, 0x00]);
        assert_eq!(rest.data, [0x07]);
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

    // The PIN/PUK tests build APDUs straight, the host byte layer's
    // builders are the host side of the same wire format.

    /// A case-3 APDU `00 INS P1 P2 Lc body` whose `body_len` body bytes are
    /// the ASCII digit `0`.
    fn case3(ins: u8, p1: u8, p2: u8, body_len: usize) -> Vec<u8> {
        let mut apdu = vec![0x00, ins, p1, p2, body_len as u8];
        apdu.extend(std::iter::repeat(0x30).take(body_len));
        apdu
    }

    /// Burn every PIN retry with wrong PINs, asserting each `63Cx` along the
    /// way; afterwards the PIN is blocked.
    fn block_pin(applet: &mut PivApplet) {
        for tries in (1..=DEFAULT_PIN_TRIES).rev() {
            let resp = applet.process(&keyroost_piv::verify_pin(b"000000").unwrap());
            assert_eq!(resp.sw, tries_sw(tries - 1));
        }
    }

    #[test]
    fn verify_factory_pin_succeeds() {
        let mut applet = PivApplet::new();
        let resp = applet.process(&keyroost_piv::verify_pin(b"123456").unwrap());
        assert_eq!(resp.sw, keyroost_piv::SW_OK);
    }

    #[test]
    fn verify_status_queries_the_retry_counter() {
        let mut applet = PivApplet::new();
        // Case-1 and case-3 `Le` = 0 both read as an empty body.
        let resp = applet.process(&[0x00, 0x20, 0x00, 0x80]);
        assert_eq!(resp.sw, tries_sw(DEFAULT_PIN_TRIES));
        let resp = applet.process(&[0x00, 0x20, 0x00, 0x80, 0x00]);
        assert_eq!(resp.sw, tries_sw(DEFAULT_PIN_TRIES));
    }

    #[test]
    fn verify_status_is_ok_after_a_verify() {
        let mut applet = PivApplet::new();
        let resp = applet.process(&keyroost_piv::verify_pin(b"123456").unwrap());
        assert_eq!(resp.sw, keyroost_piv::SW_OK);
        let resp = applet.process(&[0x00, 0x20, 0x00, 0x80]);
        assert_eq!(resp.sw, keyroost_piv::SW_OK);
    }

    #[test]
    fn verify_wrong_pin_burns_a_try() {
        let mut applet = PivApplet::new();
        let resp = applet.process(&keyroost_piv::verify_pin(b"000000").unwrap());
        assert_eq!(resp.sw, tries_sw(DEFAULT_PIN_TRIES - 1));
    }

    #[test]
    fn verify_failed_try_keeps_a_verified_session() {
        let mut applet = PivApplet::new();
        let resp = applet.process(&keyroost_piv::verify_pin(b"123456").unwrap());
        assert_eq!(resp.sw, keyroost_piv::SW_OK);
        let resp = applet.process(&keyroost_piv::verify_pin(b"000000").unwrap());
        assert_eq!(resp.sw, tries_sw(DEFAULT_PIN_TRIES - 1));
        let resp = applet.process(&[0x00, 0x20, 0x00, 0x80]);
        assert_eq!(resp.sw, keyroost_piv::SW_OK);
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
            assert_eq!(resp.sw, keyroost_piv::SW_AUTH_BLOCKED);
        }
    }

    #[test]
    fn verify_unverify_clears_a_verified_pin() {
        let mut applet = PivApplet::new();
        let resp = applet.process(&keyroost_piv::verify_pin(b"123456").unwrap());
        assert_eq!(resp.sw, keyroost_piv::SW_OK);
        let resp = applet.process(&[0x00, 0x20, 0xFF, 0x80]);
        assert_eq!(resp.sw, keyroost_piv::SW_OK);
        let resp = applet.process(&[0x00, 0x20, 0x00, 0x80]);
        assert_eq!(resp.sw, tries_sw(DEFAULT_PIN_TRIES));
    }

    #[test]
    fn verify_unverify_leaves_an_unverified_counter_alone() {
        let mut applet = PivApplet::new();
        let resp = applet.process(&keyroost_piv::verify_pin(b"000000").unwrap());
        assert_eq!(resp.sw, tries_sw(DEFAULT_PIN_TRIES - 1));
        let resp = applet.process(&keyroost_piv::verify_pin(b"000000").unwrap());
        assert_eq!(resp.sw, tries_sw(DEFAULT_PIN_TRIES - 2));
        let resp = applet.process(&[0x00, 0x20, 0xFF, 0x80]);
        assert_eq!(resp.sw, keyroost_piv::SW_OK);
        let resp = applet.process(&[0x00, 0x20, 0x00, 0x80]);
        assert_eq!(resp.sw, tries_sw(DEFAULT_PIN_TRIES - 2));
    }

    #[test]
    fn verify_rejects_the_puk_reference() {
        let mut applet = PivApplet::new();
        let resp = applet.process(&case3(0x20, 0x00, PIN_REF_PUK, 8));
        assert_eq!(resp.sw, keyroost_piv::SW_REFERENCE_NOT_FOUND);
    }

    #[test]
    fn verify_rejects_other_p1s() {
        let mut applet = PivApplet::new();
        for p1 in [0x01u8, 0x80u8] {
            let resp = applet.process(&case3(0x20, p1, PIN_REF_APPLICATION, 8));
            assert_eq!(resp.sw, SW_INCORRECT_P1P2);
        }
    }

    #[test]
    fn verify_wrong_length_body_is_wrong_data() {
        let mut applet = PivApplet::new();
        let resp = applet.process(&case3(0x20, 0x00, PIN_REF_APPLICATION, 7));
        assert_eq!(resp.sw, SW_WRONG_DATA);
    }

    #[test]
    fn verify_lc_overrun_is_wrong_length() {
        let mut applet = PivApplet::new();
        let resp = applet.process(&[0x00, 0x20, 0x00, 0x80, 0x09, 0x31, 0x32, 0x33, 0x34]);
        assert_eq!(resp.sw, keyroost_piv::SW_WRONG_LENGTH);
    }

    #[test]
    fn change_reference_changes_the_pin() {
        let mut applet = PivApplet::new();
        let resp = applet.process(
            &keyroost_piv::change_reference(PIN_REF_APPLICATION, b"123456", b"654321").unwrap(),
        );
        assert_eq!(resp.sw, keyroost_piv::SW_OK);
        let resp = applet.process(&keyroost_piv::verify_pin(b"654321").unwrap());
        assert_eq!(resp.sw, keyroost_piv::SW_OK);
    }

    #[test]
    fn change_reference_changes_the_puk() {
        let mut applet = PivApplet::new();
        let resp = applet.process(
            &keyroost_piv::change_reference(PIN_REF_PUK, b"12345678", b"87654321").unwrap(),
        );
        assert_eq!(resp.sw, keyroost_piv::SW_OK);
        let resp = applet.process(&keyroost_piv::unblock_pin(b"87654321", b"111111").unwrap());
        assert_eq!(resp.sw, keyroost_piv::SW_OK);
    }

    #[test]
    fn change_reference_wrong_old_value_burns_a_try() {
        let mut applet = PivApplet::new();
        let resp = applet.process(
            &keyroost_piv::change_reference(PIN_REF_APPLICATION, b"000000", b"654321").unwrap(),
        );
        assert_eq!(resp.sw, tries_sw(DEFAULT_PIN_TRIES - 1));
        let resp = applet.process(&keyroost_piv::verify_pin(b"123456").unwrap());
        assert_eq!(resp.sw, keyroost_piv::SW_OK);
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
        assert_change_reference_body(&mut applet, &body, SW_WRONG_DATA);
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
        assert_change_reference_body(&mut applet, &body, SW_WRONG_DATA);
        // The PIN is unchanged; nothing was burned (the old value was
        // correct and the new one was never stored).
        let resp = applet.process(&keyroost_piv::verify_pin(b"123456").unwrap());
        assert_eq!(resp.sw, keyroost_piv::SW_OK);
    }

    /// Send a CHANGE REFERENCE DATA APDU with the given 16-byte body and
    /// assert the status word.
    fn assert_change_reference_body(applet: &mut PivApplet, body: &[u8], sw: u16) {
        let mut apdu = vec![0x00, 0x24, 0x00, 0x80, body.len() as u8];
        apdu.extend_from_slice(body);
        let resp = applet.process(&apdu);
        assert_eq!(resp.sw, sw);
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
        assert_change_reference_body(&mut applet, &body, SW_WRONG_DATA);
    }

    #[test]
    fn change_reference_accepts_a_seven_digit_pin() {
        let mut applet = PivApplet::new();
        let resp = applet.process(
            &keyroost_piv::change_reference(PIN_REF_APPLICATION, b"123456", b"6543217").unwrap(),
        );
        assert_eq!(resp.sw, keyroost_piv::SW_OK);
        let resp = applet.process(&keyroost_piv::verify_pin(b"6543217").unwrap());
        assert_eq!(resp.sw, keyroost_piv::SW_OK);
    }

    #[test]
    fn change_reference_wrong_length_body_is_wrong_data() {
        let mut applet = PivApplet::new();
        let resp = applet.process(&case3(0x24, 0x00, PIN_REF_APPLICATION, 15));
        assert_eq!(resp.sw, SW_WRONG_DATA);
    }

    #[test]
    fn change_reference_blocked_reference_is_blocked() {
        let mut applet = PivApplet::new();
        block_pin(&mut applet);
        let resp = applet.process(
            &keyroost_piv::change_reference(PIN_REF_APPLICATION, b"123456", b"654321").unwrap(),
        );
        assert_eq!(resp.sw, keyroost_piv::SW_AUTH_BLOCKED);
        // The card checks the body length before the blocked state.
        let resp = applet.process(&case3(0x24, 0x00, PIN_REF_APPLICATION, 15));
        assert_eq!(resp.sw, SW_WRONG_DATA);
    }

    #[test]
    fn change_reference_rejects_bad_p1_p2() {
        let mut applet = PivApplet::new();
        let resp = applet.process(&case3(0x24, 0x01, PIN_REF_APPLICATION, 16));
        assert_eq!(resp.sw, SW_INCORRECT_P1P2);
        let resp = applet.process(&case3(0x24, 0x00, 0x82, 16));
        assert_eq!(resp.sw, keyroost_piv::SW_REFERENCE_NOT_FOUND);
    }

    #[test]
    fn change_reference_lc_overrun_is_wrong_length() {
        let mut applet = PivApplet::new();
        let mut apdu = vec![0x00, 0x24, 0x00, 0x80, 0x11];
        apdu.extend(std::iter::repeat(0x31).take(10));
        let resp = applet.process(&apdu);
        assert_eq!(resp.sw, keyroost_piv::SW_WRONG_LENGTH);
    }

    #[test]
    fn unblock_pin_unblocks_and_sets_the_new_pin() {
        let mut applet = PivApplet::new();
        block_pin(&mut applet);
        let resp = applet.process(&keyroost_piv::unblock_pin(b"12345678", b"999999").unwrap());
        assert_eq!(resp.sw, keyroost_piv::SW_OK);
        let resp = applet.process(&keyroost_piv::verify_pin(b"999999").unwrap());
        assert_eq!(resp.sw, keyroost_piv::SW_OK);
        let resp = applet.process(&[0x00, 0x20, 0x00, 0x80]);
        assert_eq!(resp.sw, keyroost_piv::SW_OK);
    }

    #[test]
    fn unblock_pin_wrong_puk_burns_a_puk_try() {
        let mut applet = PivApplet::new();
        let resp = applet.process(&keyroost_piv::unblock_pin(b"00000000", b"999999").unwrap());
        assert_eq!(resp.sw, tries_sw(DEFAULT_PUK_TRIES - 1));
        let resp = applet.process(&keyroost_piv::unblock_pin(b"12345678", b"999999").unwrap());
        assert_eq!(resp.sw, keyroost_piv::SW_OK);
    }

    #[test]
    fn unblock_pin_puk_blocks_after_three_tries() {
        let mut applet = PivApplet::new();
        for tries in (1..=DEFAULT_PUK_TRIES).rev() {
            let resp = applet.process(&keyroost_piv::unblock_pin(b"00000000", b"999999").unwrap());
            assert_eq!(resp.sw, tries_sw(tries - 1));
        }
        let resp = applet.process(&keyroost_piv::unblock_pin(b"12345678", b"999999").unwrap());
        assert_eq!(resp.sw, keyroost_piv::SW_AUTH_BLOCKED);
    }

    #[test]
    fn unblock_pin_invalid_new_pin_is_wrong_data() {
        let mut applet = PivApplet::new();
        block_pin(&mut applet);
        let resp = applet.process(&keyroost_piv::unblock_pin(b"12345678", b"99999a").unwrap());
        assert_eq!(resp.sw, SW_WRONG_DATA);
        // The PIN is still blocked; nothing was set.
        let resp = applet.process(&keyroost_piv::verify_pin(b"99999a").unwrap());
        assert_eq!(resp.sw, keyroost_piv::SW_AUTH_BLOCKED);
    }

    #[test]
    fn unblock_pin_resets_the_puk_counter() {
        let mut applet = PivApplet::new();
        let resp = applet.process(&keyroost_piv::unblock_pin(b"00000000", b"999999").unwrap());
        assert_eq!(resp.sw, tries_sw(DEFAULT_PUK_TRIES - 1));
        let resp = applet.process(&keyroost_piv::unblock_pin(b"12345678", b"999999").unwrap());
        assert_eq!(resp.sw, keyroost_piv::SW_OK);
        // The counter was reset to its limit: one wrong PUK answers `63C2`,
        // not `63C0`.
        let resp = applet.process(&keyroost_piv::unblock_pin(b"00000000", b"111111").unwrap());
        assert_eq!(resp.sw, tries_sw(DEFAULT_PUK_TRIES - 1));
    }

    #[test]
    fn unblock_pin_rejects_bad_p1_p2_and_length() {
        let mut applet = PivApplet::new();
        let resp = applet.process(&case3(0x2C, 0x01, PIN_REF_APPLICATION, 16));
        assert_eq!(resp.sw, SW_INCORRECT_P1P2);
        let resp = applet.process(&case3(0x2C, 0x00, PIN_REF_PUK, 16));
        assert_eq!(resp.sw, keyroost_piv::SW_REFERENCE_NOT_FOUND);
        let resp = applet.process(&case3(0x2C, 0x00, PIN_REF_APPLICATION, 15));
        assert_eq!(resp.sw, SW_WRONG_DATA);
    }

    #[test]
    fn pin_and_puk_counters_are_independent() {
        let mut applet = PivApplet::new();
        let resp = applet.process(&keyroost_piv::verify_pin(b"000000").unwrap());
        assert_eq!(resp.sw, tries_sw(DEFAULT_PIN_TRIES - 1));
        let resp = applet.process(&keyroost_piv::verify_pin(b"000000").unwrap());
        assert_eq!(resp.sw, tries_sw(DEFAULT_PIN_TRIES - 2));
        let resp = applet.process(&keyroost_piv::unblock_pin(b"00000000", b"999999").unwrap());
        assert_eq!(resp.sw, tries_sw(DEFAULT_PUK_TRIES - 1));
        let resp = applet.process(&keyroost_piv::verify_pin(b"123456").unwrap());
        assert_eq!(resp.sw, keyroost_piv::SW_OK);
        let resp = applet.process(&keyroost_piv::unblock_pin(b"00000000", b"111111").unwrap());
        assert_eq!(resp.sw, tries_sw(DEFAULT_PUK_TRIES - 2));
        let resp = applet.process(&keyroost_piv::unblock_pin(b"00000000", b"111111").unwrap());
        assert_eq!(resp.sw, tries_sw(0));
        let resp = applet.process(&keyroost_piv::unblock_pin(b"00000000", b"111111").unwrap());
        assert_eq!(resp.sw, keyroost_piv::SW_AUTH_BLOCKED);
    }

    #[test]
    fn pin_commands_reject_cla_bits() {
        let mut applet = PivApplet::new();
        for (cla, ins) in [(0x80u8, 0x20u8), (0x80u8, 0x24u8), (0x80u8, 0x2Cu8)] {
            let apdu = [cla, ins, 0x00, 0x80];
            let resp = applet.process(&apdu);
            assert_eq!(resp.sw, SW_CLA_NOT_SUPPORTED);
        }
    }
}
