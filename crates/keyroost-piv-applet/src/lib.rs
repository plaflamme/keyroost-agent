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

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use keyroost_piv::{Instruction, KEY_REF_MANAGEMENT, MgmtAlg, PIN_REF_APPLICATION, PIN_REF_PUK};
use zeroize::{Zeroize, Zeroizing};

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
/// ISO 7816-4 status word: security status not satisfied — the JavaCard
/// `ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED` word the card answers when a
/// management command's preconditions are not met.
const SW_SECURITY_STATUS_NOT_SATISFIED: u16 = 0x6986;
/// ISO 7816-4 status word: success — the card's `9000`.
const SW_OK: u16 = 0x9000;
/// ISO 7816-4 status word: wrong length — `Lc` overrunning the APDU.
const SW_WRONG_LENGTH: u16 = 0x6700;
/// ISO 7816-4 status word: invalid data — a structurally broken TLV
/// template (truncated lengths, an underrun body). Same value as
/// [`SW_INCORRECT_P1P2`]; the name marks which check produced it.
const SW_DATA_INVALID: u16 = 0x6B00;

/// SP 800-73-4 §4.1.3 dynamic-authentication tags: the `7C` wrapper and its
/// witness / challenge / response / exponent members.
const GA_TAG_DYN_AUTH: u8 = 0x7C;
const GA_TAG_WITNESS: u8 = 0x80;
const GA_TAG_CHALLENGE: u8 = 0x81;
const GA_TAG_RESPONSE: u8 = 0x82;
const GA_TAG_EXP: u8 = 0x85;

/// Largest GA challenge value this applet will encrypt — the reference's
/// 64-byte scratch buffer caps the template it will accept at all.
const GA_MAX_CHALLENGE: usize = 64;

/// The 9B management key a factory-fresh applet answers to: 3DES with the
/// Yubico default key (three `01 02 03 04 05 06 07 08` halves).
const DEFAULT_MGMT_KEY: [u8; 24] = [
    1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
];

/// SELECT P1: select by DF name (the AID). Anything else on a PIV card is
/// a file select this applet has no answer for.
const INS_SELECT_P1_BY_AID: u8 = 0x04;

/// The default serial a factory-fresh applet presents: a placeholder until
/// the virtual card has a real source of serial identity.
pub const DEFAULT_SERIAL: u32 = 0x0102_0304;

/// The applet version GET VERSION presents: `major.minor.patch`, tracking
/// the Yubico PIV firmware line the behaviour is being reimplemented from.
pub const VERSION: [u8; 3] = [0x05, 0x07, 0x04];

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
    /// The 9B management key as stored: the cipher algorithm plus the key
    /// material, zero-padded into the fixed 32-byte array. Factory state is
    /// 3DES with the Yubico default key.
    mgmt_alg: MgmtAlg,
    mgmt_key: Zeroizing<[u8; 32]>,
    /// The last witness/challenge issued for a 9B symmetric GA, plus whether
    /// it is still valid — a new issuance invalidates the old one, the
    /// card's single-challenge-transient model.
    mgmt_challenge: [u8; 16],
    mgmt_challenge_valid: bool,
    /// The 9B slot's GA security status: set by a successful witness or
    /// response verification, retained until the session ends, and never
    /// cleared by RESET (the reference keeps `F_UNLOCKED` through it too).
    mgmt_unlocked: bool,
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

    /// GENERAL AUTHENTICATE (0x87): the SP 800-73-4 dynamic-authentication
    /// exchange — the 9B management-key mutual auth this applet implements.
    ///
    /// The body is the dynamic-auth template `7C [80 witness] [81
    /// challenge] [82 response] [85 exponent]`, where an *empty* member
    /// names what the host wants (at most one) and a *non-empty* member
    /// carries data. Mirrors the card's `processGeneralAuth` /
    /// `processGenAuthSym` for P2=`9B`:
    ///
    /// - `6B00` when P1 is not the stored management algorithm, when P2 is
    ///   not a slot reference the applet knows, or — with an asymmetric P1
    ///   (`06`/`07`/`11`/`14`) — when the template has the signing shape
    ///   (a challenge offered for a response) and the slot has no key.
    /// - A non-empty witness (`80`) must be the current challenge encrypted
    ///   with the management key (a re-issued witness invalidates the
    ///   pending one); a non-empty response (`82`) must decrypt to it. A
    ///   correct verification sets the slot's unlocked status. A wrong
    ///   value — or the challenge no longer valid — is `6A86`.
    /// - Wanted `80` (witness): the applet issues a fresh challenge and
    ///   answers `7C 80 <n> <encrypted challenge>`. Wanted `81`:
    ///   `7C 81 <n> <challenge>` in the clear. Wanted `82` (response): the
    ///   body's challenge is encrypted and answered `7C 82 <n> <encrypted>`
    ///   — `6A86` without a challenge, `6986` while the slot is still
    ///   locked. A no-empty-tag body with a challenge (the yubico-piv-tool
    ///   shape) wants a response; a fully empty body answers `9000` with no
    ///   data.
    ///
    /// P2=`9A`/`9C`/`9D` (and the `82`–`8C` history slots) need the PIN
    /// verified in this session — `6986` until it is — then answer `6B00`
    /// (the applet holds no key material for them yet). Every other P2 —
    /// `9E`, `9F`, `58`–`5A`, … — answers `6B00` outright.
    ///
    /// The per-slot signing / key agreement half (the `58`–`82`/`9E`/`9F`
    /// slots' RSA and ECDSA operations) lands with the key slots.
    fn process_general_authenticate(&mut self, apdu: &[u8]) -> Response {
        let [cla, _, p1, p2, ..] = apdu else {
            // `process` guarantees the 4-byte header.
            unreachable!("process guarantees the 4-byte header");
        };
        if cla & 0x90 != 0 {
            return Response::sw(SW_CLA_NOT_SUPPORTED);
        }
        match *p2 {
            KEY_REF_MANAGEMENT => self.ga_management(*p1, apdu_lc_body(apdu)),
            0x9A | 0x9C | 0x9D => self.ga_gated_slot(),
            0x82..=0x8C => self.ga_gated_slot(),
            _ => Response::sw(SW_INCORRECT_P1P2),
        }
    }

    /// The PIN-gated slot references (`9A`/`9C`/`9D`, history `82`–`8C`):
    /// `6986` until the PIN is verified in this session, `6B00` after (the
    /// applet holds no key material for them yet).
    fn ga_gated_slot(&self) -> Response {
        if self.pin.verified {
            Response::sw(SW_INCORRECT_P1P2)
        } else {
            Response::sw(SW_SECURITY_STATUS_NOT_SATISFIED)
        }
    }

    /// The 9B (management-key) half of GENERAL AUTHENTICATE: P1 selects the
    /// symmetric or an asymmetric algorithm, the body carries the
    /// dynamic-auth template.
    fn ga_management(&mut self, p1: u8, lc_body: Result<(u8, &[u8]), ()>) -> Response {
        let (_lc, body) = match lc_body {
            Ok(pair) => pair,
            Err(()) => return Response::sw(SW_WRONG_LENGTH),
        };
        let tmpl = match parse_ga_template(body) {
            Ok(t) => t,
            Err(sw) => return Response::sw(sw),
        };
        match MgmtAlg::from_id(p1) {
            Some(alg) => self.ga_sym(alg, tmpl),
            // Asymmetric (or unknown) algorithm: the reference allows only
            // the signing shape, then fails on the missing key.
            None => {
                if tmpl.is_sign_shape() {
                    Response::sw(SW_INCORRECT_P1P2)
                } else {
                    Response::sw(SW_WRONG_DATA)
                }
            }
        }
    }

    /// The symmetric 9B dynamic-auth exchange (the card's
    /// `processGenAuthSym`), once the template is parsed.
    fn ga_sym(&mut self, alg: MgmtAlg, t: GaTemplate) -> Response {
        if self.mgmt_alg != alg {
            return Response::sw(SW_INCORRECT_P1P2);
        }
        let bs = alg.block_size();
        // The reference's special case: a body with a challenge and no
        // empty tag wants a response.
        let mut wanted = t.wanted;
        if wanted.is_none() && t.has_challenge {
            wanted = Some(GA_TAG_RESPONSE);
        }

        // Witness/response verification — the card's `comp` pass. The
        // witness (0x80) is the challenge in the clear: the host only
        // knows it because it decrypted the card's ciphertext with the
        // management key. The proof value (the 0x81 challenge, or a 0x82
        // value) is checked the way the card checks it — decrypted and
        // compared — and only when the witness did not already consume
        // the challenge, which is also why a host that presents both
        // gets its 0x81 taken raw, never decrypted.
        if t.witness.is_some() || t.challenge.is_some() || t.response.is_some() {
            let mut comp = false;
            if let Some(w) = t.witness {
                if w.len() != bs || !self.mgmt_challenge_valid {
                    return Response::sw(SW_WRONG_DATA);
                }
                comp = w == &self.mgmt_challenge[..bs];
                // The witness consumes the challenge — a proof value in the
                // same body is never checked, so the host's raw 0x81
                // challenge passes through to the 0x82 response undecrypted.
                self.mgmt_challenge_valid = false;
            }
            // The proof value (the 0x81 challenge, or a 0x82 value) is
            // checked the way the card checks it — decrypted and compared —
            // and only when a witness did not just consume the challenge.
            let proof = t
                .challenge
                .or(t.response)
                .filter(|_| self.mgmt_challenge_valid);
            if let Some(p) = proof {
                if p.len() != bs {
                    return Response::sw(SW_WRONG_DATA);
                }
                let dec = self.mgmt_decrypt(p);
                comp = dec == self.mgmt_challenge[..bs];
                self.mgmt_challenge_valid = false;
            }
            if comp {
                self.mgmt_unlocked = true;
            } else {
                return Response::sw(SW_WRONG_DATA);
            }
            if wanted.is_none() {
                return Response::ok(Vec::new());
            }
        }

        match wanted {
            Some(GA_TAG_WITNESS) => {
                self.mgmt_issue_challenge();
                let enc = self.mgmt_encrypt(&self.mgmt_challenge[..bs]);
                Response::ok(ga_response(GA_TAG_WITNESS, &enc))
            }
            Some(GA_TAG_CHALLENGE) => {
                self.mgmt_issue_challenge();
                Response::ok(ga_response(GA_TAG_CHALLENGE, &self.mgmt_challenge[..bs]))
            }
            Some(GA_TAG_RESPONSE) => {
                if !t.has_challenge {
                    return Response::sw(SW_WRONG_DATA);
                }
                if !self.mgmt_unlocked {
                    return Response::sw(SW_SECURITY_STATUS_NOT_SATISFIED);
                }
                let Some(host_chal) = t.challenge else {
                    return Response::sw(SW_WRONG_DATA);
                };
                if host_chal.is_empty()
                    || host_chal.len() > GA_MAX_CHALLENGE
                    || host_chal.len() % bs != 0
                {
                    return Response::sw(SW_WRONG_DATA);
                }
                let enc = self.mgmt_encrypt(host_chal);
                Response::ok(ga_response(GA_TAG_RESPONSE, &enc))
            }
            _ => Response::sw(SW_WRONG_DATA),
        }
    }

    /// Replace the stored 9B management key: the algorithm and the key
    /// material, zero-padded into the 32-byte array. The old material is
    /// zeroed before the copy.
    fn set_management_key(&mut self, alg: MgmtAlg, key: &[u8]) {
        let len = alg.key_len();
        self.mgmt_alg = alg;
        self.mgmt_key.zeroize();
        self.mgmt_key[..len].copy_from_slice(key);
    }

    /// Issue a fresh witness/challenge value of the current algorithm's
    /// block size: random bytes stored as the pending GA challenge, the
    /// previous one (if any) invalidated.
    fn mgmt_issue_challenge(&mut self) {
        let bs = self.mgmt_alg.block_size();
        let mut buf = [0u8; 16];
        getrandom::getrandom(&mut buf).expect("OsRng failure");
        self.mgmt_challenge[..bs].copy_from_slice(&buf[..bs]);
        self.mgmt_challenge_valid = true;
    }

    /// Encrypt `data` (a whole number of cipher blocks) with the stored
    /// management key — one-shot ECB blocks. The card's `Cipher` is
    /// initialized with a zero-initialized transient IV, which is
    /// byte-identical to ECB for the block-by-block use GA makes of it.
    fn mgmt_encrypt(&self, data: &[u8]) -> Vec<u8> {
        let key = &self.mgmt_key[..self.mgmt_alg.key_len()];
        match self.mgmt_alg {
            MgmtAlg::TripleDes => {
                let c = des::TdesEde3::new_from_slice(key).expect("24-byte key");
                Self::run_blocks(&c, data, 8, false)
            }
            MgmtAlg::Aes128 => {
                let c = aes::Aes128::new_from_slice(key).expect("16-byte key");
                Self::run_blocks(&c, data, 16, false)
            }
            MgmtAlg::Aes192 => {
                let c = aes::Aes192::new_from_slice(key).expect("24-byte key");
                Self::run_blocks(&c, data, 16, false)
            }
            MgmtAlg::Aes256 => {
                let c = aes::Aes256::new_from_slice(key).expect("32-byte key");
                Self::run_blocks(&c, data, 16, false)
            }
        }
    }

    /// Decrypt `data` (a whole number of cipher blocks) with the stored
    /// management key — the [`PivApplet::mgmt_encrypt`] inverse.
    fn mgmt_decrypt(&self, data: &[u8]) -> Vec<u8> {
        let key = &self.mgmt_key[..self.mgmt_alg.key_len()];
        match self.mgmt_alg {
            MgmtAlg::TripleDes => {
                let c = des::TdesEde3::new_from_slice(key).expect("24-byte key");
                Self::run_blocks(&c, data, 8, true)
            }
            MgmtAlg::Aes128 => {
                let c = aes::Aes128::new_from_slice(key).expect("16-byte key");
                Self::run_blocks(&c, data, 16, true)
            }
            MgmtAlg::Aes192 => {
                let c = aes::Aes192::new_from_slice(key).expect("24-byte key");
                Self::run_blocks(&c, data, 16, true)
            }
            MgmtAlg::Aes256 => {
                let c = aes::Aes256::new_from_slice(key).expect("32-byte key");
                Self::run_blocks(&c, data, 16, true)
            }
        }
    }

    /// Block-by-block encrypt/decrypt, the card's `Cipher` use in one pass.
    fn run_blocks<C: BlockEncrypt + BlockDecrypt>(
        c: &C,
        data: &[u8],
        bs: usize,
        decrypt: bool,
    ) -> Vec<u8> {
        use cipher::generic_array::GenericArray;
        let mut out = Vec::with_capacity(data.len());
        for chunk in data.chunks(bs) {
            let mut block = GenericArray::clone_from_slice(chunk);
            if decrypt {
                c.decrypt_block(&mut block);
            } else {
                c.encrypt_block(&mut block);
            }
            out.extend_from_slice(&block);
        }
        out
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
/// One parsed SP 800-73-4 dynamic-auth template: the empty member the host
/// wants (if any), and the values of the non-empty members — the first of
/// each, as the card's rescan would find them.
struct GaTemplate<'a> {
    /// The single empty tag (`80`/`81`/`82`), if the host named one.
    wanted: Option<u8>,
    /// The first non-empty witness (`80`), if any.
    witness: Option<&'a [u8]>,
    /// The first non-empty challenge (`81`), if any.
    challenge: Option<&'a [u8]>,
    /// The first non-empty response (`82`), if any.
    response: Option<&'a [u8]>,
    /// Whether a non-empty challenge or exponent was present.
    has_challenge: bool,
}

impl<'a> GaTemplate<'a> {
    /// The reference's asymmetric-only shape: a challenge offered for a
    /// response, nothing else.
    fn is_sign_shape(&self) -> bool {
        self.has_challenge
            && self.witness.is_none()
            && self.response.is_none()
            && self.wanted == Some(GA_TAG_RESPONSE)
    }
}

/// Build the card's GA answer: the `7C` wrapper around one tagged value.
fn ga_response(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut data = vec![
        GA_TAG_DYN_AUTH,
        value.len() as u8 + 2,
        tag,
        value.len() as u8,
    ];
    data.extend_from_slice(value);
    data
}

/// Parse the GA body as the card's dispatcher does: the `7C` wrapper (with
/// its own 1-, 2- or 3-byte length) followed by a scan of the members — the
/// scan runs to the end of the APDU body, not just the declared `7C`
/// length. `6B00` on a structurally broken template (truncated lengths,
/// underrun), `6A86` on a protocol violation (two empty tags, an unknown or
/// non-80/81/82 empty tag).
fn parse_ga_template<'a>(body: &'a [u8]) -> Result<GaTemplate<'a>, u16> {
    let Some((&outer, rest)) = body.split_first() else {
        return Err(SW_WRONG_DATA);
    };
    if outer != GA_TAG_DYN_AUTH {
        return Err(SW_WRONG_DATA);
    }
    let (declared, after_header) = read_tlv_length(rest)?;
    if rest.len() < after_header + declared {
        return Err(SW_DATA_INVALID);
    }
    let mut t = GaTemplate {
        wanted: None,
        witness: None,
        challenge: None,
        response: None,
        has_challenge: false,
    };
    // The scan region: everything after the 7C header — the reference's
    // stream ends at the APDU body's end, whatever the 7C length said.
    let mut rest = &body[1 + after_header..];
    while let Some((&tag, r1)) = rest.split_first() {
        // `r1` is everything after the tag byte: the length header plus the
        // value. The member consumes `thdr + tlen` of it.
        let (tlen, thdr) = read_tlv_length(r1)?;
        let value_end = thdr + tlen;
        if r1.len() < value_end {
            return Err(SW_DATA_INVALID);
        }
        let value = &r1[thdr..value_end];
        if tlen == 0 {
            if t.wanted.is_some() {
                return Err(SW_WRONG_DATA);
            }
            match tag {
                GA_TAG_WITNESS | GA_TAG_CHALLENGE | GA_TAG_RESPONSE => {
                    t.wanted = Some(tag);
                }
                _ => return Err(SW_WRONG_DATA),
            }
        } else {
            match tag {
                GA_TAG_WITNESS => {
                    if t.witness.is_none() {
                        t.witness = Some(value);
                    }
                }
                GA_TAG_RESPONSE => {
                    if t.response.is_none() {
                        t.response = Some(value);
                    }
                }
                GA_TAG_CHALLENGE => {
                    t.has_challenge = true;
                    if t.challenge.is_none() {
                        t.challenge = Some(value);
                    }
                }
                GA_TAG_EXP => t.has_challenge = true,
                _ => return Err(SW_WRONG_DATA),
            }
        }
        rest = &r1[value_end..];
    }
    Ok(t)
}

/// Read a PIV TLV length (short form, or `81`/`82` long form) and return
/// (value, header bytes consumed). `6B00` on truncation or an invalid
/// length byte (`80`, `83`+).
fn read_tlv_length(buf: &[u8]) -> Result<(usize, usize), u16> {
    match buf.first().copied() {
        Some(n) if n <= 0x7F => Ok((usize::from(n), 1)),
        Some(0x81) => {
            let b = *buf.get(1).ok_or(SW_DATA_INVALID)?;
            Ok((usize::from(b), 2))
        }
        Some(0x82) => {
            let b = buf.get(2..4).ok_or(SW_DATA_INVALID)?;
            let v = (usize::from(b[0])) << 8 | usize::from(b[1]);
            Ok((v, 3))
        }
        _ => Err(SW_DATA_INVALID),
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
        apdu.extend_from_slice(&[0x31u8; 10]);
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

    // GENERAL AUTHENTICATE (management key) and the management commands.
    // The card's processGeneralAuth for P2 = 9B and its three companions.

    /// The GA dynamic-auth body: `7C` wrapping the given tagged members.
    fn ga_body(members: &[&[u8]]) -> Vec<u8> {
        let mut inner = Vec::new();
        for m in members {
            inner.extend_from_slice(m);
        }
        let mut body = vec![0x7C, inner.len() as u8];
        body.extend_from_slice(&inner);
        body
    }

    /// A GA APDU: `00 87 p1 9B Lc body`.
    fn ga_apdu(p1: u8, body: &[u8]) -> Vec<u8> {
        let mut apdu = vec![0x00, 0x87, p1, KEY_REF_MANAGEMENT, body.len() as u8];
        apdu.extend_from_slice(body);
        apdu
    }

    /// A full 9B management-key handshake against a fresh applet using the
    /// factory 3DES key: a witness round, then a response round proving the
    /// witness — afterwards the session is unlocked.
    /// The host's management-key handshake (keyroost-transport's
    /// `authenticate_management`), factory 3DES: the witness round, then
    /// the decrypted witness plus a fresh host challenge — the exact APDUs
    /// `general_auth_request_witness` and `general_auth_mutual` build.
    /// Returns the card's step-2 `7C` data and the host challenge the
    /// caller can check the card encrypted.
    fn mgmt_handshake(applet: &mut PivApplet) -> (Vec<u8>, [u8; 8]) {
        // Step 1 (general_auth_request_witness): 7C 02 80 00.
        let r = applet.process(&ga_apdu(0x03, &ga_body(&[&[0x80, 0x00]])));
        assert_eq!(r.sw, SW_OK, "witness round: {r:?}");
        assert_eq!(r.data[0], 0x7C);
        // The 7C wraps tag + length + 8-byte value: 2 + 8.
        assert_eq!(r.data[1], 10);
        assert_eq!(r.data[2], 0x80);
        assert_eq!(r.data[3], 8);
        // The host decrypts the witness with the management key — the
        // clear challenge is the key proof.
        let witness = des_decrypt(&r.data[4..12]);
        // Step 2 (general_auth_mutual): the clear witness plus a fresh
        // host challenge; the card answers 7C .. 82 .. <enc(challenge)>.
        let challenge: [u8; 8] = [0x42; 8];
        let mut members = vec![0x80, 0x08];
        members.extend_from_slice(&witness);
        members.extend_from_slice(&[0x81, 0x08]);
        members.extend_from_slice(&challenge);
        let r = applet.process(&ga_apdu(0x03, &ga_body(&[&members])));
        assert_eq!(r.sw, SW_OK, "mutual round: {r:?}");
        assert_eq!(r.data[0], 0x7C);
        assert_eq!(r.data[2], 0x82);
        assert_eq!(r.data[3], 8);
        (r.data, challenge)
    }

    /// Decrypt an 8-byte block with the stored 3DES management key.
    fn des_decrypt(data: &[u8]) -> [u8; 8] {
        let c = des::TdesEde3::new_from_slice(&DEFAULT_MGMT_KEY).unwrap();
        let mut block = cipher::generic_array::GenericArray::clone_from_slice(data);
        c.decrypt_block(&mut block);
        block.into()
    }

    /// Burn every PUK retry with wrong PUKs, asserting each `63Cx` along
    /// the way; afterwards the PUK is blocked.
    fn block_puk(applet: &mut PivApplet) {
        for tries in (1..=DEFAULT_PUK_TRIES).rev() {
            let resp = applet.process(&keyroost_piv::unblock_pin(b"00000000", b"123456").unwrap());
            assert_eq!(resp.sw, tries_sw(tries - 1));
        }
    }

    #[test]
    fn ga_witness_round_answers_an_encrypted_challenge() {
        let mut applet = PivApplet::new();
        let r1 = applet.process(&ga_apdu(0x03, &ga_body(&[&[0x80, 0x00]])));
        assert_eq!(r1.sw, SW_OK);
        assert_eq!(r1.data.len(), 12);
        let r2 = applet.process(&ga_apdu(0x03, &ga_body(&[&[0x80, 0x00]])));
        assert_eq!(r2.sw, SW_OK);
        // A fresh challenge every time — the witnesses differ.
        assert_ne!(&r1.data[4..12], &r2.data[4..12]);
    }

    #[test]
    fn ga_challenge_round_answers_the_clear_challenge() {
        let mut applet = PivApplet::new();
        let r = applet.process(&ga_apdu(0x03, &ga_body(&[&[0x81, 0x00]])));
        assert_eq!(r.sw, SW_OK);
        assert_eq!(r.data[0], 0x7C);
        assert_eq!(r.data[2], 0x81);
        assert_eq!(r.data.len(), 12);
    }

    #[test]
    fn ga_full_handshake_unlocks_and_responds() {
        let mut applet = PivApplet::new();
        let (data, challenge) = mgmt_handshake(&mut applet);
        // Mutual auth: the 0x82 response decrypts to the host challenge.
        assert_eq!(des_decrypt(&data[4..12]), challenge);
    }

    #[test]
    fn ga_response_proof_without_a_witness_unlocks() {
        let mut applet = PivApplet::new();
        let r1 = applet.process(&ga_apdu(0x03, &ga_body(&[&[0x80, 0x00]])));
        assert_eq!(r1.sw, SW_OK);
        // No witness: the proof is the card's challenge re-encrypted, offered
        // under 0x82 — the card decrypts and compares it to the challenge.
        let mut body = vec![0x82, 0x08];
        body.extend_from_slice(&r1.data[4..12]);
        let r = applet.process(&ga_apdu(0x03, &ga_body(&[&body])));
        assert_eq!(r.sw, SW_OK, "decrypted proof: {r:?}");
        assert!(r.data.is_empty());
        // The session is unlocked: a management write goes through.
        let mut apdu = vec![0x00, 0xFF, 0xFF, 0xFF, 27];
        apdu.extend_from_slice(&[0x03, KEY_REF_MANAGEMENT, 0x18]);
        apdu.extend_from_slice(&[0u8; 24]);
        let r = applet.process(&apdu);
        assert_eq!(r.sw, SW_OK, "unlocked session: {r:?}");
    }

    #[test]
    fn ga_challenged_body_without_a_valid_challenge_is_wrong_data() {
        let mut applet = PivApplet::new();
        // Only a non-empty challenge, no witness round before it — the card
        // has no valid challenge to check the proof against, so the `comp`
        // pass fails before the response is considered.
        let r = applet.process(&ga_apdu(
            0x03,
            &ga_body(&[&[0x81, 0x08, 0, 1, 2, 3, 4, 5, 6, 7]]),
        ));
        assert_eq!(r.sw, SW_WRONG_DATA);
        // After a handshake the challenge is spent, so the same APDU still
        // refuses.
        mgmt_handshake(&mut applet);
        let r = applet.process(&ga_apdu(
            0x03,
            &ga_body(&[&[0x81, 0x08, 0, 1, 2, 3, 4, 5, 6, 7]]),
        ));
        assert_eq!(r.sw, SW_WRONG_DATA);
    }

    #[test]
    fn ga_wrong_witness_is_wrong_data_and_consumes_the_challenge() {
        let mut applet = PivApplet::new();
        let r1 = applet.process(&ga_apdu(0x03, &ga_body(&[&[0x80, 0x00]])));
        assert_eq!(r1.sw, SW_OK);
        // A corrupted witness — the applet's challenge is consumed.
        let mut bad = vec![0x80, 0x08];
        bad.extend_from_slice(&r1.data[4..12]);
        bad[2] ^= 1;
        let r = applet.process(&ga_apdu(0x03, &ga_body(&[&bad])));
        assert_eq!(r.sw, SW_WRONG_DATA);
        // The real witness no longer verifies — the challenge is gone.
        let mut good = vec![0x80, 0x08];
        good.extend_from_slice(&r1.data[4..12]);
        let r = applet.process(&ga_apdu(0x03, &ga_body(&[&good])));
        assert_eq!(r.sw, SW_WRONG_DATA);
    }

    #[test]
    fn ga_reissued_witness_invalidates_the_old_one() {
        let mut applet = PivApplet::new();
        let r1 = applet.process(&ga_apdu(0x03, &ga_body(&[&[0x80, 0x00]])));
        let r2 = applet.process(&ga_apdu(0x03, &ga_body(&[&[0x80, 0x00]])));
        assert_eq!(r1.sw, SW_OK);
        assert_eq!(r2.sw, SW_OK);
        // Presenting the first witness fails — the second issued it away.
        let mut body = vec![0x80, 0x08];
        body.extend_from_slice(&r1.data[4..12]);
        let r = applet.process(&ga_apdu(0x03, &ga_body(&[&body])));
        assert_eq!(r.sw, SW_WRONG_DATA);
    }

    #[test]
    fn ga_response_of_wrong_length_is_wrong_data() {
        let mut applet = PivApplet::new();
        // A witness round first, so the challenge is valid and the length
        // check — not a spent challenge — is what fires.
        let r = applet.process(&ga_apdu(0x03, &ga_body(&[&[0x80, 0x00]])));
        assert_eq!(r.sw, SW_OK);
        // A 4-byte response where the 3DES block size is 8.
        let body = ga_body(&[&[0x82, 4, 0, 1, 2, 3]]);
        let r = applet.process(&ga_apdu(0x03, &body));
        assert_eq!(r.sw, SW_WRONG_DATA);
    }

    #[test]
    fn ga_wrong_algorithm_is_incorrect_p1p2() {
        let mut applet = PivApplet::new();
        // The applet is 3DES; P1 = AES-256 is not its algorithm.
        let r = applet.process(&ga_apdu(0x0C, &ga_body(&[&[0x80, 0x00]])));
        assert_eq!(r.sw, SW_INCORRECT_P1P2);
        // And an asymmetric P1 with a signing-shaped body too.
        let mut members = vec![0x81, 0x08, 0, 1, 2, 3, 4, 5, 6, 7];
        members.extend_from_slice(&[0x82, 0x00]);
        let r = applet.process(&ga_apdu(0x14, &ga_body(&[&members])));
        assert_eq!(r.sw, SW_INCORRECT_P1P2);
    }

    #[test]
    fn ga_unknown_p2_is_incorrect_p1p2_and_pin_gated_slots_need_the_pin() {
        let mut applet = PivApplet::new();
        // 9E is not a slot reference the applet knows.
        for p2 in [0x9Eu8, 0x58u8, 0x00u8] {
            let r = applet.process(&ga_apdu_for_p2(p2));
            assert_eq!(r.sw, SW_INCORRECT_P1P2);
        }
        // 9A/9C/9D and the history slots: PIN-gated — locked first.
        for p2 in [0x9Au8, 0x9Cu8, 0x9Du8, 0x82u8, 0x8Cu8] {
            let r = applet.process(&ga_apdu_for_p2(p2));
            assert_eq!(r.sw, SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        // After the PIN is verified the applet has no key material for them.
        let r = applet.process(&keyroost_piv::verify_pin(b"123456").unwrap());
        assert_eq!(r.sw, SW_OK);
        for p2 in [0x9Au8, 0x9Cu8, 0x9Du8, 0x82u8, 0x8Cu8] {
            let r = applet.process(&ga_apdu_for_p2(p2));
            assert_eq!(r.sw, SW_INCORRECT_P1P2);
        }
    }

    /// A GA APDU for a slot reference other than 9B: `00 87 00 p2 00`.
    fn ga_apdu_for_p2(p2: u8) -> Vec<u8> {
        vec![0x00, 0x87, 0x00, p2, 0x00]
    }

    #[test]
    fn ga_broken_templates_are_wrong_length_or_wrong_data() {
        let mut applet = PivApplet::new();
        // Lc overrunning the APDU.
        let r = applet.process(&[0x00, 0x87, 0x03, KEY_REF_MANAGEMENT, 0x08, 0x7C, 0x00]);
        assert_eq!(r.sw, SW_WRONG_LENGTH);
        // No 7C wrapper at all.
        let r = applet.process(&ga_apdu(0x03, &[0x80, 0x00]));
        assert_eq!(r.sw, SW_WRONG_DATA);
        // Two empty tags.
        let r = applet.process(&ga_apdu(0x03, &ga_body(&[&[0x80, 0x00], &[0x81, 0x00]])));
        assert_eq!(r.sw, SW_WRONG_DATA);
        // An unknown empty tag.
        let r = applet.process(&ga_apdu(0x03, &ga_body(&[&[0x85, 0x00]])));
        assert_eq!(r.sw, SW_WRONG_DATA);
        // A member that overruns the body.
        let r = applet.process(&ga_apdu(0x03, &ga_body(&[&[0x81, 0x08, 0, 1, 2]])));
        assert_eq!(r.sw, SW_DATA_INVALID);
        // The 7C wrapper's length underdeclared: the scan still runs to the
        // end of the body — here to a second empty tag, a protocol error.
        let body = vec![0x7C, 0x02, 0x80, 0x00, 0x81, 0x00];
        let r = applet.process(&ga_apdu(0x03, &body));
        assert_eq!(r.sw, SW_WRONG_DATA);
    }

    #[test]
    fn ga_rejects_cla_bits() {
        let mut applet = PivApplet::new();
        let mut apdu = ga_apdu(0x03, &ga_body(&[&[0x80, 0x00]]));
        apdu[0] = 0x80;
        let r = applet.process(&apdu);
        assert_eq!(r.sw, SW_CLA_NOT_SUPPORTED);
    }

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
