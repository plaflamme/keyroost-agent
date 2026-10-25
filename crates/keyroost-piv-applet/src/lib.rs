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

mod attest;
mod auth;
mod constants;
mod data;
mod general_auth;
mod identity;
mod keygen;
mod management;
mod select;
mod slot;
mod state;

pub use constants::{AID_FULL, AID_RID, DEFAULT_SERIAL, INS_IMPORT_ASYM, VERSION};

use attest::Attestation;
use constants::{
    DEFAULT_PIN_TRIES, DEFAULT_PIN_VALUE, DEFAULT_PUK_TRIES, DEFAULT_PUK_VALUE,
    SW_INS_NOT_SUPPORTED, SW_OK,
};
use data::PivData;
use keyroost_piv::Instruction;
use management::MgmtKey;
use slot::{Slot, factory_slots};
use state::Pin;

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
    /// The 9B management key and its session state: the stored cipher
    /// algorithm and key material (factory: 3DES with the Yubico default
    /// key), the pending GA witness/challenge, and the slot's unlocked
    /// status.
    pub(crate) mgmt: MgmtKey,
    /// The 24 key slots in table order: `9A`, `9C`, `9D`, `9E`, then
    /// retired `1..=20` (key refs `82`..=`95`). `9B` (management) and `F9`
    /// (attestation) are not slots.
    pub(crate) slots: [Slot; 24],
    /// The non-slot data objects — CHUID, PIN-protected, Yubico admin —
    /// none stored at the factory.
    pub(crate) data: PivData,
    /// The PIN/ALWAYS latch: set by a successful VERIFY, consumed by the
    /// next non-chained APDU — an `ALWAYS`-policy slot operation must be
    /// the APDU right after the VERIFY that armed it.
    pub(crate) pin_always_armed: bool,
    /// The `F9` attestation key and its self-signed certificate — the key
    /// that signs the ATTEST certificates and the slot keys' on-card
    /// origin proof.
    pub(crate) attestation: Attestation,
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
            mgmt: MgmtKey::default(),
            slots: factory_slots(),
            data: PivData::default(),
            pin_always_armed: false,
            attestation: crate::attest::fresh_attestation(),
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
        // A GET RESPONSE with a pending tail is a chained continuation of
        // its parent APDU: it inherits the parent's gate results, so it
        // does not consume the PIN/ALWAYS latch. Any other APDU — including
        // a stray GET RESPONSE with nothing pending — is a new command and
        // consumes the latch: an `ALWAYS`-policy slot operation must be the
        // APDU right after a successful VERIFY.
        let chained = *ins == keyroost_piv::Instruction::GetResponse as u8
            && self.get_response_tail.is_some();
        // A VERIFY carrying an 8-byte body is a real PIN presentation —
        // the status query (no body) is not, even though both can answer
        // 9000. Only a presentation that the card accepts re-arms the
        // PIN/ALWAYS latch.
        let pin_presentation = *ins == keyroost_piv::Instruction::Verify as u8
            && apdu.get(2) == Some(&0x00)
            && matches!(apdu_lc_body(apdu), Ok((_, body, _)) if body.len() == 8);
        let response = match Instruction::from_code(*ins) {
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
        };
        // The PIN/ALWAYS latch is consumed by the APDU after the one that
        // armed it. A successful PIN presentation is the one APDU that arms
        // it — and it must not consume the arm it just set: the arm survives
        // until the next command.
        let armed_this_apdu = pin_presentation && response.sw == SW_OK;
        if !chained && !armed_this_apdu {
            self.pin_always_armed = false;
        }
        response
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

/// The `Lc`, body and trailing bytes of a case-3/4 APDU:
/// `Ok((lc, body, tail))`, where `tail` is the remainder after the body —
/// the `Le` byte of a case-4 APDU, for the caller to read through
/// [`apdu_le`] — and `Err(())` when `Lc` overruns the APDU: the caller
/// answers [`keyroost_piv::SW_WRONG_LENGTH`]. A case-1/2 APDU carries no
/// length byte at all and reads as an empty body.
///
/// Both the short form and the extended form are accepted: a non-zero byte
/// at index 4 is the short `Lc` with the body at byte 5; a `0x00` there is
/// either a case-4 APDU carrying no command data (a `Le` follows, the APDU
/// is at most 6 bytes) or the extended marker, with `Lc` as the two-byte
/// value at bytes 5–6 and the body at byte 7 — the host's `build_apdu_ext`
/// form, which the large PUT DATA and IMPORT ASYMMETRIC KEY bodies use.
pub(crate) fn apdu_lc_body(apdu: &[u8]) -> Result<(usize, &[u8], &[u8]), ()> {
    let first = match apdu.get(4) {
        Some(&b) => b,
        None => return Ok((0, &[], &[])),
    };
    if first != 0 {
        let lc = usize::from(first);
        let Some(body) = apdu.get(5..5 + lc) else { return Err(()) };
        return Ok((lc, body, &apdu[5 + lc..]));
    }
    // The zero leading length byte: a case-4 APDU with no command data, or
    // (at 7 bytes and up) the extended marker.
    if apdu.len() < 7 {
        return Ok((0, &[], &apdu[5..]));
    }
    let lc = (usize::from(apdu[5]) << 8) | usize::from(apdu[6]);
    let Some(body) = apdu.get(7..7 + lc) else { return Err(()) };
    Ok((lc, body, &apdu[7 + lc..]))
}

/// The `63Cx` status word carrying `tries` remaining in the low nibble of
/// the second byte — the form the host's `sw_tries_remaining` decodes.
pub(crate) fn tries_sw(tries: u8) -> u16 {
    0x63C0 | u16::from(tries)
}
