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
//! # Scope (wiring only)
//!
//! The crate is currently **scaffolding**: [`PivApplet::process`] dispatches
//! a received APDU to one handler per PIV instruction. SELECT (and its
//! `61xx` / GET RESPONSE follow-up) and GET SERIAL / GET VERSION are
//! implemented; the remaining handlers are stubs answering `6D00` (instruction
//! not supported)
//! — GET DATA answers `6A82` (no objects yet). The card state (PIN/PUK,
//! management key, key slots,
//! certificates, CHUID, admin data) and the crypto it will carry (key
//! generation, signing, ECDH, block ciphers for management-key auth) land
//! with the command implementations; the RustCrypto dependencies they need
//! are deliberately not in the dependency tree yet.
//!
//! The instruction surface is the union of SP 800-73-4's PIV commands and
//! the Yubico extensions PivApplet implements — the same set
//! [`keyroost_piv::Instruction`] enumerates for the host side, plus IMPORT
//! ASYMMETRIC KEY ([`INS_IMPORT_ASYM`]), which the host byte layer does not
//! build yet.

#![forbid(unsafe_code)]

use keyroost_piv::Instruction;

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

/// A PIV applet instance: the card side of NIST SP 800-73-4.
///
/// Owns the card's state — the application PIN and PUK with their retry
/// counters, the management (9B) key, the per-slot private key material and
/// certificates, the CHUID, the admin data, and the applet version/serial —
/// and answers host APDUs through [`PivApplet::process`].
///
/// While the crate is wiring only the only state is the response tail; the
/// rest of the card state lands with the command implementations.
pub struct PivApplet {
    /// The card serial GET SERIAL presents: a 32-bit value, big-endian on
    /// the wire.
    serial: u32,
    /// The tail of a response the previous command signalled with `61xx`
    /// because it did not fit in the requested `Le`, pending for a GET
    /// RESPONSE (0xC0). `None` when nothing is pending.
    get_response_tail: Option<Vec<u8>>,
}

impl Default for PivApplet {
    fn default() -> Self {
        Self::new()
    }
}

impl PivApplet {
    /// A factory-fresh applet: default PIN/PUK with full retry counters, the
    /// default management key, the [`DEFAULT_SERIAL`] serial, empty key
    /// slots.
    ///
    /// While the applet is wiring only the serial is the only state field
    /// with a factory value; the rest lands with the state fields.
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

    /// VERIFY (0x20): present the application PIN (P2=`80`) or PUK (P2=`81`)
    /// against the stored value. An empty body queries the retry counter
    /// without consuming a try (`63Cx` / `9000` / `6983`).
    fn process_verify(&mut self, _apdu: &[u8]) -> Response {
        Response::sw(SW_INS_NOT_SUPPORTED)
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

    /// CHANGE REFERENCE DATA (0x24): change the application PIN (P2=`80`)
    /// or PUK (P2=`81`), old value first.
    fn process_change_reference(&mut self, _apdu: &[u8]) -> Response {
        Response::sw(SW_INS_NOT_SUPPORTED)
    }

    /// RESET RETRY COUNTER (0x2C): unblock a blocked PIN using the PUK and
    /// set the new PIN.
    fn process_reset_retry_counter(&mut self, _apdu: &[u8]) -> Response {
        Response::sw(SW_INS_NOT_SUPPORTED)
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
}
