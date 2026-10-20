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
//! a received APDU to one handler per PIV instruction, and every handler
//! body is a `todo!()`. The card state (PIN/PUK, management key, key slots,
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
/// Deliberately empty while the crate is wiring only: the state fields land
/// together with the command implementations.
pub struct PivApplet;

impl Default for PivApplet {
    fn default() -> Self {
        Self::new()
    }
}

impl PivApplet {
    /// A factory-fresh applet: default PIN/PUK with full retry counters, the
    /// default management key, a freshly generated serial, empty key slots.
    ///
    /// A no-op while the applet is wiring only: there are no state fields to
    /// initialise yet; the factory state lands with them.
    #[must_use]
    pub fn new() -> Self {
        Self
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
            Some(Instruction::GeneralAuthenticate) => {
                self.process_general_authenticate(apdu)
            }
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

    /// SELECT (0xA4, P1=`04`): activate the applet by AID and answer with
    /// the application property template — the AID plus the
    /// supported-algorithms object (tag `0xAC`) advertising the slot
    /// algorithms and any applet-specific extensions.
    fn process_select(&mut self, _apdu: &[u8]) -> Response {
        todo!()
    }

    /// VERIFY (0x20): present the application PIN (P2=`80`) or PUK (P2=`81`)
    /// against the stored value. An empty body queries the retry counter
    /// without consuming a try (`63Cx` / `9000` / `6983`).
    fn process_verify(&mut self, _apdu: &[u8]) -> Response {
        todo!()
    }

    /// GET DATA (0xCB, P1P2=`3FFF`): read a data object by its
    /// `5C`-wrapped tag — a slot certificate, the CHUID, an admin object —
    /// and return it wrapped in the `53` data template.
    fn process_get_data(&mut self, _apdu: &[u8]) -> Response {
        todo!()
    }

    /// GET RESPONSE (0xC0): fetch the next chunk of a response the applet
    /// signalled with `61xx` (large objects such as certificates arrive this
    /// way).
    fn process_get_response(&mut self, _apdu: &[u8]) -> Response {
        todo!()
    }

    /// GENERAL AUTHENTICATE (0x87): the slot engine. Management-key (9B)
    /// mutual authentication via witness/challenge, and per-slot signing /
    /// key agreement (RSA, ECDSA, ECDH) with the `7C` dynamic-authentication
    /// template.
    fn process_general_authenticate(&mut self, _apdu: &[u8]) -> Response {
        todo!()
    }

    /// GENERATE ASYMMETRIC KEY PAIR (0x47): create a private key on-card in
    /// a slot and return its public key in the `7F 49` template.
    fn process_generate_key_pair(&mut self, _apdu: &[u8]) -> Response {
        todo!()
    }

    /// PUT DATA (0xDB): write a data object — a slot certificate or another
    /// object — under its `5C`-wrapped tag.
    fn process_put_data(&mut self, _apdu: &[u8]) -> Response {
        todo!()
    }

    /// CHANGE REFERENCE DATA (0x24): change the application PIN (P2=`80`)
    /// or PUK (P2=`81`), old value first.
    fn process_change_reference(&mut self, _apdu: &[u8]) -> Response {
        todo!()
    }

    /// RESET RETRY COUNTER (0x2C): unblock a blocked PIN using the PUK and
    /// set the new PIN.
    fn process_reset_retry_counter(&mut self, _apdu: &[u8]) -> Response {
        todo!()
    }

    /// GET VERSION (0xFD, Yubico extension): the 3-byte applet version.
    fn process_get_version(&mut self, _apdu: &[u8]) -> Response {
        todo!()
    }

    /// GET SERIAL (0xF8, Yubico extension): the 4-byte card serial.
    fn process_get_serial(&mut self, _apdu: &[u8]) -> Response {
        todo!()
    }

    /// GET METADATA (0xF7, Yubico extension): per-key/PIN metadata
    /// (algorithm, origin, policy, retries) for the P2 reference.
    fn process_get_metadata(&mut self, _apdu: &[u8]) -> Response {
        todo!()
    }

    /// IMPORT ASYMMETRIC KEY (0x86, Yubico extension, [`INS_IMPORT_ASYM`]):
    /// import a full key pair into a slot.
    fn process_import_key(&mut self, _apdu: &[u8]) -> Response {
        todo!()
    }

    /// MOVE KEY (0xF6, Yubico extension): move a slot's key to another slot;
    /// `P1 = 0xFF` deletes the key instead.
    fn process_move_key(&mut self, _apdu: &[u8]) -> Response {
        todo!()
    }

    /// SET MANAGEMENT KEY (0xFF, Yubico extension): replace the 9B key
    /// (authenticated by the current one) and set its touch requirement.
    fn process_set_management_key(&mut self, _apdu: &[u8]) -> Response {
        todo!()
    }

    /// SET PIN RETRIES (0xFA, Yubico extension): set the PIN/PUK retry
    /// limits.
    fn process_set_pin_retries(&mut self, _apdu: &[u8]) -> Response {
        todo!()
    }

    /// RESET (0xFB, Yubico extension): factory-reset the applet; allowed
    /// only when PIN and PUK are both blocked.
    fn process_reset(&mut self, _apdu: &[u8]) -> Response {
        todo!()
    }

    /// ATTEST (0xF9, Yubico extension): self-signed attestation certificate
    /// for a slot's key, proving on-card generation.
    fn process_attest(&mut self, _apdu: &[u8]) -> Response {
        todo!()
    }
}
