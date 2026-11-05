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
//! `VSmartCard` protocol, behind the `vpcd` reader driver.
//!
//! # Reference
//!
//! The behaviour being reimplemented here is the one of `PivApplet`, the
//! `JavaCard` PIV applet (YubiKey-PIV-compatible, including the Yubico
//! extension instructions) — done in pure Rust, so the crate itself needs no
//! `JavaCard` toolchain or JVM; an engine front-end (e.g. jCardEngine) can
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
//! the Yubico extensions `PivApplet` implements — the same set
//! [`keyroost_piv::Instruction`] enumerates for the host side, plus IMPORT
//! ASYMMETRIC KEY ([`INS_IMPORT_ASYM`]), which the host byte layer does not
//! build yet.

#![forbid(unsafe_code)]

mod apdu;
mod attest;
mod auth;
mod constants;
mod data;
mod general_auth;
mod identity;
mod keygen;
mod management;
mod piv;
mod slot;
mod state;
mod yubico;

pub use constants::{AID_FULL, AID_RID, DEFAULT_SERIAL, VERSION};

use attest::Attestation;
use constants::{DEFAULT_PIN_TRIES, DEFAULT_PIN_VALUE, DEFAULT_PUK_TRIES, DEFAULT_PUK_VALUE};
use data::PivData;
use iso7816::{Instruction, response::Status};
use management::MgmtKey;
use slot::{Slot, factory_slots};
use state::Pin;

#[derive(Debug)]
struct Response(apdu_dispatch::Response);

impl Response {
    #[allow(clippy::needless_pass_by_value)]
    pub(crate) fn from_vec(data: Vec<u8>) -> Self {
        Self(apdu_dispatch::Response::Data(
            apdu_dispatch::response::Data::from_slice(data.as_slice()).unwrap(), // TODO: don't panic
        ))
    }

    #[allow(unused)]
    pub(crate) fn data(&self) -> &[u8] {
        match &self.0 {
            iso7816::Response::Data(d) => d,
            iso7816::Response::Status(_) => &[],
        }
    }

    pub(crate) fn status(&self) -> Status {
        match self.0 {
            iso7816::Response::Data(_) => Status::Success,
            iso7816::Response::Status(status) => status,
        }
    }
}

impl From<Status> for Response {
    fn from(value: Status) -> Self {
        Self(apdu_dispatch::Response::Status(value))
    }
}

use crate::yubico::YubicoInstruction;

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

impl iso7816::App for PivApplet {
    fn aid(&self) -> iso7816::Aid {
        iso7816::Aid::new_truncatable(&constants::AID_FULL, constants::AID_RID.len())
    }
}

impl apdu_app::App for PivApplet {
    fn select(
        &mut self,
        _interface: iso7816::Interface,
        _apdu: apdu_app::CommandView<'_>,
        _reply: &mut apdu_app::VecView<u8>,
    ) -> apdu_app::Result {
        // NOOP
        Ok(())
    }

    fn deselect(&mut self) {}

    fn call(
        &mut self,
        _interface: iso7816::Interface,
        apdu: apdu_app::CommandView<'_>,
        reply: &mut apdu_app::VecView<u8>,
    ) -> apdu_app::Result {
        match self.process_command(&apdu).0 {
            apdu_dispatch::Response::Data(d) => reply.extend(d),
            apdu_dispatch::Response::Status(s) => return Err(s),
        }
        Ok(())
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
    #[allow(clippy::missing_panics_doc)]
    pub fn with_serial(serial: u32) -> Self {
        Self {
            serial,
            pin: Pin::factory(DEFAULT_PIN_VALUE, DEFAULT_PIN_TRIES),
            puk: Pin::factory(DEFAULT_PUK_VALUE, DEFAULT_PUK_TRIES),
            mgmt: MgmtKey::default(),
            slots: factory_slots(),
            data: PivData::default(),
            pin_always_armed: false,
            attestation: crate::attest::fresh_attestation().expect("fresh attestation"),
        }
    }

    /// The applet's entry point: dispatch a received host APDU to its
    /// instruction handler.
    #[cfg(test)]
    fn process(&mut self, apdu: &[u8]) -> Response {
        let command = match apdu::CommandView::try_from(apdu) {
            Ok(command) => command,
            Err(
                iso7816::command::FromSliceError::TooLong
                | iso7816::command::FromSliceError::TooShort
                | iso7816::command::FromSliceError::InvalidSliceLength,
            ) => return iso7816::Status::WrongLength.into(),
            Err(iso7816::command::FromSliceError::InvalidClass) => {
                return iso7816::Status::ClassNotSupported.into();
            }
            Err(iso7816::command::FromSliceError::InvalidFirstBodyByteForExtended) => {
                return iso7816::Status::WrongLength.into();
            }
        };
        self.process_command(&command)
    }

    fn process_command(&mut self, command: &apdu::CommandView<'_>) -> Response {
        if command.class().chain().not_the_last() {
            return iso7816::Status::ClaNotSupported.into();
        }

        if matches!(
            command.class().range(),
            iso7816::command::class::Range::Proprietary
        ) {
            return iso7816::Status::ClaNotSupported.into();
        }

        let ins = command.instruction();
        // A VERIFY carrying an 8-byte body is a real PIN presentation —
        // the status query (no body) is not, even though both can answer
        // 9000. Only a presentation that the card accepts re-arms the
        // PIN/ALWAYS latch.
        let pin_presentation =
            ins == Instruction::Verify && command.p1 == 0x00 && command.data().len() == 8;
        #[allow(clippy::match_same_arms)]
        let response = match ins {
            Instruction::Select => unreachable!(),
            Instruction::Verify => self.process_verify(command),
            Instruction::GetData => self.process_get_data(command),
            Instruction::GetResponse => unreachable!(),
            Instruction::GeneralAuthenticate => self.process_general_authenticate(command),
            Instruction::GenerateAsymmetricKeyPair => self.process_generate_key_pair(command),
            Instruction::PutData => self.process_put_data(command),
            Instruction::ChangeReferenceData => self.process_change_reference(command),
            Instruction::ResetRetryCounter => self.process_reset_retry_counter(command),
            Instruction::ReadBinary => Status::InstructionNotSupportedOrInvalid.into(), // TODO
            Instruction::WriteBinary => Status::InstructionNotSupportedOrInvalid.into(), // TODO
            Instruction::Unknown(code) if let Some(yi) = YubicoInstruction::from_code(code) => {
                match yi {
                    YubicoInstruction::GetVersion => self.process_get_version(command),
                    YubicoInstruction::GetSerial => self.process_get_serial(command),
                    YubicoInstruction::GetMetadata => self.process_get_metadata(command),
                    YubicoInstruction::ImportAsymmetricKey => self.process_import_key(command),
                    YubicoInstruction::MoveKey => self.process_move_key(command),
                    YubicoInstruction::SetManagementKey => self.process_set_management_key(command),
                    YubicoInstruction::SetPinRetries => self.process_set_pin_retries(command),
                    YubicoInstruction::Reset => self.process_reset(command),
                    YubicoInstruction::Attest => self.process_attest(command),
                }
            }
            Instruction::Unknown(_code) => Status::InstructionNotSupportedOrInvalid.into(),
        };
        // The PIN/ALWAYS latch is consumed by the APDU after the one that
        // armed it. A successful PIN presentation is the one APDU that arms
        // it — and it must not consume the arm it just set: the arm survives
        // until the next command.
        let armed_this_apdu = pin_presentation && response.status() == Status::Success;
        if !armed_this_apdu {
            self.pin_always_armed = false;
        }
        response
    }
}

/// The `63Cx` status word carrying `tries` remaining in the low nibble of
/// the second byte — the form the host's `sw_tries_remaining` decodes.
pub(crate) fn tries_sw(tries: u8) -> Status {
    Status::RemainingRetries(tries)
}
