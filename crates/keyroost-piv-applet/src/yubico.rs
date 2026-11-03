//! Yubico PIV extensions: the custom instructions the `YubiKey` implements beyond
//! the standard ISO 7816-4 instruction set.
//!

/// Yubico extension instructions not in the iso7816 crate.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum YubicoInstruction {
    /// GET VERSION (0xFD): the applet version as three `major.minor.patch`
    /// bytes.
    GetVersion,
    /// GET SERIAL (0xF8): the card serial as four big-endian bytes.
    GetSerial,
    /// GET METADATA (0xF7): per-key/PIN metadata (algorithm, origin, policy,
    /// retries).
    GetMetadata,
    /// IMPORT ASYMMETRIC KEY (0xFE): import a private key into a slot.
    ImportAsymmetricKey,
    /// MOVE KEY (0xF6): import a private key into a slot.
    MoveKey,
    /// SET MANAGEMENT KEY (0xFF): change the management key.
    SetManagementKey,
    /// SET PIN RETRIES (0xFA): change the PIN and PUK retry counters.
    SetPinRetries,
    /// RESET (0xFB): reset the applet to factory defaults.
    Reset,
    /// ATTEST (0xF9): sign a certificate attesting to the applet's key.
    Attest,
}

impl YubicoInstruction {
    /// Convert a raw instruction byte to a `YubicoInstruction`, if it's one of
    /// the Yubico extensions.
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0xF6 => Some(YubicoInstruction::MoveKey),
            0xF7 => Some(YubicoInstruction::GetMetadata),
            0xF8 => Some(YubicoInstruction::GetSerial),
            0xF9 => Some(YubicoInstruction::Attest),
            0xFA => Some(YubicoInstruction::SetPinRetries),
            0xFB => Some(YubicoInstruction::Reset),
            0xFD => Some(YubicoInstruction::GetVersion),
            0xFE => Some(YubicoInstruction::ImportAsymmetricKey),
            0xFF => Some(YubicoInstruction::SetManagementKey),
            _ => None,
        }
    }

    /// Convert a `YubicoInstruction` to its raw instruction byte.
    #[allow(unused)]
    pub fn to_code(self) -> u8 {
        match self {
            YubicoInstruction::MoveKey => 0xF6,
            YubicoInstruction::GetMetadata => 0xF7,
            YubicoInstruction::GetSerial => 0xF8,
            YubicoInstruction::Attest => 0xF9,
            YubicoInstruction::SetPinRetries => 0xFA,
            YubicoInstruction::Reset => 0xFB,
            YubicoInstruction::GetVersion => 0xFD,
            YubicoInstruction::ImportAsymmetricKey => 0xFE,
            YubicoInstruction::SetManagementKey => 0xFF,
        }
    }
}
