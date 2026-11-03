//! Yubico PIV extensions: the custom instructions the YubiKey implements beyond
//! the standard ISO 7816-4 instruction set.

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
    /// IMPORT ASYMMETRIC KEY (0x86): import a private key into a slot.
    ImportAsymmetricKey,
    /// MOVE KEY (0xF6): import a private key into a slot.
    MoveKey,
    /// SET MANAGEMENT KEY (0x3D): change the management key.
    SetManagementKey,
    /// SET PIN RETRIES (0x3C): change the PIN and PUK retry counters.
    SetPinRetries,
    /// RESET (0x2F): reset the applet to factory defaults.
    Reset,
    /// ATTEST (0x1D): sign a certificate attesting to the applet's key.
    Attest,
}

impl YubicoInstruction {
    /// Convert a raw instruction byte to a YubicoInstruction, if it's one of
    /// the Yubico extensions.
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0xFD => Some(YubicoInstruction::GetVersion),
            0xF8 => Some(YubicoInstruction::GetSerial),
            0xF7 => Some(YubicoInstruction::GetMetadata),
            0x86 => Some(YubicoInstruction::ImportAsymmetricKey),
            0xF6 => Some(YubicoInstruction::MoveKey),
            0x3D => Some(YubicoInstruction::SetManagementKey),
            0x3C => Some(YubicoInstruction::SetPinRetries),
            0x2F => Some(YubicoInstruction::Reset),
            0x1D => Some(YubicoInstruction::Attest),
            _ => None,
        }
    }

    /// Convert a YubicoInstruction to its raw instruction byte.
    pub fn to_code(&self) -> u8 {
        match self {
            YubicoInstruction::GetVersion => 0xFD,
            YubicoInstruction::GetSerial => 0xF8,
            YubicoInstruction::GetMetadata => 0xF7,
            YubicoInstruction::ImportAsymmetricKey => 0x86,
            YubicoInstruction::MoveKey => 0xF6,
            YubicoInstruction::SetManagementKey => 0x3D,
            YubicoInstruction::SetPinRetries => 0x3C,
            YubicoInstruction::Reset => 0x2F,
            YubicoInstruction::Attest => 0x1D,
        }
    }
}
