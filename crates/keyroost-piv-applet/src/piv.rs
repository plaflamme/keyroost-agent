/// The four PIV asymmetric key slots, identified by their key reference and the
/// certificate data object that holds the slot's X.509 certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    /// `9A` — PIV Authentication.
    Authentication,
    /// `9C` — Digital Signature.
    Signature,
    /// `9D` — Key Management (decryption).
    KeyManagement,
    /// `9E` — Card Authentication.
    CardAuthentication,
    /// Yubico retired key-management slots (fw 5.7+). 0x82..=0x95 (represented as Retired(0..20))
    Retired(u8),
}

impl Slot {
    /// The key-reference byte (`9A`/`9C`/`9D`/`9E`, or `82`..=`95` for retired).
    #[must_use]
    pub const fn into_u8(self) -> u8 {
        match self {
            Slot::Authentication => 0x9A,
            Slot::Signature => 0x9C,
            Slot::KeyManagement => 0x9D,
            Slot::CardAuthentication => 0x9E,
            Slot::Retired(n) => 0x82 + n,
        }
    }

    /// Checked constructor for a retired slot: `Some` for n in 1..=20, else `None`.
    /// All retired-slot construction must go through here so an invalid ref can
    /// never be built.
    #[must_use]
    pub(crate) fn retired(n: u8) -> Option<Slot> {
        if (1..=20).contains(&n) {
            Some(Self::Retired(n - 1))
        } else {
            None
        }
    }

    pub(crate) fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x9A => Some(Self::Authentication),
            0x9C => Some(Self::Signature),
            0x9D => Some(Self::KeyManagement),
            0x9E => Some(Self::CardAuthentication),
            0x82..=0x95 => Some(Self::Retired(value - 0x82)),
            _ => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn all() -> impl Iterator<Item = Slot> {
        let named = [
            Self::Authentication,
            Self::Signature,
            Self::KeyManagement,
            Self::CardAuthentication,
        ];
        let retired = (1..=20).filter_map(Slot::retired);
        std::iter::chain(named, retired)
    }
}

/// Management-key (9B) cipher algorithm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MgmtAlg {
    /// 3DES (TDEA) — pre-5.7 `YubiKey` default; 24-byte key, 8-byte block.
    TripleDes = 0x03,
    /// AES-128 — 16-byte key, 16-byte block.
    Aes128 = 0x08,
    /// AES-192 — 24-byte key, 16-byte block; the `YubiKey` 5.7+ default.
    Aes192 = 0x0A,
    /// AES-256 — 32-byte key, 16-byte block.
    Aes256 = 0x0C,
}

impl MgmtAlg {
    pub(crate) fn key_len(self) -> usize {
        #[allow(clippy::match_same_arms)]
        match self {
            MgmtAlg::TripleDes => 24,
            MgmtAlg::Aes128 => 16,
            MgmtAlg::Aes192 => 24,
            MgmtAlg::Aes256 => 32,
        }
    }

    pub(crate) fn block_size(self) -> usize {
        match self {
            MgmtAlg::TripleDes => 8,
            MgmtAlg::Aes128 | MgmtAlg::Aes192 | Self::Aes256 => 16,
        }
    }

    pub(crate) fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x03 => Some(Self::TripleDes),
            0x08 => Some(Self::Aes128),
            0x0A => Some(Self::Aes192),
            0x0C => Some(Self::Aes256),
            _ => None,
        }
    }
}

/// Asymmetric key algorithm
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyAlg {
    Rsa1024 = 0x06,
    Rsa2048 = 0x07,
    Rsa3072 = 0x05,
    Rsa4096 = 0x16,
    EccP256 = 0x11,
    EccP384 = 0x14,
    EccP521 = 0x15,
    Ed25519 = 0xE0,
    X25519 = 0xE1,
}

impl KeyAlg {
    pub(crate) fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x06 => Some(Self::Rsa1024),
            0x07 => Some(Self::Rsa2048),
            0x05 => Some(Self::Rsa3072),
            0x16 => Some(Self::Rsa4096),
            0x11 => Some(Self::EccP256),
            0x14 => Some(Self::EccP384),
            0x15 => Some(Self::EccP521),
            0xE0 => Some(Self::Ed25519),
            0xE1 => Some(Self::X25519),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinPolicy {
    Default = 0x00,
    Never = 0x01,
    Once = 0x02,
    Always = 0x03,
}

impl PinPolicy {
    pub(crate) fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Self::Default),
            0x01 => Some(Self::Never),
            0x02 => Some(Self::Once),
            0x03 => Some(Self::Always),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TouchPolicy {
    Default = 0x00,
    Never = 0x01,
    Always = 0x02,
    Cached = 0x03,
}
impl TouchPolicy {
    pub(crate) fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Self::Default),
            0x01 => Some(Self::Never),
            0x02 => Some(Self::Always),
            0x03 => Some(Self::Cached),
            _ => None,
        }
    }
}
