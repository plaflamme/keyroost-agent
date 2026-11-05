//! Applet-wide constants: the ISO 7816-4 status words the handlers answer,
//! the SP 800-73-4 dynamic-authentication tags, and the factory default
//! values.

/// SP 800-73-4 §4.1.3 dynamic-authentication tags: the `7C` wrapper and its
/// witness / challenge / response / exponent members.
pub(crate) const GA_TAG_DYN_AUTH: u8 = 0x7C;
pub(crate) const GA_TAG_WITNESS: u8 = 0x80;
pub(crate) const GA_TAG_CHALLENGE: u8 = 0x81;
pub(crate) const GA_TAG_RESPONSE: u8 = 0x82;
pub(crate) const GA_TAG_EXP: u8 = 0x85;

/// Largest GA challenge value this applet will encrypt — the reference's
/// 64-byte scratch buffer caps the template it will accept at all.
pub(crate) const GA_MAX_CHALLENGE: usize = 64;

/// The 9B management key a factory-fresh applet answers to: 3DES with the
/// Yubico default key (three `01 02 03 04 05 06 07 08` halves).
pub(crate) const DEFAULT_MGMT_KEY: [u8; 24] = [
    1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
];

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

/// The factory application PIN: "123456" 0xFF-padded to 8 bytes.
pub(crate) const DEFAULT_PIN_VALUE: [u8; 8] = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF];
/// The factory PUK: "12345678".
pub(crate) const DEFAULT_PUK_VALUE: [u8; 8] = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38];
/// The factory PIN retry limit (`PivApplet`'s `pinRetries`).
pub(crate) const DEFAULT_PIN_TRIES: u8 = 5;
/// The factory PUK retry limit (`PivApplet`'s `pukRetries`).
pub(crate) const DEFAULT_PUK_TRIES: u8 = 3;
