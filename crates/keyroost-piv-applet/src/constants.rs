//! Applet-wide constants: the ISO 7816-4 status words the handlers answer,
//! the SP 800-73-4 dynamic-authentication tags, and the factory default
//! values.

/// Yubico extension: IMPORT ASYMMETRIC KEY. PivApplet implements it, but
/// `keyroost-piv` has no host-side builder for it, so the byte is local
/// rather than a variant of [`keyroost_piv::Instruction`].
pub const INS_IMPORT_ASYM: u8 = 0x86;

/// ISO 7816-4 status word: instruction not supported.
pub(crate) const SW_INS_NOT_SUPPORTED: u16 = 0x6D00;
/// ISO 7816-4 status word: CLA not supported.
pub(crate) const SW_CLA_NOT_SUPPORTED: u16 = 0x6400;
/// ISO 7816-4 status word: conditions not satisfied — the standard form
/// (a GET RESPONSE with nothing pending). Note `keyroost-piv` carries its
/// own `SW_CONDITIONS_NOT_SATISFIED` = `0x6985`; this is the `0x6900` one.
pub(crate) const SW_CONDITIONS_NOT_SATISFIED: u16 = 0x6900;
/// ISO 7816-4 status word: incorrect P1/P2 — the JavaCard
/// `ISO7816.SW_INCORRECT_P1P2` word the card answers for an unexpected P1.
pub(crate) const SW_INCORRECT_P1P2: u16 = 0x6B00;
/// ISO 7816-4 status word: wrong data — the JavaCard
/// `ISO7816.SW_WRONG_DATA` word the card answers for a wrong-length or
/// invalid reference-data body.
pub(crate) const SW_WRONG_DATA: u16 = 0x6A86;
/// ISO 7816-4 status word: security status not satisfied — the JavaCard
/// `ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED` word the card answers when a
/// management command's preconditions are not met.
pub(crate) const SW_SECURITY_STATUS_NOT_SATISFIED: u16 = 0x6986;
/// ISO 7816-4 status word: security object not satisfied — the
/// `0x6982` word the slot key commands answer when the 9B management
/// session is not unlocked. Same value as the host crate's
/// [`keyroost_piv::SW_SECURITY_NOT_SATISFIED`].
// The first non-test reader lands with the key-slot commands (T2); until
// then only the gate's unit tests read it.
#[allow(dead_code)]
pub(crate) const SW_SECURITY_NOT_SATISFIED: u16 = 0x6982;
/// ISO 7816-4 status word: success — the card's `9000`.
pub(crate) const SW_OK: u16 = 0x9000;
/// ISO 7816-4 status word: wrong length — `Lc` overrunning the APDU.
pub(crate) const SW_WRONG_LENGTH: u16 = 0x6700;
/// ISO 7816-4 status word: invalid data — a structurally broken TLV
/// template (truncated lengths, an underrun body). Same value as
/// [`SW_INCORRECT_P1P2`]; the name marks which check produced it.
pub(crate) const SW_DATA_INVALID: u16 = 0x6B00;

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

/// SELECT P1: select by DF name (the AID). Anything else on a PIV card is
/// a file select this applet has no answer for.
pub(crate) const INS_SELECT_P1_BY_AID: u8 = 0x04;

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
pub(crate) const TAG_61: u8 = 0x61;
/// TLV tag of the application identifier (AID/PIX) object.
pub(crate) const TAG_4F: u8 = 0x4F;
/// TLV tag of the application identifier template (SP 800-73-4) carrying
/// the RID form of the AID.
pub(crate) const TAG_79: u8 = 0x79;

/// The factory application PIN: "123456" 0xFF-padded to 8 bytes.
pub(crate) const DEFAULT_PIN_VALUE: [u8; 8] = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF];
/// The factory PUK: "12345678".
pub(crate) const DEFAULT_PUK_VALUE: [u8; 8] = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38];
/// The factory PIN retry limit (PivApplet's `pinRetries`).
pub(crate) const DEFAULT_PIN_TRIES: u8 = 5;
/// The factory PUK retry limit (PivApplet's `pukRetries`).
pub(crate) const DEFAULT_PUK_TRIES: u8 = 3;
