//! The key slots: the 24-slot table with its factory state and the two
//! gates every key-slot command applies.
//!
//! The slots are the SP 800-73-4 key references minus the two that are not
//! key slots: `9B` is the management key (its session state lives in
//! [`crate::management`]) and `F9` is the attestation key reference. The
//! table order is `9A`, `9C`, `9D`, `9E`, then retired `1..=20` (key refs
//! `82`..=`95`), the mapping the host crate's `Slot::retired(n)`
//! implements.
//!
//! Every slot carries its PIN policy (the factory values: `ONCE` for 9A,
//! `ALWAYS` for 9C, `ONCE` for 9D, `NEVER` for 9E and for every retired
//! slot), its touch policy (`0` at the factory) and, once a key lands, the
//! key itself and its certificate data object. The two gates:
//!
//! - [`PivApplet::management_unlocked`] — the 9B session must be unlocked
//!   ([`SW_SECURITY_NOT_SATISFIED`] otherwise); a read-only consultation
//!   of the management state, not a second challenge.
//! - [`PivApplet::slot_pin_gate`] — the slot's PIN policy, enforced with
//!   the session's `pin.verified` flag and the [`PivApplet::pin_always_armed`]
//!   latch; [`SW_SECURITY_STATUS_NOT_SATISFIED`] otherwise.

use elliptic_curve::sec1::ToEncodedPoint;
use keyroost_piv::{KeyAlg, PinPolicy};
use pkcs1::DecodeRsaPrivateKey;
use rsa::RsaPrivateKey;
use rsa::traits::PublicKeyParts;
use zeroize::Zeroizing;

use crate::PivApplet;
use crate::constants::{SW_SECURITY_NOT_SATISFIED, SW_SECURITY_STATUS_NOT_SATISFIED};

/// One key slot: its key material (or the absence of one), its policies
/// and its certificate data object.
///
/// The fields the key-slot commands read and write land with them:
/// `key` with the key-generation commands, `cert` with GET/PUT DATA,
/// `touch_policy` with GENERATE and GET METADATA, `imported` with GENERATE
/// and MOVE KEY.
pub(crate) struct Slot {
    /// The slot's key, or `None` for an empty slot.
    #[allow(dead_code)] // read by slot GA (T3) and GET METADATA (T5).
    pub(crate) key: Option<SlotKey>,
    /// The PIN policy GENERATE KEY (re)sets for this slot; the factory
    /// value per slot.
    pub(crate) pin_policy: PinPolicy,
    /// The touch policy GENERATE KEY (re)sets for this slot: a raw
    /// [`keyroost_piv::TouchPolicy`] id, `0` (default) at the factory.
    #[allow(dead_code)] // (re)set by GENERATE/IMPORT/MOVE, read by GET METADATA (T5).
    pub(crate) touch_policy: u8,
    /// Whether the current key was imported by the host (`true`, origin
    /// `0x02`) or generated on the card (`false`, origin `0x01`).
    #[allow(dead_code)] // set by GENERATE/IMPORT/MOVE, read by GET METADATA (T5).
    pub(crate) imported: bool,
    /// The slot's certificate as stored under its data object (the `53`-
    /// wrapped value GET DATA returns verbatim), or `None` when the slot
    /// holds no certificate.
    pub(crate) cert: Option<Vec<u8>>,
}

/// A key held in a slot.
///
/// An EC key's material is the curve's private scalar — a zeroized
/// big-endian value, 32 bytes (P-256), 48 (P-384) or 66 (P-521), in
/// `secret`. An RSA key's material is the key's PKCS#1 ("`RSAPrivateKey`")
/// DER encoding — the `rsa` crate's `RsaPrivateKey` via `to_pkcs1_der`,
/// modulus, private exponent and the prime factors — and the card keeps
/// only that byte string, deserializing it for each use (the raw GA sign
/// and `public_inner` both read it).
#[allow(dead_code)] // read by slot GA (T3) and GET METADATA (T5).
pub(crate) struct SlotKey {
    /// The key's algorithm — the slot's key-algorithm id on the wire.
    pub(crate) alg: KeyAlg,
    /// The key's secret material, zeroized on drop: the EC private
    /// scalar, or — for RSA slots — the key's PKCS#1 DER encoding.
    pub(crate) secret: Zeroizing<Vec<u8>>,
}

impl SlotKey {
    /// The `7F49`-inner public-key TLVs this key reports — the same shape
    /// GENERATE's answer, the GET METADATA `04` member and the host's
    /// `parse_public_key`/`parse_metadata` all carry: the uncompressed
    /// point under `86` for EC keys, the modulus under `81` and the
    /// exponent under `82` for RSA keys. `None` for an algorithm this
    /// applet does not store.
    pub(crate) fn public_inner(&self) -> Option<Vec<u8>> {
        match self.alg {
            KeyAlg::EccP256 | KeyAlg::EccP384 | KeyAlg::EccP521 => {
                let point = match self.alg {
                    KeyAlg::EccP256 => {
                        let signing = ecdsa::SigningKey::<p256::NistP256>::from_slice(
                            &self.secret[..32],
                        )
                        .ok()?;
                        signing.verifying_key().to_encoded_point(false).as_bytes().to_vec()
                    }
                    KeyAlg::EccP384 => {
                        let signing = ecdsa::SigningKey::<p384::NistP384>::from_slice(
                            &self.secret[..48],
                        )
                        .ok()?;
                        signing.verifying_key().to_encoded_point(false).as_bytes().to_vec()
                    }
                    KeyAlg::EccP521 => {
                        // The generic `SecretKey` derivation — the ECDH path's
                        // own route — since `NistP521` does not satisfy the
                        // `ecdsa` crate's signing bounds.
                        let secret =
                            elliptic_curve::SecretKey::<p521::NistP521>::from_slice(
                                &self.secret[..],
                            )
                            .ok()?;
                        secret.public_key().to_encoded_point(false).as_bytes().to_vec()
                    }
                    _ => unreachable!("the outer match arm holds only the EC curves"),
                };
                let mut inner = Vec::with_capacity(2 + point.len());
                crate::data::push_tlv(&mut inner, &[0x86], &point);
                Some(inner)
            }
            KeyAlg::Rsa1024 | KeyAlg::Rsa2048 | KeyAlg::Rsa3072 | KeyAlg::Rsa4096 => {
                // The slot key's PKCS#1 encoding: serve the modulus under
                // `81` and the public exponent under `82`, as the
                // reference applet's `getKeyDetails` does.
                let Ok(key) = RsaPrivateKey::from_pkcs1_der(self.secret.as_slice()) else { return None };
                let (n, e) = (key.n().to_bytes_be(), key.e().to_bytes_be());
                let mut inner = Vec::with_capacity(2 + n.len() + 5);
                crate::data::push_tlv(&mut inner, &[0x81], &n);
                crate::data::push_tlv(&mut inner, &[0x82], &e);
                Some(inner)
            }
            _ => None,
        }
    }
}

/// The modulus size in bytes of an RSA algorithm id — `None` for
/// non-RSA algorithms.
pub(crate) fn rsa_modulus_len(alg: KeyAlg) -> Option<usize> {
    match alg {
        KeyAlg::Rsa1024 => Some(128),
        KeyAlg::Rsa2048 => Some(256),
        KeyAlg::Rsa3072 => Some(384),
        KeyAlg::Rsa4096 => Some(512),
        _ => None,
    }
}

impl Slot {
    /// The factory state of a slot: empty, the given PIN policy, no touch
    /// policy, no certificate.
    pub(crate) const fn factory(pin_policy: PinPolicy) -> Self {
        Slot {
            key: None,
            pin_policy,
            touch_policy: 0,
            imported: false,
            cert: None,
        }
    }
}

/// The table order of the 24 key slots, one entry per slot: `9A`, `9C`,
/// `9D`, `9E`, then retired `1..=20` (key refs `82`..=`95`).
pub(crate) const fn factory_slots() -> [Slot; 24] {
    [
        Slot::factory(PinPolicy::Once),
        Slot::factory(PinPolicy::Always),
        Slot::factory(PinPolicy::Once),
        Slot::factory(PinPolicy::Never),
        Slot::factory(PinPolicy::Once),
        Slot::factory(PinPolicy::Once),
        Slot::factory(PinPolicy::Once),
        Slot::factory(PinPolicy::Once),
        Slot::factory(PinPolicy::Once),
        Slot::factory(PinPolicy::Once),
        Slot::factory(PinPolicy::Once),
        Slot::factory(PinPolicy::Once),
        Slot::factory(PinPolicy::Once),
        Slot::factory(PinPolicy::Once),
        Slot::factory(PinPolicy::Once),
        Slot::factory(PinPolicy::Once),
        Slot::factory(PinPolicy::Once),
        Slot::factory(PinPolicy::Once),
        Slot::factory(PinPolicy::Once),
        Slot::factory(PinPolicy::Once),
        Slot::factory(PinPolicy::Once),
        Slot::factory(PinPolicy::Once),
        Slot::factory(PinPolicy::Once),
        Slot::factory(PinPolicy::Once),
    ]
}

/// The factory PIN policy of the slot at `index`: `ALWAYS` for 9C (index 1),
/// `NEVER` for 9E (index 3) and `ONCE` for every other slot — the per-slot
/// column of [`factory_slots`], exposed so GET METADATA can report whether a
/// slot still holds its factory policies.
pub(crate) const fn factory_pin_policy(index: usize) -> PinPolicy {
    match index {
        1 => PinPolicy::Always,
        3 => PinPolicy::Never,
        _ => PinPolicy::Once,
    }
}

/// Map a key reference to its table index.
///
/// `9A`/`9C`/`9D`/`9E` are table indices `0`..=`3`; retired `n` (key ref
/// `81 + n`) is table index `3 + n`, so key refs `82`..=`95` are indices
/// `4`..=`23`. Everything else — `9B` (management), `F9` (attestation), the
/// vendor-extension references, the PIN references — is not a slot.
pub(crate) const fn slot_index(key_ref: u8) -> Option<usize> {
    match key_ref {
        0x9A => Some(0),
        0x9C => Some(1),
        0x9D => Some(2),
        0x9E => Some(3),
        0x82..=0x95 => Some((key_ref - 0x82 + 4) as usize),
        _ => None,
    }
}

impl PivApplet {
    /// The management gate: the 9B session must be unlocked.
    ///
    /// A read-only consultation of [`MgmtKey::unlocked`](crate::management)
    /// — the 9B exchange itself stays in GENERAL AUTHENTICATE. Answers
    /// [`SW_SECURITY_NOT_SATISFIED`].
    ///
    /// Consulted by the key-slot commands (GENERATE, IMPORT, MOVE KEY) and
    /// PUT DATA.
    pub(crate) fn management_unlocked(&self) -> Result<(), u16> {
        if self.mgmt.unlocked() {
            Ok(())
        } else {
            Err(SW_SECURITY_NOT_SATISFIED)
        }
    }

    /// The slot's PIN gate: enforce the slot's PIN policy.
    ///
    /// `NEVER` is ungated; `ONCE` needs the PIN verified in this session;
    /// `ALWAYS` needs the PIN verified and this APDU to be the one right
    /// after the successful VERIFY (the [`PivApplet::pin_always_armed`]
    /// latch, which the dispatch consumes with this APDU). A
    /// not-satisfied policy answers [`SW_SECURITY_STATUS_NOT_SATISFIED`].
    /// Slots never hold the `DEFAULT` policy — GENERATE KEY always stores
    /// one of the three concrete values — so `DEFAULT` is unreachable here.
    pub(crate) fn slot_pin_gate(&self, slot: &Slot) -> Result<(), u16> {
        let satisfied = match slot.pin_policy {
            PinPolicy::Never => true,
            PinPolicy::Once => self.pin.verified,
            PinPolicy::Always => self.pin.verified && self.pin_always_armed,
            PinPolicy::Default => unreachable!("slots never hold the DEFAULT policy"),
        };
        if satisfied {
            Ok(())
        } else {
            Err(SW_SECURITY_STATUS_NOT_SATISFIED)
        }
    }

    /// The factory PIN policy of the slot at `index`: `NEVER` for 9E,
    /// `ALWAYS` for 9C, `ONCE` for every other slot — the same table
    /// `factory_slots` lays out.
    pub(crate) const fn factory_pin_policy(index: usize) -> PinPolicy {
        match index {
            3 => PinPolicy::Never,
            1 => PinPolicy::Always,
            _ => PinPolicy::Once,
        }
    }
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use super::*;
    use crate::PivApplet;
    use crate::constants::{
        AID_FULL, SW_CONDITIONS_NOT_SATISFIED, SW_INCORRECT_P1P2, SW_OK,
        SW_SECURITY_STATUS_NOT_SATISFIED, SW_WRONG_DATA,
    };
    use crate::general_auth::tests::mgmt_handshake;

    /// A case-1 GA APDU: `00 87 00 <p2>`, the shape the host's
    /// `general_auth` builders emit when there is no payload yet.
    fn ga_apdu(p2: u8) -> Vec<u8> {
        vec![0x00, 0x87, 0x00, p2]
    }

    /// The host's VERIFY: `00 20 00 80` with the PIN 0xFF-padded to the
    /// 8-byte field, as the host's `verify_pin` builder emits it.
    fn verify_pin(pin: &[u8]) -> Vec<u8> {
        let mut body = [0xFFu8; 8];
        body[..pin.len()].copy_from_slice(pin);
        let mut apdu = vec![0x00, 0x20, 0x00, 0x80, 0x08];
        apdu.extend_from_slice(&body);
        apdu
    }

    #[test]
    fn factory_slot_table_has_the_plan_policies() {
        let applet = PivApplet::new();
        // 9A, 9C, 9D, 9E: once, always, once, never.
        assert_eq!(applet.slots[0].pin_policy, PinPolicy::Once);
        assert_eq!(applet.slots[1].pin_policy, PinPolicy::Always);
        assert_eq!(applet.slots[2].pin_policy, PinPolicy::Once);
        assert_eq!(applet.slots[3].pin_policy, PinPolicy::Never);
        // All 20 retired slots: once.
        for slot in &applet.slots[4..] {
            assert_eq!(slot.pin_policy, PinPolicy::Once);
        }
    }

    #[test]
    fn factory_pin_policy_matches_the_table() {
        let slots = factory_slots();
        for (index, slot) in slots.iter().enumerate() {
            assert_eq!(slot.pin_policy, factory_pin_policy(index));
        }
    }

    #[test]
    fn factory_slots_are_empty() {
        let applet = PivApplet::new();
        for slot in &applet.slots {
            assert!(slot.key.is_none());
            assert!(slot.cert.is_none());
            assert!(!slot.imported);
            assert_eq!(slot.touch_policy, 0);
        }
    }

    #[test]
    fn slot_index_maps_the_slot_refs_only() {
        assert_eq!(slot_index(0x9A), Some(0));
        assert_eq!(slot_index(0x9C), Some(1));
        assert_eq!(slot_index(0x9D), Some(2));
        assert_eq!(slot_index(0x9E), Some(3));
        assert_eq!(slot_index(0x82), Some(4));
        assert_eq!(slot_index(0x95), Some(23));
        for n in 1..=20usize {
            assert_eq!(slot_index(0x81 + n as u8), Some(3 + n));
        }
        // Not slots: the PIN/PUK refs, the management key, the
        // attestation reference, the vendor-extension references,
        // `Retired(0)`, and everything above the retired range.
        for ref_ in [
            0x80u8, 0x81u8, 0x96u8, 0x9Bu8, 0xE0u8, 0xE1u8, 0xF9u8, 0x00u8,
        ] {
            assert_eq!(slot_index(ref_), None, "{ref_:02X}");
        }
    }

    #[test]
    fn management_gate_answers_6982_until_unlocked() {
        let mut applet = PivApplet::new();
        assert_eq!(applet.management_unlocked(), Err(SW_SECURITY_NOT_SATISFIED));
        mgmt_handshake(&mut applet);
        assert!(applet.management_unlocked().is_ok());
        // A witness request re-locks the session — the gate locks with it.
        let r = applet.process(&[0x00, 0x87, 0x03, 0x9B, 0x04, 0x7C, 0x02, 0x80, 0x00, 0x00]);
        assert_eq!(r.sw, SW_OK);
        assert_eq!(applet.management_unlocked(), Err(SW_SECURITY_NOT_SATISFIED));
    }

    #[test]
    fn once_policy_gates_on_the_pin_session_flag() {
        let mut applet = PivApplet::new();
        // 9A is ONCE: locked before the PIN is verified...
        assert_eq!(
            applet.slot_pin_gate(&applet.slots[0]),
            Err(SW_SECURITY_STATUS_NOT_SATISFIED)
        );
        // ...and open after.
        let r = applet.process(&verify_pin(b"123456"));
        assert_eq!(r.sw, SW_OK);
        assert!(applet.slot_pin_gate(&applet.slots[0]).is_ok());
    }

    #[test]
    fn always_policy_needs_the_arm_after_verify() {
        let mut applet = PivApplet::new();
        // Locked before the PIN is verified...
        assert_eq!(
            applet.slot_pin_gate(&applet.slots[1]),
            Err(SW_SECURITY_STATUS_NOT_SATISFIED)
        );
        // ...and the APDU right after a successful VERIFY is the one that
        // gets through: the latch is set by the VERIFY and still set when
        // this slot GA runs.
        let r = applet.process(&verify_pin(b"123456"));
        assert_eq!(r.sw, SW_OK);
        let r = applet.process(&ga_apdu(0x9C));
        assert_eq!(r.sw, SW_INCORRECT_P1P2, "arm survives the VERIFY");
        // The arm is consumed by that APDU: the next one is gated again
        // even though the PIN is still verified.
        let r = applet.process(&ga_apdu(0x9C));
        assert_eq!(r.sw, SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    #[test]
    fn never_policy_is_ungated() {
        let mut applet = PivApplet::new();
        // 9E is NEVER: no PIN, no arm, always open.
        assert!(applet.slot_pin_gate(&applet.slots[3]).is_ok());
        let r = applet.process(&ga_apdu(0x9E));
        assert_eq!(r.sw, SW_INCORRECT_P1P2);
    }

    #[test]
    fn retired_slots_are_gated_by_their_own_policy() {
        let mut applet = PivApplet::new();
        // Retired 1 (82) and retired 20 (95) are ONCE.
        for (ref_, index) in [(0x82u8, 4usize), (0x95u8, 23usize)] {
            assert_eq!(slot_index(ref_), Some(index));
            assert_eq!(
                applet.process(&ga_apdu(ref_)).sw,
                SW_SECURITY_STATUS_NOT_SATISFIED
            );
        }
        let r = applet.process(&verify_pin(b"123456"));
        assert_eq!(r.sw, SW_OK);
        assert_eq!(applet.process(&ga_apdu(0x82)).sw, SW_INCORRECT_P1P2);
        assert_eq!(applet.process(&ga_apdu(0x95)).sw, SW_INCORRECT_P1P2);
    }

    #[test]
    fn the_arm_is_set_only_by_a_successful_verify() {
        let mut applet = PivApplet::new();
        // A fresh applet has no arm.
        assert!(!applet.pin_always_armed);
        // A wrong PIN does not set it...
        let r = applet.process(&verify_pin(b"000000"));
        assert_eq!(r.sw, 0x63C4);
        assert!(!applet.pin_always_armed);
        // ...nor does a status query, even though both can answer 9000.
        let r = applet.process(&[0x00, 0x20, 0x00, 0x80]);
        assert_eq!(r.sw, 0x63C4);
        assert!(!applet.pin_always_armed);
        // A successful PIN presentation does.
        let r = applet.process(&verify_pin(b"123456"));
        assert_eq!(r.sw, SW_OK);
        assert!(applet.pin_always_armed);
    }

    #[test]
    fn a_wrong_pin_does_not_arm_the_latch() {
        let mut applet = PivApplet::new();
        // One burned try (5 -> 4).
        let r = applet.process(&verify_pin(b"000000"));
        assert_eq!(r.sw, 0x63C4);
        assert!(!applet.pin_always_armed);
        let r = applet.process(&ga_apdu(0x9C));
        assert_eq!(r.sw, SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    #[test]
    fn a_stray_get_response_consumes_the_arm() {
        let mut applet = PivApplet::new();
        // A stray GET RESPONSE with nothing pending is not a continuation
        // of any command: it is a new APDU and consumes the arm.
        let r = applet.process(&verify_pin(b"123456"));
        assert_eq!(r.sw, SW_OK);
        let r = applet.process(&[0x00, 0xC0, 0x00, 0x00]);
        assert_eq!(r.sw, SW_CONDITIONS_NOT_SATISFIED);
        assert!(!applet.pin_always_armed);
        // And the ALWAYS slot is gated.
        let r = applet.process(&ga_apdu(0x9C));
        assert_eq!(r.sw, SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    #[test]
    fn a_real_continuation_does_not_consume_the_arm() {
        let mut applet = PivApplet::new();
        // A SELECT with Le=5 truncates the 19-byte property template and
        // stashes the tail for a GET RESPONSE.
        let mut select = vec![0x00, 0xA4, 0x04, 0x0B, 0x0B];
        select.extend_from_slice(&AID_FULL);
        select.push(0x05);
        let first = applet.process(&select);
        assert_eq!(first.sw, 0x610E); // 19 - 5 = 14 remain
        // A successful VERIFY arms the latch... The GET RESPONSE is a
        // continuation of the SELECT, not a new command: it must not
        // consume the arm.
        let r = applet.process(&verify_pin(b"123456"));
        assert_eq!(r.sw, SW_OK);
        let rest = applet.process(&[0x00, 0xC0, 0x00, 0x00, 0x00]);
        assert_eq!(rest.data.len(), 14);
        assert_eq!(rest.sw, SW_OK);
        // The arm survives: the ALWAYS slot is still open.
        let r = applet.process(&ga_apdu(0x9C));
        assert_eq!(r.sw, SW_INCORRECT_P1P2);
        // A stray GET RESPONSE with nothing pending is not a continuation:
        // it is a new command, and the 9C GA after it is gated again.
        let r = applet.process(&[0x00, 0xC0, 0x00, 0x00, 0x00]);
        assert_eq!(r.sw, SW_CONDITIONS_NOT_SATISFIED);
        let r = applet.process(&ga_apdu(0x9C));
        assert_eq!(r.sw, SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    #[test]
    fn non_slot_p2s_keep_their_answers() {
        let mut applet = PivApplet::new();
        // 9B: the management path — a bare APDU carries no witness member,
        // the shape is refused.
        let r = applet.process(&[0x00, 0x87, 0x03, 0x9B]);
        assert_eq!(r.sw, SW_WRONG_DATA);
        // The vendor-extension references are not slots: refused, and
        // ungated (no PIN needed).
        for p2 in [0xE0u8, 0xE1u8, 0xF9u8] {
            let r = applet.process(&ga_apdu(p2));
            assert_eq!(r.sw, SW_INCORRECT_P1P2);
        }
    }
}
