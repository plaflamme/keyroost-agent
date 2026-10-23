//! GET VERSION (0xFD), GET SERIAL (0xF8) and GET METADATA (0xF7): the
//! read-only Yubico extension commands.

use crate::constants::{
    DEFAULT_PIN_VALUE, DEFAULT_PUK_VALUE, SW_CLA_NOT_SUPPORTED, SW_INCORRECT_P1P2, VERSION,
};
use crate::slot::{factory_pin_policy, slot_index, SlotKey};
use crate::state::Pin;
use crate::{PivApplet, Response, apdu_le};
use keyroost_piv::{KeyAlg, SW_REFERENCE_NOT_FOUND};

impl PivApplet {
    /// GET VERSION (0xFD, Yubico extension): the applet version as three
    /// `major.minor.patch` bytes under `9000`.
    ///
    /// Like the other Yubico extensions this accepts both the ISO CLA and
    /// the Yubico proprietary one (`0xFF`); anything else is
    /// [`SW_CLA_NOT_SUPPORTED`]. A case-2 `Le` smaller than three re-enters
    /// the usual `61xx` / GET RESPONSE continuation.
    pub(crate) fn process_get_version(&mut self, apdu: &[u8]) -> Response {
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
    pub(crate) fn process_get_serial(&mut self, apdu: &[u8]) -> Response {
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
    ///
    /// The host's case-1 form (`00 F7 00 <ref>`, no body, no `Le`) asks for
    /// the reference's metadata; a case-2 `Le` re-enters the usual `61xx` /
    /// GET RESPONSE continuation. P1 must be `0x00` (the host builder always
    /// sends `0x00` — R4: anything else is [`SW_INCORRECT_P1P2`]).
    ///
    /// A key reference (`9A`/`9C`/`9D`/`9E`, retired `1..=20`) whose slot is
    /// empty answers [`SW_REFERENCE_NOT_FOUND`]; an occupied slot answers the
    /// flat TLVs the host's `parse_metadata` reads:
    ///
    /// - `01 <algorithm>` — the key's [`KeyAlg`] id (P-256 is `0x11`);
    /// - `02 <pin policy><touch policy>` — the slot's policies, the host's
    ///   [`keyroost_piv::PinPolicy`] / [`keyroost_piv::TouchPolicy`] ids;
    /// - `03 <origin>` — `0x01` generated on-card, `0x02` imported;
    /// - `04 <public key TLVs>` — the `7F49` inner TLVs the GENERATE response
    ///   carries (the `86` EC point for the P-256 keys);
    /// - `05 <is default>` — `1` while the slot still holds its factory
    ///   policies.
    ///
    /// The PIN/PUK references (`80`/`81`) answer `05 <is default>` — `1`
    /// while the stored value is the factory one — and `06
    /// <remaining><total>` retry counts in the host's byte order
    /// ([remaining][total], R2).
    pub(crate) fn process_get_metadata(&mut self, apdu: &[u8]) -> Response {
        let cla = apdu[0];
        if cla != 0x00 && cla != 0xFF {
            return Response::sw(SW_CLA_NOT_SUPPORTED);
        }
        if apdu[2] != 0x00 {
            return Response::sw(SW_INCORRECT_P1P2);
        }
        let le = match apdu_le(&apdu[4..]) {
            Ok(le) => le,
            Err(()) => return Response::sw(keyroost_piv::SW_WRONG_LENGTH),
        };
        let body = match apdu[3] {
            0x80 => self.pin_reference_metadata(&self.pin, &DEFAULT_PIN_VALUE),
            0x81 => self.pin_reference_metadata(&self.puk, &DEFAULT_PUK_VALUE),
            reference => match slot_index(reference) {
                Some(index) => match self.key_reference_metadata(index) {
                    Some(body) => body,
                    None => return Response::sw(SW_REFERENCE_NOT_FOUND),
                },
                None => return Response::sw(SW_INCORRECT_P1P2),
            },
        };
        self.split_for_le(body, le)
    }

    /// The flat metadata TLVs of the occupied key slot at `index`;
    /// `None` for an empty slot (the caller answers
    /// [`SW_REFERENCE_NOT_FOUND`]).
    fn key_reference_metadata(&self, index: usize) -> Option<Vec<u8>> {
        let slot = &self.slots[index];
        let key = slot.key.as_ref()?;
        // Only P-256 keys can be stored today, so the point always exists;
        // P-384/P-521 (T9) and the RSA keys (T10) add their encodings here.
        let point = ec_point(key)?;
        let is_default = slot.pin_policy == factory_pin_policy(index) && slot.touch_policy == 0;
        let mut body = Vec::new();
        body.extend_from_slice(&[0x01, 0x01, key.alg.id()]);
        body.extend_from_slice(&[0x02, 0x02, slot.pin_policy.id(), slot.touch_policy]);
        body.extend_from_slice(&[0x03, 0x01, if slot.imported { 0x02 } else { 0x01 }]);
        // The `7F49` inner TLVs: the `86` EC point, unwrapped from its
        // template exactly as the GENERATE response carries it.
        body.push(0x04);
        body.push((2 + point.len()) as u8);
        body.push(0x86);
        body.push(point.len() as u8);
        body.extend_from_slice(&point);
        body.extend_from_slice(&[0x05, 0x01, u8::from(is_default)]);
        Some(body)
    }

    /// The flat metadata TLVs of a PIN/PUK reference: `05 <is default>` and
    /// `06 <remaining><total>`.
    fn pin_reference_metadata(&self, reference: &Pin, factory: &[u8; 8]) -> Vec<u8> {
        let is_default = *reference.value == *factory;
        vec![
            0x05,
            0x01,
            u8::from(is_default),
            0x06,
            0x02,
            reference.tries,
            reference.max_tries,
        ]
    }
}

/// The uncompressed point of the slot key: the `86` TLV content the GENERATE
/// response and the metadata `04` member carry.
fn ec_point(key: &SlotKey) -> Option<Vec<u8>> {
    match key.alg {
        KeyAlg::EccP256 => {
            let signing = p256::ecdsa::SigningKey::from_slice(&key.secret[..]).ok()?;
            Some(signing.verifying_key().to_encoded_point(false).as_bytes().to_vec())
        }
        // P-384/P-521 land with T9, the RSA keys with T10.
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{DEFAULT_PIN_TRIES, DEFAULT_PUK_TRIES, DEFAULT_SERIAL};
    use crate::general_auth::tests::mgmt_handshake;
    use keyroost_piv::{
        KeyAlg, PinPolicy, Slot, TouchPolicy, change_reference, generate_key, get_metadata,
        parse_metadata, parse_public_key, verify_pin, PIN_REF_APPLICATION,
    };

    /// A management-unlocked applet: the factory 3DES handshake ran, the
    /// 9B session is unlocked.
    fn unlocked() -> PivApplet {
        let mut applet = PivApplet::new();
        mgmt_handshake(&mut applet);
        applet
    }

    /// GET METADATA through the host's case-1 builder, parsed with the
    /// host's `parse_metadata`.
    fn metadata(app: &mut PivApplet, reference: u8) -> keyroost_piv::Metadata {
        let resp = app.process(&get_metadata(reference));
        assert_eq!(resp.sw, keyroost_piv::SW_OK, "GET METADATA {reference:#04x}");
        parse_metadata(&resp.data).expect("a well-formed metadata response")
    }

    /// A raw IMPORT ASYMMETRIC KEY APDU (P1 the algorithm, P2 the slot, the
    /// `06` scalar body): the shape T6 pins for the host's import flow.
    fn imported_scalar_apdu(slot: u8) -> Vec<u8> {
        let scalar = [0x2Bu8; 32];
        let mut body = vec![0x06u8, 0x20u8];
        body.extend_from_slice(&scalar);
        let mut apdu = vec![0x00u8, 0x86, 0x11, slot, body.len() as u8];
        apdu.extend_from_slice(&body);
        apdu
    }

    #[test]
    fn get_version_answers_5_7_4() {
        let mut applet = PivApplet::new();
        // The host's case-2 form: `00 FD 00 00 00`.
        let resp = applet.process(&[0x00, 0xFD, 0x00, 0x00, 0x00]);
        assert_eq!(resp.data, [0x05, 0x07, 0x04]);
        assert_eq!(resp.sw, keyroost_piv::SW_OK);
    }

    #[test]
    fn get_version_case1_and_yubico_cla() {
        let mut applet = PivApplet::new();
        for apdu in [[0x00u8, 0xFD, 0x00, 0x00], [0xFF, 0xFD, 0x00, 0x00]] {
            let resp = applet.process(&apdu);
            assert_eq!(resp.data, [0x05, 0x07, 0x04]);
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
        assert_eq!(first.data, [0x05, 0x07]);
        assert_eq!(first.sw, 0x6101);
        let rest = applet.process(&[0x00, 0xC0, 0x00, 0x00, 0x00]);
        assert_eq!(rest.data, [0x04]);
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

    #[test]
    fn metadata_of_an_empty_key_slot_answers_reference_not_found() {
        let mut applet = PivApplet::new();
        for reference in [0x9A, 0x9C, 0x9D, 0x9E, 0x82, 0x95u8] {
            let resp = applet.process(&get_metadata(reference));
            assert_eq!(resp.data, Vec::new());
            assert_eq!(resp.sw, keyroost_piv::SW_REFERENCE_NOT_FOUND);
        }
    }

    #[test]
    fn pin_and_puk_metadata_report_the_factory_values() {
        let mut applet = PivApplet::new();
        let pin = metadata(&mut applet, 0x80);
        assert_eq!(pin.is_default, Some(true));
        assert_eq!(pin.retries, Some((DEFAULT_PIN_TRIES, DEFAULT_PIN_TRIES)));
        let puk = metadata(&mut applet, 0x81);
        assert_eq!(puk.is_default, Some(true));
        assert_eq!(puk.retries, Some((DEFAULT_PUK_TRIES, DEFAULT_PUK_TRIES)));
        // The key-reference fields stay empty on the PIN references.
        assert_eq!(pin.algorithm, None);
        assert_eq!(pin.policy, None);
        assert_eq!(pin.public_key, None);
    }

    #[test]
    fn pin_metadata_retries_move_with_a_burned_try() {
        let mut applet = PivApplet::new();
        // A wrong PIN burns one try.
        let resp = applet.process(&verify_pin(b"000000").unwrap());
        assert_eq!(resp.sw, 0x63C4);
        let pin = metadata(&mut applet, 0x80);
        assert_eq!(
            pin.retries,
            Some((DEFAULT_PIN_TRIES - 1, DEFAULT_PIN_TRIES))
        );
    }

    #[test]
    fn pin_metadata_is_default_flips_after_a_change() {
        let mut applet = PivApplet::new();
        let resp = applet
            .process(&change_reference(PIN_REF_APPLICATION, b"123456", b"654321").unwrap());
        assert_eq!(resp.sw, keyroost_piv::SW_OK);
        let pin = metadata(&mut applet, 0x80);
        assert_eq!(pin.is_default, Some(false));
        assert_eq!(pin.retries, Some((DEFAULT_PIN_TRIES, DEFAULT_PIN_TRIES)));
    }

    #[test]
    fn metadata_of_a_generated_key_reports_the_plan_fields() {
        let mut applet = unlocked();
        let generated = applet.process(&generate_key(
            Slot::Signature,
            KeyAlg::EccP256.id(),
            PinPolicy::Default,
            TouchPolicy::Default,
        ));
        assert_eq!(generated.sw, keyroost_piv::SW_OK);
        let announced = match parse_public_key(&generated.data).expect("the announced public key") {
            keyroost_piv::PublicKey::Ecc { point } => point,
            other => panic!("expected an EC point, got {other:?}"),
        };
        let md = metadata(&mut applet, 0x9C);
        assert_eq!(md.algorithm, Some(KeyAlg::EccP256.id()));
        // The host's `generate_key` omits the absent `AA`/`AB` members for
        // `Default` policies, and the applet keeps the current policies when
        // a member is absent: 9C stays at its factory `ALWAYS`.
        assert_eq!(
            md.policy,
            Some((PinPolicy::Always.id(), TouchPolicy::Default.id()))
        );
        assert_eq!(md.origin, Some(1));
        // Still at the factory policies, so the flag is set.
        assert_eq!(md.is_default, Some(true));
        // The public key is the `7F49` inner TLV: the announced `86` point.
        let expected: Vec<u8> = [0x86, 65]
            .iter()
            .copied()
            .chain(announced.iter().copied())
            .collect();
        assert_eq!(md.public_key, Some(expected));
    }

    #[test]
    fn metadata_is_default_tracks_the_factory_policies() {
        let mut applet = unlocked();
        // 9A is ONCE at the factory: generating it with `ONCE` back keeps
        // `is_default` set...
        let generated = applet.process(&generate_key(
            Slot::Authentication,
            KeyAlg::EccP256.id(),
            PinPolicy::Once,
            TouchPolicy::Default,
        ));
        assert_eq!(generated.sw, keyroost_piv::SW_OK);
        let md = metadata(&mut applet, 0x9A);
        assert_eq!(
            md.policy,
            Some((PinPolicy::Once.id(), TouchPolicy::Default.id()))
        );
        assert_eq!(md.is_default, Some(true));
        // ...and a non-factory policy clears it.
        let generated = applet.process(&generate_key(
            Slot::Authentication,
            KeyAlg::EccP256.id(),
            PinPolicy::Always,
            TouchPolicy::Default,
        ));
        assert_eq!(generated.sw, keyroost_piv::SW_OK);
        let md = metadata(&mut applet, 0x9A);
        assert_eq!(md.policy, Some((PinPolicy::Always.id(), TouchPolicy::Default.id())));
        assert_eq!(md.is_default, Some(false));
    }

    #[test]
    fn metadata_of_an_imported_key_reports_origin_imported() {
        let mut applet = unlocked();
        let resp = applet.process(&imported_scalar_apdu(0x9E));
        assert_eq!(resp.sw, keyroost_piv::SW_OK);
        let md = metadata(&mut applet, 0x9E);
        assert_eq!(md.algorithm, Some(KeyAlg::EccP256.id()));
        assert_eq!(md.origin, Some(2));
    }

    #[test]
    fn metadata_answers_6b00_for_a_nonzero_p1() {
        let mut applet = PivApplet::new();
        let resp = applet.process(&[0x00, 0xF7, 0x01, 0x80]);
        assert_eq!(resp.data, Vec::new());
        assert_eq!(resp.sw, SW_INCORRECT_P1P2);
    }

    #[test]
    fn metadata_answers_6b00_for_unknown_references() {
        let mut applet = PivApplet::new();
        for reference in [0x00u8, 0x58, 0x9B, 0xF9, 0xE0, 0xE1] {
            let resp = applet.process(&get_metadata(reference));
            assert_eq!(resp.data, Vec::new());
            assert_eq!(resp.sw, SW_INCORRECT_P1P2);
        }
    }

    #[test]
    fn metadata_rejects_other_clas() {
        let mut applet = PivApplet::new();
        let resp = applet.process(&[0x40, 0xF7, 0x00, 0x80]);
        assert_eq!(resp.data, Vec::new());
        assert_eq!(resp.sw, SW_CLA_NOT_SUPPORTED);
    }

    #[test]
    fn metadata_small_le_truncates_and_get_response_completes() {
        let mut applet = PivApplet::new();
        let full = applet.process(&get_metadata(0x80)).data;
        assert_eq!(full.len(), 7);
        let first = applet.process(&[0x00, 0xF7, 0x00, 0x80, 0x04]);
        assert_eq!(first.data, full[..4].to_vec());
        assert_eq!(first.sw, 0x6103);
        let rest = applet.process(&[0x00, 0xC0, 0x00, 0x00, 0x00]);
        assert_eq!(rest.data, full[4..].to_vec());
        assert_eq!(rest.sw, keyroost_piv::SW_OK);
    }
}
