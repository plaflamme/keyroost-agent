//! The key-slot key commands: GENERATE ASYMMETRIC KEY PAIR (`0x47`) and
//! IMPORT ASYMMETRIC KEY (`0x86`), both P-256.
//!
//! Both commands need the 9B management session unlocked and both replace
//! what the slot holds: the key is overwritten, the requested policies
//! (a `DEFAULT` policy restores the slot's factory policy, an absent one
//! keeps what the slot had) are applied and the slot certificate is
//! cleared — the old one no longer matches the new key.
//!
//! GENERATE answers the new public point as a `7F 49 86 <point>` template
//! (the shape the host's `parse_public_key` reads); the host cannot know
//! a key it did not choose. IMPORT answers bare `9000` — the host already
//! knows the key it sent.
//!
//! The two control bodies share one member grammar: ordered TLVs, each
//! member at most once, in any order — a required member (the `80`
//! algorithm for GENERATE, the `06` scalar for IMPORT) and optional
//! `AA 01 <pin policy>` and `AB 01 <touch policy>` members, a broken
//! structure or an unknown or repeated member refusing the command with
//! `6A86`.

use p256::SecretKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use zeroize::Zeroizing;

use keyroost_piv::{KeyAlg, PinPolicy, TouchPolicy};

use crate::Response;
use crate::constants::{
    SW_CLA_NOT_SUPPORTED, SW_INCORRECT_P1P2, SW_OK, SW_WRONG_DATA, SW_WRONG_LENGTH,
};
use crate::data::push_tlv;
use crate::slot::{SlotKey, slot_index};
use crate::{PivApplet, apdu_lc_body};

/// The P-256 group order `n`, big endian. The largest scalar the IMPORT
/// command will accept is `n - 1`.
const P256_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF4, 0xB9, 0xF2, 0xF1, 0x3B, 0xD3, 0xB2, 0xDC,
];

impl PivApplet {
    /// GENERATE ASYMMETRIC KEY PAIR (`0x47`): the host's `generate_key`
    /// APDU, `00 47 00 <slot> Lc AC <len> 80 01 <alg> [AA 01 <pin>]
    /// [AB 01 <touch>]`, case 4 with `Le 0x00`.
    ///
    /// The card generates the P-256 key with `OsRng`, stores the scalar
    /// (origin: on-card) and answers the public point. A slot that already
    /// holds a key is regenerated — its key and certificate are replaced
    /// and an absent policy request keeps the slot's current policy.
    pub(crate) fn process_generate_key_pair(&mut self, apdu: &[u8]) -> Response {
        let [cla, _ins, p1, p2, _rest @ ..] = apdu else {
            return Response::sw(SW_WRONG_LENGTH);
        };
        if cla & 0x90 != 0 {
            return Response::sw(SW_CLA_NOT_SUPPORTED);
        }
        if let Err(sw) = self.management_unlocked() {
            return Response::sw(sw);
        }
        if *p1 != 0x00 {
            return Response::sw(SW_INCORRECT_P1P2);
        }
        let index = match slot_index(*p2) {
            Some(index) => index,
            None => return Response::sw(SW_INCORRECT_P1P2),
        };
        let body = match apdu_lc_body(apdu) {
            Ok((_, body)) => body,
            Err(()) => return Response::sw(SW_WRONG_LENGTH),
        };
        // Unwrap the `AC` control-reference template.
        let control = match body {
            [0xAC, len, control @ ..] if usize::from(*len) == control.len() => control,
            _ => return Response::sw(SW_WRONG_DATA),
        };
        let (alg, pin_policy, touch_policy) = match parse_control(control) {
            Ok(parsed) => parsed,
            Err(()) => return Response::sw(SW_WRONG_DATA),
        };
        if alg != KeyAlg::EccP256 {
            return Response::sw(SW_WRONG_DATA);
        }

        let key = SecretKey::random(&mut rand_core::OsRng);
        let point = key.public_key().to_encoded_point(false);
        let secret = Zeroizing::new(key.to_bytes().into());
        self.commit_slot_key(index, secret, false, pin_policy, touch_policy);

        let mut inner = Vec::with_capacity(2 + 65);
        push_tlv(&mut inner, &[0x86], point.as_bytes());
        let mut data = Vec::with_capacity(3 + inner.len());
        push_tlv(&mut data, &[0x7F, 0x49], &inner);
        Response::ok(data)
    }

    /// IMPORT ASYMMETRIC KEY (`0x86`): the host's
    /// `ykpriv`/`import` APDU, `00 86 <alg> <slot> Lc 06 20 <scalar>
    /// [AA 01 <pin>] [AB 01 <touch>]`, case 3 — no `Le`, the host keeps
    /// the key it sends and answers are bare `9000`.
    ///
    /// The scalar must be a 32-byte big-endian P-256 secret in
    /// `1..=n-1`; anything else refuses the command without touching the
    /// slot.
    pub(crate) fn process_import_key(&mut self, apdu: &[u8]) -> Response {
        let [cla, _ins, p1, p2, _rest @ ..] = apdu else {
            return Response::sw(SW_WRONG_LENGTH);
        };
        if cla & 0x90 != 0 {
            return Response::sw(SW_CLA_NOT_SUPPORTED);
        }
        if let Err(sw) = self.management_unlocked() {
            return Response::sw(sw);
        }
        let index = match slot_index(*p2) {
            Some(index) => index,
            None => return Response::sw(SW_INCORRECT_P1P2),
        };
        if KeyAlg::from_id(*p1) != Some(KeyAlg::EccP256) {
            return Response::sw(SW_WRONG_DATA);
        }
        let body = match apdu_lc_body(apdu) {
            Ok((_, body)) => body,
            Err(()) => return Response::sw(SW_WRONG_LENGTH),
        };
        let import = match parse_import(body) {
            Ok(import) => import,
            Err(()) => return Response::sw(SW_WRONG_DATA),
        };

        // The scalar must be the big-endian encoding of a value in
        // 1..=n-1. The range check precedes `from_bytes` — it would reduce
        // `n` and above modulo `n` instead of refusing them.
        if import.scalar == [0u8; 32] || import.scalar >= P256_ORDER {
            return Response::sw(SW_WRONG_DATA);
        }
        let key = match SecretKey::from_bytes(&import.scalar.into()) {
            Ok(key) => key,
            Err(_) => return Response::sw(SW_WRONG_DATA),
        };
        let secret = Zeroizing::new(key.to_bytes().into());
        self.commit_slot_key(index, secret, true, import.pin_policy, import.touch_policy);
        Response::sw(SW_OK)
    }
}

/// The control-reference template of a GENERATE ASYMMETRIC KEY PAIR
/// command: a required `80 01 <algorithm>` member and optional `AA 01
/// <pin policy>` / `AB 01 <touch policy>` members, in any order, each at
/// most once.
fn parse_control(control: &[u8]) -> Result<(KeyAlg, Option<PinPolicy>, Option<TouchPolicy>), ()> {
    let mut alg = None;
    let mut pin_policy = None;
    let mut touch_policy = None;
    walk_tlvs(control, |tag, value| {
        match tag {
            0x80 if alg.is_none() => alg = Some(parse_alg(value)?),
            0xAA if pin_policy.is_none() => pin_policy = Some(parse_pin_policy(value)?),
            0xAB if touch_policy.is_none() => touch_policy = Some(parse_touch_policy(value)?),
            _ => return Err(()),
        }
        Ok(())
    })?;
    Ok((alg.ok_or(())?, pin_policy, touch_policy))
}

/// The body of an IMPORT ASYMMETRIC KEY command, EC branches: a required
/// `06 20 <scalar>` member and optional `AA` / `AB` policy members, in any
/// order, each at most once.
fn parse_import(body: &[u8]) -> Result<ImportKey, ()> {
    let mut scalar = None;
    let mut pin_policy = None;
    let mut touch_policy = None;
    walk_tlvs(body, |tag, value| {
        match tag {
            0x06 if scalar.is_none() => scalar = Some(parse_scalar(value)?),
            0xAA if pin_policy.is_none() => pin_policy = Some(parse_pin_policy(value)?),
            0xAB if touch_policy.is_none() => touch_policy = Some(parse_touch_policy(value)?),
            _ => return Err(()),
        }
        Ok(())
    })?;
    Ok(ImportKey {
        scalar: scalar.ok_or(())?,
        pin_policy,
        touch_policy,
    })
}

struct ImportKey {
    scalar: [u8; 32],
    pin_policy: Option<PinPolicy>,
    touch_policy: Option<TouchPolicy>,
}

/// Walk the ordered TLV members of `rest` from the front, calling `f` for
/// each: a broken member (no length, a value that overruns the input) or a
/// member `f` rejects ends the walk with `Err(())`.
fn walk_tlvs(rest: &[u8], mut f: impl FnMut(u8, &[u8]) -> Result<(), ()>) -> Result<(), ()> {
    let mut rest = rest;
    while !rest.is_empty() {
        let (tag, value, next) = match next_tlv(rest) {
            Some(tlv) => tlv,
            None => return Err(()),
        };
        f(tag, value)?;
        rest = next;
    }
    Ok(())
}

/// The next TLV member at the front of `rest` — `(tag, value, remainder)`
/// — or `None` when the structure is broken.
fn next_tlv(rest: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (tag, rest) = rest.split_first()?;
    let (length, rest) = rest.split_first()?;
    let (value, next) = rest.split_at_checked(usize::from(*length))?;
    Some((*tag, value, next))
}

/// A `80 01 <id>` algorithm member.
fn parse_alg(value: &[u8]) -> Result<KeyAlg, ()> {
    let [id] = value else {
        return Err(());
    };
    KeyAlg::from_id(*id).ok_or(())
}

/// An `AA 01 <id>` pin-policy member.
fn parse_pin_policy(value: &[u8]) -> Result<PinPolicy, ()> {
    let [id] = value else {
        return Err(());
    };
    PinPolicy::from_id(*id).ok_or(())
}

/// An `AB 01 <id>` touch-policy member.
fn parse_touch_policy(value: &[u8]) -> Result<TouchPolicy, ()> {
    let [id] = value else {
        return Err(());
    };
    TouchPolicy::from_id(*id).ok_or(())
}

/// A `06 20 <scalar>` member: exactly the 32-byte big-endian secret.
fn parse_scalar(value: &[u8]) -> Result<[u8; 32], ()> {
    value.try_into().map_err(|_| ())
}

impl PivApplet {
    /// Commit a freshly generated or imported P-256 key to the slot at
    /// `index`: replace the key material, record the origin, apply the
    /// requested policies (a `DEFAULT` pin policy restores the slot's
    /// factory policy, an absent request keeps what the slot had) and
    /// clear the slot certificate (the R5 decision: a replaced key
    /// invalidates the old certificate).
    fn commit_slot_key(
        &mut self,
        index: usize,
        secret: Zeroizing<[u8; 32]>,
        imported: bool,
        pin_policy: Option<PinPolicy>,
        touch_policy: Option<TouchPolicy>,
    ) {
        let slot = &mut self.slots[index];
        slot.key = Some(SlotKey {
            alg: KeyAlg::EccP256,
            secret,
        });
        slot.imported = imported;
        slot.pin_policy = match pin_policy {
            Some(PinPolicy::Default) => Self::factory_pin_policy(index),
            Some(policy) => policy,
            None => slot.pin_policy,
        };
        slot.touch_policy = match touch_policy {
            Some(policy) => policy.id(),
            None => slot.touch_policy,
        };
        slot.cert = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{INS_IMPORT_ASYM, SW_SECURITY_NOT_SATISFIED};
    use crate::general_auth::tests::mgmt_handshake;
    use keyroost_piv::{
        CertInfo, PublicKey, SW_NOT_FOUND, Slot, encode_certificate, generate_key, get_data,
        parse_public_key, put_data,
    };
    use p256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
    use p256::ecdsa::{SigningKey, VerifyingKey};

    /// A management-unlocked applet: the factory 3DES handshake ran, the
    /// 9B session is unlocked.
    fn unlocked() -> PivApplet {
        let mut app = PivApplet::new();
        mgmt_handshake(&mut app);
        app
    }

    /// The host's GENERATE ASYMMETRIC KEY PAIR APDU for `slot`; a
    /// `DEFAULT` policy request is omitted, exactly as the host builds it.
    fn gen_apdu(slot: Slot) -> Vec<u8> {
        generate_key(
            slot,
            KeyAlg::EccP256.id(),
            PinPolicy::Default,
            TouchPolicy::Default,
        )
    }

    /// The host's `generate_key` APDU with explicit policies.
    fn gen_policies_apdu(slot: Slot, pin: PinPolicy, touch: TouchPolicy) -> Vec<u8> {
        generate_key(slot, KeyAlg::EccP256.id(), pin, touch)
    }

    /// A GENERATE APDU with a raw control-reference template (the
    /// broken-structure cases the host builder cannot express).
    fn gen_control_apdu(slot: Slot, control: &[u8]) -> Vec<u8> {
        let mut data = Vec::with_capacity(control.len() + 3);
        data.extend_from_slice(&[0xAC, control.len() as u8]);
        data.extend_from_slice(control);
        let mut apdu = vec![0x00, 0x47, 0x00, slot.key_ref(), data.len() as u8];
        apdu.extend_from_slice(&data);
        apdu.push(0x00);
        apdu
    }

    /// A raw GENERATE APDU with an arbitrary P2 (slot reference).
    fn gen_raw_p2(p2: u8) -> Vec<u8> {
        vec![0x00, 0x47, 0x00, p2, 0x06, 0x80, 0x01, 0x11, 0x00]
    }

    /// An IMPORT body: `06 20 <scalar>` plus optional `AA`/`AB` members.
    fn ec_body(scalar: &[u8; 32], pin: Option<u8>, touch: Option<u8>) -> Vec<u8> {
        let mut body = vec![0x06, 0x20];
        body.extend_from_slice(scalar);
        if let Some(pin) = pin {
            body.extend_from_slice(&[0xAA, 0x01, pin]);
        }
        if let Some(touch) = touch {
            body.extend_from_slice(&[0xAB, 0x01, touch]);
        }
        body
    }

    /// A raw IMPORT ASYMMETRIC KEY APDU.
    fn import_apdu(alg: u8, slot: u8, body: &[u8]) -> Vec<u8> {
        let mut apdu = vec![0x00, INS_IMPORT_ASYM, alg, slot, body.len() as u8];
        apdu.extend_from_slice(body);
        apdu
    }

    fn fixed_scalar() -> [u8; 32] {
        let mut scalar = [0x2B; 32];
        scalar[31] = 0x01;
        scalar
    }

    /// The uncompressed point in the `7F 49 86` template.
    fn point_of(r: &Response) -> Vec<u8> {
        match parse_public_key(&r.data).expect("a well-formed public-key template") {
            PublicKey::Ecc { point } => point,
            other => panic!("expected an EC point, got {other:?}"),
        }
    }

    #[test]
    fn generate_answers_the_uncompressed_point() {
        let mut app = unlocked();
        let r = app.process(&gen_apdu(Slot::Authentication));
        assert_eq!(r.sw, SW_OK);
        let point = point_of(&r);
        assert_eq!(point.len(), 65);
        assert_eq!(point[0], 0x04);
        // A second generate on the same slot regenerates: a different point.
        let r2 = app.process(&gen_apdu(Slot::Authentication));
        assert_eq!(r2.sw, SW_OK);
        assert_ne!(point_of(&r2), point);
    }

    #[test]
    fn generate_refusals() {
        // The management gate is checked before anything else.
        let mut app = PivApplet::new();
        assert_eq!(
            app.process(&gen_apdu(Slot::Authentication)).sw,
            SW_SECURITY_NOT_SATISFIED
        );

        let mut app = unlocked();
        // A non-zero P1 is refused.
        let mut apdu = gen_apdu(Slot::Authentication);
        apdu[2] = 0x01;
        assert_eq!(app.process(&apdu).sw, SW_INCORRECT_P1P2);
        // Non-slot P2s: management, attestation, vendor-extension and PIN
        // references.
        for p2 in [0x9B, 0xF9, 0xE0, 0xE1, 0x80, 0x00u8] {
            assert_eq!(app.process(&gen_raw_p2(p2)).sw, SW_INCORRECT_P1P2);
        }
        // A non-PIV CLA.
        let mut apdu = gen_apdu(Slot::Authentication);
        apdu[0] = 0x80;
        assert_eq!(app.process(&apdu).sw, SW_CLA_NOT_SUPPORTED);
        // Broken control templates: missing or truncated `80`, trailing
        // garbage, repeated members, unknown members.
        let broken: [&[u8]; 8] = [
            &b""[..],
            &b"\x80"[..],
            &b"\x80\x01"[..],
            &b"\x80\x00"[..],
            &b"\x80\x01\x11\x11"[..],
            &b"\x80\x01\x11\x80\x01\x11"[..],
            &b"\x80\x01\x11\xAA\x01\x02\xAA\x01\x03"[..],
            &b"\x80\x01\x11\x88\x01\x00"[..],
        ];
        for control in broken {
            assert_eq!(
                app.process(&gen_control_apdu(Slot::Authentication, control))
                    .sw,
                SW_WRONG_DATA,
                "control template {control:02X?}",
            );
        }
        // An Lc overrun.
        let mut apdu = gen_apdu(Slot::Authentication);
        apdu[4] = 0x10;
        assert_eq!(app.process(&apdu).sw, SW_WRONG_LENGTH);
    }

    #[test]
    fn generate_applies_policies_and_origin() {
        let mut app = unlocked();
        let r = app.process(&gen_policies_apdu(
            Slot::Authentication,
            PinPolicy::Always,
            TouchPolicy::Always,
        ));
        assert_eq!(r.sw, SW_OK);
        let slot = &app.slots[0];
        assert!(slot.key.is_some());
        assert_eq!(slot.pin_policy, PinPolicy::Always);
        assert_eq!(slot.touch_policy, TouchPolicy::Always.id());
        assert!(!slot.imported);

        // Absent policy requests keep the slot's current policies.
        assert_eq!(app.process(&gen_apdu(Slot::Authentication)).sw, SW_OK);
        assert_eq!(app.slots[0].pin_policy, PinPolicy::Always);
        assert_eq!(app.slots[0].touch_policy, TouchPolicy::Always.id());

        // Explicit `DEFAULT` policies restore the slot's factory policies.
        let control = [0x80, 0x01, 0x11, 0xAA, 0x01, 0x00, 0xAB, 0x01, 0x00];
        assert_eq!(
            app.process(&gen_control_apdu(Slot::Authentication, &control))
                .sw,
            SW_OK
        );
        assert_eq!(app.slots[0].pin_policy, PinPolicy::Once); // 9A's factory
        assert_eq!(app.slots[0].touch_policy, 0); // factory: no touch policy
    }

    #[test]
    fn generate_replaces_the_key_and_clears_the_certificate() {
        let mut app = unlocked();
        let der: Vec<u8> = (0..100u32).map(|i| (i % 251) as u8).collect();
        let cert = encode_certificate(&der, CertInfo::Uncompressed);
        let tag = Slot::Authentication.cert_object_tag();
        assert_eq!(app.process(&put_data(&tag, &cert)).sw, SW_OK);

        let first = app.process(&gen_apdu(Slot::Authentication));
        assert_eq!(first.sw, SW_OK);
        let second = app.process(&gen_apdu(Slot::Authentication));
        assert_eq!(second.sw, SW_OK);
        assert_ne!(point_of(&second), point_of(&first));

        // R5: the certificate object is cleared on regenerate.
        assert_eq!(app.process(&get_data(&tag)).sw, SW_NOT_FOUND);
    }

    #[test]
    fn import_stores_the_scalar_with_origin_and_policies() {
        let mut app = unlocked();
        let scalar = fixed_scalar();
        let cert = encode_certificate(&[0x30, 0x82, 0x01, 0x00], CertInfo::Uncompressed);
        let tag = Slot::Authentication.cert_object_tag();
        assert_eq!(app.process(&put_data(&tag, &cert)).sw, SW_OK);

        let r = app.process(&import_apdu(
            0x11,
            0x9A,
            &ec_body(&scalar, Some(0x02), Some(0x02)),
        ));
        assert_eq!(r.sw, SW_OK);
        assert!(r.data.is_empty());

        let slot = &app.slots[0];
        let key = slot.key.as_ref().expect("the imported key");
        assert_eq!(key.alg, KeyAlg::EccP256);
        assert_eq!(&key.secret[..], &scalar[..]);
        assert!(slot.imported);
        assert_eq!(slot.pin_policy, PinPolicy::Once);
        assert_eq!(slot.touch_policy, 0x02);

        // R5: import clears the stored certificate.
        assert_eq!(app.process(&get_data(&tag)).sw, SW_NOT_FOUND);
    }

    #[test]
    fn import_refusals() {
        let scalar = fixed_scalar();
        // The management gate.
        let mut app = PivApplet::new();
        assert_eq!(
            app.process(&import_apdu(0x11, 0x9A, &ec_body(&scalar, None, None)))
                .sw,
            SW_SECURITY_NOT_SATISFIED
        );

        let mut app = unlocked();
        // Non-P-256 algorithm ids.
        for alg in [
            KeyAlg::Rsa3072.id(),
            KeyAlg::EccP384.id(),
            KeyAlg::Ed25519.id(),
        ] {
            assert_eq!(
                app.process(&import_apdu(alg, 0x9A, &ec_body(&scalar, None, None)))
                    .sw,
                SW_WRONG_DATA
            );
        }
        // Non-slot P2s.
        for p2 in [0x9B, 0xF9u8] {
            assert_eq!(
                app.process(&import_apdu(0x11, p2, &ec_body(&scalar, None, None)))
                    .sw,
                SW_INCORRECT_P1P2
            );
        }
        // A non-PIV CLA.
        let mut apdu = import_apdu(0x11, 0x9A, &ec_body(&scalar, None, None));
        apdu[0] = 0x80;
        assert_eq!(app.process(&apdu).sw, SW_CLA_NOT_SUPPORTED);
        // Broken bodies: no scalar, wrong lengths, trailing garbage,
        // repeated and unknown members.
        let mut with_trailing = ec_body(&scalar, None, None);
        with_trailing.push(0x11);
        let mut repeated = ec_body(&scalar, Some(0x02), None);
        repeated.extend_from_slice(&[0xAA, 0x01, 0x03]);
        let mut unknown = ec_body(&scalar, None, None);
        unknown.extend_from_slice(&[0x88, 0x01, 0x00]);
        let broken: [&[u8]; 7] = [
            b"",
            b"\xAA\x01\x02",
            b"\x06\x1F\x00",
            b"\x06\x21\x00",
            &with_trailing,
            &repeated,
            &unknown,
        ];
        for body in broken {
            assert_eq!(
                app.process(&import_apdu(0x11, 0x9A, body)).sw,
                SW_WRONG_DATA
            );
        }
        // An Lc overrun.
        let mut apdu = import_apdu(0x11, 0x9A, &ec_body(&scalar, None, None));
        apdu[4] = 0x30;
        assert_eq!(app.process(&apdu).sw, SW_WRONG_LENGTH);
        // Refusals leave the slot empty.
        assert!(app.slots[0].key.is_none());
    }

    #[test]
    fn import_rejects_out_of_range_scalars() {
        let mut app = unlocked();
        let zero = [0u8; 32];
        let order = P256_ORDER;
        let mut above = P256_ORDER;
        above[31] += 1;
        for scalar in [zero, order, above] {
            let r = app.process(&import_apdu(0x11, 0x9A, &ec_body(&scalar, None, None)));
            assert_eq!(r.sw, SW_WRONG_DATA, "{scalar:02X?}");
        }
        assert!(app.slots[0].key.is_none());
    }

    #[test]
    fn imported_key_signs_ecdsa_prehash() {
        let mut app = unlocked();
        let scalar = fixed_scalar();
        assert_eq!(
            app.process(&import_apdu(0x11, 0x9A, &ec_body(&scalar, None, None)))
                .sw,
            SW_OK
        );
        // The stored scalar is the ECDSA secret for the point the slot
        // reports: a host-side prehash sign/verify round trip closes it.
        let key = app.slots[0].key.as_ref().expect("the imported key");
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&key.secret[..]);
        let sk = SigningKey::from_bytes(&bytes.into()).expect("a valid scalar");
        let vk = VerifyingKey::from(&sk);
        let digest = [0x37; 32];
        let sig: p256::ecdsa::Signature = sk.sign_prehash(&digest).expect("an ECDSA signature");
        vk.verify_prehash(&digest, &sig).expect("a valid signature");
    }

    #[test]
    fn imported_key_signs_in_the_ga_path() {
        let mut app = PivApplet::new();
        mgmt_handshake(&mut app);
        let scalar = fixed_scalar();
        assert_eq!(
            app.process(&import_apdu(0x11, 0x9E, &ec_body(&scalar, None, None))).sw,
            SW_OK
        );
        // 9E is `NEVER` at the factory, so no VERIFY is needed: the GA
        // signing path signs the prehashed digest with the imported
        // scalar, verified under the point that scalar derives.
        let sk = SigningKey::from_slice(&scalar).expect("a valid scalar");
        let point = sk.verifying_key().to_encoded_point(false).as_bytes().to_vec();
        crate::general_auth::tests::card_signature(&mut app, 0x9E, &point, &[0x2B; 32]);
    }
}
