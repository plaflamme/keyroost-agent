//! ATTEST (`0xF9`): the on-card attestation key and the self-signed
//! X.509 v3 certificates it mints.
//!
//! The card owns an attestation key at slot reference `F9` — a P-256 key
//! generated on-card at construction, never importable, never a slot of the
//! 24-slot table. It signs two kinds of certificate, both in the reference
//! applet's `writeAttestationCert` shape:
//!
//! - its own self-signed certificate, stored in the `70`-wrapped form the
//!   host reads back through GET DATA object `5FFF01` (the Yubico PIV
//!   Attestation Certificate),
//! - a certificate for a key slot's key, minted on demand by ATTEST: the
//!   slot's public key under the issuer "`PIVApplet` Attestation", signed by
//!   the `F9` key — the card's proof that the key it names was generated on
//!   the card.

use keyroost_piv::{KeyAlg, PublicKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::constants::{SW_CLA_NOT_SUPPORTED, SW_INCORRECT_P1P2, SW_WRONG_LENGTH, VERSION};
use crate::data::push_tlv;
use crate::slot::{SlotKey, slot_index};
use crate::{PivApplet, Response, apdu_lc_body, apdu_le};
use ecdsa::signature::hazmat::PrehashSigner;
use elliptic_curve::sec1::ToEncodedPoint;
use pkcs1::DecodeRsaPrivateKey;
use rsa::RsaPrivateKey;

/// The card's attestation state: the `F9` key's P-256 secret scalar and its
/// own self-signed certificate in the `70`-wrapped storage form.
pub(crate) struct Attestation {
    pub(crate) secret: Zeroizing<Vec<u8>>,
    pub(crate) cert: Option<Vec<u8>>,
}

/// The reference applet's issuer/subject common name.
const CN_STRING: &[u8] = b"PIVApplet Attestation";

/// The reference applet's fixed validity: 2018-01-01 to 2050-01-01.
const NOT_BEFORE: &[u8] = b"180101000000Z";
const NOT_AFTER: &[u8] = b"20500101000000Z";

/// The ecdsa-with-SHA-256 `AlgorithmIdentifier`: the OID alone, no parameters
/// (the reference writes the bare OID for EC signers).
const SIG_ALG_ECDSA_SHA256: &[u8] = &[
    0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02,
];

/// The Yubico firmware-version extension OID: 1.3.6.1.4.1.41482.3.3.
const OID_YUBICO_VERSION_EXT: &[u8] = &[
    0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xC4, 0x0A, 0x03, 0x03,
];

/// The Yubico key-policy extension OID: 1.3.6.1.4.1.41482.3.8 — the exact
/// content bytes the host's `parse_key_policy_extension` matches.
const OID_YUBICO_KEY_POLICY_EXT: &[u8] = &[
    0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xC4, 0x0A, 0x03, 0x08,
];

/// The CN attribute OID: 2.5.4.3.
const OID_CN: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03];

/// The `F9` attestation key's own key-policy extension bytes: the reference
/// applet's `F9` slot factory policy (PIN `ONCE`) and its hardcoded touch
/// byte (`NEVER`).
pub(crate) const F9_PIN_POLICY: u8 = 0x02;
pub(crate) const F9_TOUCH_POLICY: u8 = 0x01;

impl PivApplet {
    /// ATTEST (`0xF9`): `00 F9 <slot> 00 [Le]`, case 2. The card answers
    /// the self-signed X.509 certificate for the slot's key, signed by the
    /// `F9` attestation key — the reference applet's `writeAttestationCert`
    /// shape, bare DER with no TLV wrapper, split over `61xx` / GET
    /// RESPONSE when it does not fit the requested length.
    ///
    /// The target resolves through the 24-slot table — `9A`, `9C`, `9D`,
    /// `9E` and retired `82`..=`95`; `9B`, `F9` itself and the other
    /// non-slot references refuse with `6B00`. A target without a key
    /// refuses with the metadata's empty-slot word; the reference applet
    /// has no such check and would mint a keyless certificate.
    pub(crate) fn process_attest(&mut self, apdu: &[u8]) -> Response {
        let [cla, _ins, p1, p2, _rest @ ..] = apdu else {
            return Response::sw(SW_WRONG_LENGTH);
        };
        if cla & 0x90 != 0 {
            return Response::sw(SW_CLA_NOT_SUPPORTED);
        }
        if *p2 != 0x00 {
            return Response::sw(SW_INCORRECT_P1P2);
        }
        let Some(index) = slot_index(*p1) else { return Response::sw(SW_INCORRECT_P1P2) };
        let Some(key) = &self.slots[index].key else { return Response::sw(keyroost_piv::SW_REFERENCE_NOT_FOUND) };
        let pin_policy = self.slots[index].pin_policy;
        let touch_policy = self.slots[index].touch_policy;
        let Some((alg, public)) = target_public_key(key) else { return Response::sw(keyroost_piv::SW_REFERENCE_NOT_FOUND) };
        let subject = format!(" {p1:02X}");
        let Some(cert) = attestation_cert(
            &public,
            alg,
            &self.attestation.secret,
            Some(&subject),
            pin_policy.id(),
            touch_policy,
        ) else { return Response::sw(keyroost_piv::SW_CONDITIONS_NOT_SATISFIED) };
        let Ok((_lc, _body, tail)) = apdu_lc_body(apdu) else { return Response::sw(SW_WRONG_LENGTH) };
        let Ok(le) = apdu_le(tail) else { return Response::sw(SW_WRONG_LENGTH) };
        self.split_for_le(cert, le)
    }
}

/// The slot key's public material as the host's SPKI builder takes it: the
/// key algorithm and the `PublicKey` variant — the EC curve's uncompressed
/// point, or the RSA modulus and public exponent.
fn target_public_key(key: &SlotKey) -> Option<(KeyAlg, PublicKey)> {
    match key.alg {
        KeyAlg::EccP256 => {
            let signing = ecdsa::SigningKey::<p256::NistP256>::from_slice(&key.secret[..32]).ok()?;
            let point = signing.verifying_key().to_encoded_point(false).as_bytes().to_vec();
            Some((KeyAlg::EccP256, PublicKey::Ecc { point }))
        }
        KeyAlg::EccP384 => {
            let signing = ecdsa::SigningKey::<p384::NistP384>::from_slice(&key.secret[..48]).ok()?;
            let point = signing.verifying_key().to_encoded_point(false).as_bytes().to_vec();
            Some((KeyAlg::EccP384, PublicKey::Ecc { point }))
        }
        KeyAlg::EccP521 => {
            let secret =
                elliptic_curve::SecretKey::<p521::NistP521>::from_slice(&key.secret[..]).ok()?;
            let point = secret.public_key().to_encoded_point(false).as_bytes().to_vec();
            Some((KeyAlg::EccP521, PublicKey::Ecc { point }))
        }
        KeyAlg::Rsa1024 | KeyAlg::Rsa2048 | KeyAlg::Rsa3072 | KeyAlg::Rsa4096 => {
            use rsa::traits::PublicKeyParts;
            let rsa_key = RsaPrivateKey::from_pkcs1_der(key.secret.as_slice()).ok()?;
            let modulus = rsa_key.n().to_bytes_be();
            let exponent = rsa_key.e().to_bytes_be();
            Some((key.alg, PublicKey::Rsa { modulus, exponent }))
        }
        _ => None,
    }
}

/// Build the self-signed X.509 v3 attestation certificate: the reference
/// applet's `writeX509CertInfo` layout, signed by the `F9` attestation key
/// over SHA-256 of the TBS certificate.
///
/// `subject_suffix` is the `" <slot>"` CN suffix the reference applet
/// appends to the subject for slot targets (the issuer stays bare).
pub(crate) fn attestation_cert(
    public: &PublicKey,
    alg: KeyAlg,
    signer_secret: &[u8],
    subject_suffix: Option<&str>,
    pin_policy: u8,
    touch_policy: u8,
) -> Option<Vec<u8>> {
    let spki = keyroost_piv::spki::subject_public_key_info(public, alg).ok()?;

    let mut tbs = Vec::new();
    // Version: v3.
    tbs.extend_from_slice(&[0xA0, 0x03, 0x02, 0x01, 0x02]);
    // Serial: fresh random, top bit of the first byte cleared.
    let mut serial = [0u8; 16];
    getrandom::getrandom(&mut serial).ok()?;
    serial[0] &= 0x7F;
    push_tlv(&mut tbs, &[0x02], &serial);
    // Signature AlgorithmIdentifier: ecdsa-with-SHA-256.
    tbs.extend_from_slice(SIG_ALG_ECDSA_SHA256);
    // Issuer: CN "PIVApplet Attestation".
    push_cn(&mut tbs, CN_STRING);
    // Validity.
    let mut validity = Vec::new();
    push_tlv(&mut validity, &[0x17], NOT_BEFORE);
    push_tlv(&mut validity, &[0x18], NOT_AFTER);
    push_tlv(&mut tbs, &[0x30], &validity);
    // Subject: CN plus the slot suffix.
    let subject = match subject_suffix {
        Some(suffix) => format!("{}{}", String::from_utf8_lossy(CN_STRING), suffix),
        None => String::from_utf8_lossy(CN_STRING).into_owned(),
    };
    push_cn(&mut tbs, subject.as_bytes());
    // SubjectPublicKeyInfo.
    tbs.extend_from_slice(&spki);
    // Extensions: the Yubico firmware version and the slot's key policy.
    let mut exts = Vec::new();
    let mut version_ext = Vec::new();
    version_ext.extend_from_slice(OID_YUBICO_VERSION_EXT);
    push_tlv(&mut version_ext, &[0x04], &VERSION);
    push_tlv(&mut exts, &[0x30], &version_ext);
    let mut policy_ext = Vec::new();
    policy_ext.extend_from_slice(OID_YUBICO_KEY_POLICY_EXT);
    push_tlv(&mut policy_ext, &[0x04], &[pin_policy, touch_policy]);
    push_tlv(&mut exts, &[0x30], &policy_ext);
    let mut exts_seq = Vec::new();
    push_tlv(&mut exts_seq, &[0x30], &exts);
    push_tlv(&mut tbs, &[0xA3], &exts_seq);

    let tbs = {
        let mut wrapped = Vec::with_capacity(tbs.len() + 2);
        push_tlv(&mut wrapped, &[0x30], &tbs);
        wrapped
    };

    let signer = ecdsa::SigningKey::<p256::NistP256>::from_slice(signer_secret).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&tbs);
    let digest = hasher.finalize();
    // The annotation pins the `Signature<C>` impl: with the `der` feature
    // the `PrehashSigner` impl for `der::Signature<C>` is also in scope.
    let signature: ecdsa::Signature<p256::NistP256> = signer.sign_prehash(&digest).ok()?;
    let signature_bytes = signature.to_der().as_bytes().to_vec();

    let mut sig_content = vec![0u8]; // unused-bits byte
    sig_content.extend_from_slice(&signature_bytes);
    let mut sig_value = Vec::new();
    push_tlv(&mut sig_value, &[0x03], &sig_content);

    let mut cert = tbs;
    cert.extend_from_slice(SIG_ALG_ECDSA_SHA256);
    cert.extend_from_slice(&sig_value);

    let mut out = Vec::with_capacity(cert.len() + 2);
    push_tlv(&mut out, &[0x30], &cert);
    Some(out)
}

/// The Name of a single CN attribute: `SEQUENCE { SET { SEQUENCE { OID 2.5.4.3, UTF8STRING cn } } }`.
/// The Name of a single CN attribute: `SEQUENCE { SET { SEQUENCE { OID 2.5.4.3, UTF8STRING cn } } }`.
fn push_cn(out: &mut Vec<u8>, cn: &[u8]) {
    let mut atv = Vec::new();
    atv.extend_from_slice(OID_CN);
    push_tlv(&mut atv, &[0x0C], cn);
    let mut seq = Vec::new();
    push_tlv(&mut seq, &[0x30], &atv);
    let mut set = Vec::new();
    push_tlv(&mut set, &[0x31], &seq);
    push_tlv(out, &[0x30], &set);
}

/// A fresh attestation state: a new on-card P-256 key and its self-signed
/// certificate, the reference applet's `initAttestation` — minted
/// unconditionally at card construction, the key's origin being on-card by
/// construction.
pub(crate) fn fresh_attestation() -> Attestation {
    let secret = Zeroizing::new(
        elliptic_curve::SecretKey::<p256::NistP256>::random(&mut rand_core::OsRng)
            .to_bytes()
            .to_vec(),
    );
    let signing = ecdsa::SigningKey::<p256::NistP256>::from_slice(&secret)
        .expect("a fresh P-256 secret scalar is always a valid signing key");
    let point = signing.verifying_key().to_encoded_point(false).as_bytes().to_vec();
    let cert = attestation_cert(
        &PublicKey::Ecc { point },
        KeyAlg::EccP256,
        &secret,
        None,
        F9_PIN_POLICY,
        F9_TOUCH_POLICY,
    );
    let cert = cert.map(|der| {
        let mut wrapped = Vec::with_capacity(der.len() + 2);
        push_tlv(&mut wrapped, &[0x70], &der);
        wrapped
    });
    Attestation { secret, cert }
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use super::*;
    use crate::constants::SW_OK;
    use crate::general_auth::tests::mgmt_handshake;
    use ecdsa::signature::hazmat::PrehashVerifier;

    /// The point the GENERATE reply announced (the `86` member of the
    /// `7F49` template) from the reply's data field.
    fn announced_point(response: &Response) -> Vec<u8> {
        match keyroost_piv::parse_public_key(&response.data) {
            Ok(keyroost_piv::PublicKey::Ecc { point }) => point,
            other => panic!("the GENERATE reply is a public-key template: {other:?}"),
        }
    }

    #[test]
    fn attest_answers_a_certificate_for_a_generated_key() {
        let mut applet = PivApplet::new();
        mgmt_handshake(&mut applet);
        let apdu = keyroost_piv::generate_key(
            keyroost_piv::Slot::Authentication,
            keyroost_piv::KeyAlg::EccP256.id(),
            keyroost_piv::PinPolicy::Default,
            keyroost_piv::TouchPolicy::Default,
        );
        let response = applet.process(&apdu);
        assert_eq!(response.sw, SW_OK);
        let announced = announced_point(&response);

        // The host's builder is case 2 with Le 0x00: a certificate over
        // 256 bytes splits over 61xx / GET RESPONSE.
        let apdu = keyroost_piv::attest(0x9A);
        let first = applet.process(&apdu);
        let (cert_data, cert_sw) = if first.sw >> 8 == 0x61 {
            let remainder = applet.process(&[0x00, 0xC0, 0x00, 0x00]);
            let mut data = first.data;
            data.extend(remainder.data);
            (data, remainder.sw)
        } else {
            (first.data, first.sw)
        };
        assert_eq!(cert_sw, SW_OK, "ATTEST answers 9000 (sw 0x{cert_sw:04x})");

        // The host's own parser reads it back: the slot's P-256 point —
        // byte-identical to what GENERATE announced — and the key-policy
        // extension with the slot's policies (9A's factory: PIN ONCE, touch
        // the factory default).
        let (alg, point) = keyroost_piv::x509_parse::parse_certificate_public_key(&cert_data)
            .expect("the certificate parses");
        assert_eq!(alg, KeyAlg::EccP256);
        match point {
            keyroost_piv::PublicKey::Ecc { point } => assert_eq!(point, announced),
            keyroost_piv::PublicKey::Rsa { .. } => panic!("expected an EC point"),
        }

        let (pin, touch) = keyroost_piv::x509_parse::parse_key_policy_extension(&cert_data)
            .expect("the key-policy extension parses")
            .expect("the extension is present");
        assert_eq!((pin, touch), (0x02, 0x00));

        let dn = keyroost_piv::x509_parse::parse_subject_dn(&cert_data).expect("the subject parses");
        assert!(
            dn.rdns.iter().any(|attr| attr.1 == "PIVApplet Attestation 9A"),
            "the subject carries the slot suffix: {dn:?}"
        );

        // The certificate is signed by the on-card F9 key: the signature
        // verifies over SHA-256 of the TBS certificate, and not with any
        // other key.
        let (tbs, sig_bytes) = tbs_and_signature(&cert_data).expect("certificate structure");
        let f9_signing = ecdsa::SigningKey::<p256::NistP256>::from_slice(&applet.attestation.secret)
            .expect("the F9 key is a valid P-256 key");
        let mut hasher = Sha256::new();
        hasher.update(tbs);
        let digest = hasher.finalize();
        let sig: ecdsa::Signature<p256::NistP256> =
            ecdsa::der::Signature::<p256::NistP256>::from_bytes(sig_bytes)
                .expect("a DER ECDSA signature")
                .try_into()
                .expect("the signature fits the fixed-size form");
        f9_signing
            .verifying_key()
            .verify_prehash(digest.as_slice(), &sig)
            .expect("the F9 signature verifies over the TBS");
        let other = ecdsa::SigningKey::<p256::NistP256>::random(&mut rand_core::OsRng);
        other
            .verifying_key()
            .verify_prehash(digest.as_slice(), &sig)
            .expect_err("another key does not verify");
    }

    /// The TBS certificate's byte range inside the certificate (tag and
    /// length included) and the signature's content (after the BIT STRING's
    /// unused-bits byte) — the two pieces a signature check needs.
    fn tbs_and_signature(cert: &[u8]) -> Option<(&[u8], &[u8])> {
        if cert.first()? != &0x30 {
            return None;
        }
        let (cert_len_prefix, _cert_len) = der_len(&cert[1..])?;
        let inner = &cert[1 + cert_len_prefix..];
        // TBS: the first SEQUENCE inside.
        if inner.first()? != &0x30 {
            return None;
        }
        let (tbs_prefix, tbs_len) = der_len(&inner[1..])?;
        let tbs = &inner[..1 + tbs_prefix + tbs_len];
        // Signature algorithm: the SEQUENCE after the TBS.
        let rest = &inner[1 + tbs_prefix + tbs_len..];
        if rest.first()? != &0x30 {
            return None;
        }
        let (alg_prefix, alg_len) = der_len(&rest[1..])?;
        // Signature BIT STRING: the last TLV in the certificate.
        let sig_tlv = &rest[1 + alg_prefix + alg_len..];
        if sig_tlv.first()? != &0x03 {
            return None;
        }
        let (sig_prefix, sig_len) = der_len(&sig_tlv[1..])?;
        let sig = &sig_tlv[1 + sig_prefix..1 + sig_prefix + sig_len];
        if sig.first()? != &0x00 {
            return None;
        }
        Some((tbs, &sig[1..]))
    }

    fn der_len(buf: &[u8]) -> Option<(usize, usize)> {
        let first = *buf.first()?;
        if first <= 0x7F {
            Some((1, usize::from(first)))
        } else if first == 0x81 {
            Some((2, usize::from(*buf.get(1)?)))
        } else if first == 0x82 {
            let b = buf.get(1..3)?;
            Some((3, (usize::from(b[0]) << 8) | usize::from(b[1])))
        } else {
            None
        }
    }

    #[test]
    fn attest_refuses_non_slot_targets() {
        let mut applet = PivApplet::new();
        for ref_ in [0x9B, 0xF9, 0x96, 0x00, 0x80, 0xE0, 0x58] {
            let apdu = vec![0x00, 0xF9, ref_, 0x00, 0x00];
            let response = applet.process(&apdu);
            assert_eq!(response.sw, SW_INCORRECT_P1P2, "ref {ref_:02X}");
        }
    }

    #[test]
    fn attest_refuses_a_nonzero_p2() {
        let mut applet = PivApplet::new();
        let apdu = vec![0x00, 0xF9, 0x9A, 0x01, 0x00];
        let response = applet.process(&apdu);
        assert_eq!(response.sw, SW_INCORRECT_P1P2);
    }

    #[test]
    fn attest_refuses_a_keyless_target() {
        let mut applet = PivApplet::new();
        let apdu = keyroost_piv::attest(0x9A);
        let response = applet.process(&apdu);
        assert_eq!(response.sw, keyroost_piv::SW_REFERENCE_NOT_FOUND);
    }

    #[test]
    fn attest_answers_for_p521_targets() {
        let mut applet = PivApplet::new();
        mgmt_handshake(&mut applet);
        // P-521: the 133-byte point exercises the SPKI's long point form.
        let apdu = keyroost_piv::generate_key(
            keyroost_piv::Slot::Retired(3),
            keyroost_piv::KeyAlg::EccP521.id(),
            keyroost_piv::PinPolicy::Default,
            keyroost_piv::TouchPolicy::Default,
        );
        let response = applet.process(&apdu);
        assert_eq!(response.sw, SW_OK);
        let announced = announced_point(&response);
        let apdu = keyroost_piv::attest(0x84);
        let first = applet.process(&apdu);
        let cert_data = if first.sw >> 8 == 0x61 {
            let remainder = applet.process(&[0x00, 0xC0, 0x00, 0x00]);
            let mut data = first.data;
            data.extend(remainder.data);
            assert_eq!(remainder.sw, SW_OK);
            data
        } else {
            assert_eq!(first.sw, SW_OK);
            first.data
        };
        let (alg, point) = keyroost_piv::x509_parse::parse_certificate_public_key(&cert_data)
            .expect("the P-521 certificate parses");
        assert_eq!(alg, KeyAlg::EccP521);
        match point {
            keyroost_piv::PublicKey::Ecc { point } => assert_eq!(point, announced),
            keyroost_piv::PublicKey::Rsa { .. } => panic!("expected an EC point"),
        }
    }



    #[test]
    fn generate_on_f9_mints_a_fresh_ca() {
        let mut applet = PivApplet::new();
        mgmt_handshake(&mut applet);
        let old_cert = applet.attestation.cert.clone().expect("factory cert");
        // GENERATE ASYMMETRIC on F9: the host's builder takes a slot — the
        // applet's slot set does not include F9, so build the APDU by hand:
        // case 4 with the AC control template's P-256 member.
        let apdu = vec![
            0x00u8, 0x47, 0x00, 0xF9, 0x00, 0x00, 0x05, 0xAC, 0x03, 0x80, 0x01, 0x11, 0x00, // Le
        ];
        let response = applet.process(&apdu);
        assert_eq!(response.sw, SW_OK);
        let announced = announced_point(&response);
        // The old key is gone and the old certificate describes it no more.
        assert_ne!(
            applet.attestation.cert.as_ref().expect("re-minted"),
            &old_cert
        );
        // The re-minted certificate is 70-wrapped, parses, carries the F9
        // key's point and its signature verifies over the F9 key.
        let wrapped = applet.attestation.cert.as_ref().expect("the re-minted cert");
        assert_eq!(wrapped.first(), Some(&0x70));
        let (len_prefix, len) = der_len(&wrapped[1..]).expect("the wrapped length");
        let der = &wrapped[1 + len_prefix..1 + len_prefix + len];
        let (alg, point) =
            keyroost_piv::x509_parse::parse_certificate_public_key(der).expect("parses");
        assert_eq!(alg, KeyAlg::EccP256);
        match point {
            keyroost_piv::PublicKey::Ecc { point } => assert_eq!(point, announced),
            keyroost_piv::PublicKey::Rsa { .. } => panic!("expected an EC point"),
        }
        let (tbs, sig_bytes) = tbs_and_signature(der).expect("certificate structure");
        let f9_signing =
            ecdsa::SigningKey::<p256::NistP256>::from_slice(&applet.attestation.secret).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(tbs);
        let sig: ecdsa::Signature<p256::NistP256> =
            ecdsa::der::Signature::<p256::NistP256>::from_bytes(sig_bytes)
                .expect("a DER ECDSA signature")
                .try_into()
                .expect("the signature fits the fixed-size form");
        f9_signing
            .verifying_key()
            .verify_prehash(hasher.finalize().as_slice(), &sig)
            .expect("the re-minted self-signature verifies");
    }

    /// The F9 self-signed certificate: GET DATA 5FFF01 returns the
    /// 70-wrapped certificate, and its signature verifies over its own
    /// TBS with the F9 key.
    #[test]
    fn factory_attestation_certificate_is_served_and_self_signed() {
        let mut applet = PivApplet::new();
        let apdu = keyroost_piv::get_data(&[0x5F, 0xFF, 0x01]);
        let first = applet.process(&apdu);
        let (data, sw) = if first.sw >> 8 == 0x61 {
            let remainder = applet.process(&[0x00, 0xC0, 0x00, 0x00]);
            let mut data = first.data;
            data.extend(remainder.data);
            (data, remainder.sw)
        } else {
            (first.data, first.sw)
        };
        assert_eq!(sw, SW_OK);
        let value = keyroost_piv::unwrap_data_object(&data).expect("a 53 template");
        // The storage form is the 70-wrapped certificate.
        let wrapped = applet.attestation.cert.as_ref().expect("the cert is minted");
        assert_eq!(value, wrapped);
        let wrapped_prefix = &wrapped[..2];
        assert_eq!(wrapped_prefix[0], 0x70);
        let (len_prefix, len) = der_len(&wrapped[1..]).expect("the wrapped length");
        let der = &wrapped[1 + len_prefix..1 + len_prefix + len];
        // The F9 certificate's own signature verifies with the F9 key.
        let (tbs, sig_bytes) = tbs_and_signature(der).expect("certificate structure");
        let f9_signing =
            ecdsa::SigningKey::<p256::NistP256>::from_slice(&applet.attestation.secret).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(tbs);
        let sig: ecdsa::Signature<p256::NistP256> =
            ecdsa::der::Signature::<p256::NistP256>::from_bytes(sig_bytes)
                .expect("a DER ECDSA signature")
                .try_into()
                .expect("the signature fits the fixed-size form");
        f9_signing
            .verifying_key()
            .verify_prehash(hasher.finalize().as_slice(), &sig)
            .expect("the F9 self-signature verifies");
    }
}

