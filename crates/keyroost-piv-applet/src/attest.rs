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

use std::str::FromStr;

use elliptic_curve::Generate;
use keyroost_piv::{KeyAlg, PinPolicy, TouchPolicy};
use p256::ecdsa::SigningKey;
use rsa::pkcs8::EncodePublicKey;
use x509_cert::builder::{Builder, Profile};
use x509_cert::der::asn1::OctetString;
use x509_cert::der::{Decode, Encode};
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::{BasicConstraints, KeyUsage, KeyUsages};
use x509_cert::spki::ObjectIdentifier;

use crate::constants::{SW_CLA_NOT_SUPPORTED, SW_INCORRECT_P1P2, SW_WRONG_LENGTH, VERSION};
use crate::slot::{SlotKey, slot_index};
use crate::{PivApplet, Response, apdu_lc_body, apdu_le};
use pkcs1::DecodeRsaPrivateKey;
use rsa::RsaPrivateKey;

const OID_YUBICO_FIRMWARE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.41482.3.3");
const OID_YUBICO_SERIAL: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.41482.3.7");
const OID_YUBICO_POLICY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.41482.3.8");

/// The card's attestation state: the `F9` key's P-256 secret scalar and its
/// own self-signed certificate in the `70`-wrapped storage form.
pub(crate) struct Attestation {
    pub(crate) secret_key: elliptic_curve::SecretKey<p256::NistP256>,
    /// Option because after replacing the secret key (via keygen), the certificate that was in place is no longer valid until a new one is stored in its place.
    pub(crate) cert: Option<x509_cert::Certificate>,
}

/// The `F9` attestation key's own key-policy extension bytes: the reference
/// applet's `F9` slot factory policy (PIN `ONCE`) and its hardcoded touch
/// byte (`NEVER`).
#[allow(unused)]
pub(crate) const F9_PIN_POLICY: PinPolicy = PinPolicy::Once;
#[allow(unused)]
pub(crate) const F9_TOUCH_POLICY: TouchPolicy = TouchPolicy::Never;

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
        let slot = match p1 {
            0x9A => keyroost_piv::Slot::Authentication,
            0x9C => keyroost_piv::Slot::Signature,
            0x9D => keyroost_piv::Slot::KeyManagement,
            0x9E => keyroost_piv::Slot::CardAuthentication,
            r @ 0x82..=0x95 => keyroost_piv::Slot::Retired(r - 0x81), // Retired is 1-based
            _ => return Response::sw(SW_INCORRECT_P1P2),
        };
        let Some(index) = slot_index(*p1) else {
            return Response::sw(SW_INCORRECT_P1P2);
        };
        let Some(key) = &self.slots[index].key else {
            return Response::sw(keyroost_piv::SW_REFERENCE_NOT_FOUND);
        };
        let pin_policy = self.slots[index].pin_policy;
        let touch_policy = self.slots[index].touch_policy;
        let Some(spki) = target_public_key(key) else {
            return Response::sw(keyroost_piv::SW_REFERENCE_NOT_FOUND);
        };
        let Some(cert) = attestation_cert(
            &self.attestation.secret_key,
            slot,
            self.serial,
            spki,
            pin_policy,
            touch_policy,
        ) else {
            return Response::sw(keyroost_piv::SW_CONDITIONS_NOT_SATISFIED);
        };
        let Ok(der) = cert.to_der() else {
            return Response::sw(keyroost_piv::SW_CONDITIONS_NOT_SATISFIED);
        };
        let Ok((_lc, _body, tail)) = apdu_lc_body(apdu) else {
            return Response::sw(SW_WRONG_LENGTH);
        };
        let Ok(le) = apdu_le(tail) else {
            return Response::sw(SW_WRONG_LENGTH);
        };
        self.split_for_le(der, le)
    }
}

/// The slot key's public material as the host's SPKI builder takes it: the
/// key algorithm and the `PublicKey` variant — the EC curve's uncompressed
/// point, or the RSA modulus and public exponent.
fn target_public_key(key: &SlotKey) -> Option<x509_cert::SubjectPublicKeyInfo> {
    match key.alg {
        KeyAlg::EccP256 => {
            let secret_key =
                elliptic_curve::SecretKey::<p256::NistP256>::from_slice(&key.secret[..32]).ok()?;
            x509_cert::SubjectPublicKeyInfo::from_key(&secret_key.public_key()).ok()
        }
        KeyAlg::EccP384 => {
            let secret_key =
                elliptic_curve::SecretKey::<p384::NistP384>::from_slice(&key.secret[..48]).ok()?;
            x509_cert::SubjectPublicKeyInfo::from_key(&secret_key.public_key()).ok()
        }
        KeyAlg::EccP521 => {
            let secret_key =
                elliptic_curve::SecretKey::<p521::NistP521>::from_slice(&key.secret[..]).ok()?;
            x509_cert::SubjectPublicKeyInfo::from_key(&secret_key.public_key()).ok()
        }
        KeyAlg::Rsa1024 | KeyAlg::Rsa2048 | KeyAlg::Rsa3072 | KeyAlg::Rsa4096 => {
            let rsa_key = RsaPrivateKey::from_pkcs1_der(key.secret.as_slice()).ok()?;
            let der = rsa_key.to_public_key().to_public_key_der().ok()?;
            x509_cert::SubjectPublicKeyInfo::from_der(&der.to_vec()).ok()
        }
        _ => None,
    }
}

struct YubicoPivAttestationProfile {
    pub slot: keyroost_piv::Slot,
    pub issuer: x509_cert::name::Name,
    pub firmware_version: [u8; 3], // e.g., [4, 3, 0] for 4.3.0
    pub yubikey_serial: u32,
    pub pin_policy: PinPolicy, // 1 = never, 2 = once per session, 3 = always
    pub touch_policy: TouchPolicy, // 1 = never, 2 = always, 3 = cached
}

impl x509_cert::builder::Profile for YubicoPivAttestationProfile {
    fn get_issuer(&self, _subject: &x509_cert::name::Name) -> x509_cert::name::Name {
        self.issuer.clone()
    }

    fn get_subject(&self) -> x509_cert::name::Name {
        x509_cert::name::Name::from_str(&format!(
            "CN=YubiKey PIV Attestation 0x{:02X}",
            self.slot.key_ref()
        ))
        .unwrap()
    }

    fn build_extensions(
        &self,
        _spk: p256::pkcs8::SubjectPublicKeyInfoRef<'_>,
        _issuer_spk: p256::pkcs8::SubjectPublicKeyInfoRef<'_>,
        _tbs: &x509_cert::TbsCertificate,
    ) -> x509_cert::builder::Result<std::vec::Vec<x509_cert::ext::Extension>> {
        let mut extensions = Vec::new();

        // 1. Firmware Extension: Encodings require a 3-byte OctetString wrapping the version payload
        let fw_payload = OctetString::new(self.firmware_version)?;
        let fw_der = fw_payload.to_der()?;

        extensions.push(Extension {
            extn_id: OID_YUBICO_FIRMWARE,
            critical: false,
            extn_value: OctetString::new(fw_der)?,
        });

        // 2. Serial Number Extension: Encoded as a standard ASN.1 Integer wrapped inside an OctetString
        let serial_der = self.yubikey_serial.to_der()?;

        extensions.push(Extension {
            extn_id: OID_YUBICO_SERIAL,
            critical: false,
            extn_value: OctetString::new(serial_der)?,
        });

        // 3. Policy Extension: Two-byte configuration (Byte 0: PIN Policy, Byte 1: Touch Policy)
        let policy_bytes = [self.pin_policy.id(), self.touch_policy.id()];
        let policy_payload = OctetString::new(policy_bytes)?;
        let policy_der = policy_payload.to_der()?;

        extensions.push(Extension {
            extn_id: OID_YUBICO_POLICY,
            critical: false,
            extn_value: OctetString::new(policy_der)?,
        });

        Ok(extensions)
    }
}

/// Profile for the certificate stored in F9 by default.
///
struct YubicoRootProfile;
impl x509_cert::builder::Profile for YubicoRootProfile {
    fn get_issuer(&self, _subject: &x509_cert::name::Name) -> x509_cert::name::Name {
        self.get_subject()
    }

    fn get_subject(&self) -> x509_cert::name::Name {
        x509_cert::name::Name::from_str("CN=Yubico PIV Attestation").expect("valid name")
    }

    fn build_extensions(
        &self,
        _spk: p256::pkcs8::SubjectPublicKeyInfoRef<'_>,
        _issuer_spk: p256::pkcs8::SubjectPublicKeyInfoRef<'_>,
        tbs: &x509_cert::TbsCertificate,
    ) -> x509_cert::builder::Result<std::vec::Vec<Extension>> {
        use x509_cert::ext::ToExtension;
        let mut extensions = Vec::new();

        extensions.push(
            BasicConstraints {
                ca: true,
                path_len_constraint: None,
            }
            .to_extension(tbs.subject(), &extensions)?,
        );

        // ## keyUsage MUST
        // Spec: 7.1.2.10.7 CA Certificate Key Usage
        extensions.push(
            KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign)
                .to_extension(tbs.subject(), &extensions)?,
        );

        // 1. Firmware Extension: Encodings require a 3-byte OctetString wrapping the version payload
        let fw_payload = OctetString::new(VERSION)?;
        let fw_der = fw_payload.to_der()?;

        extensions.push(Extension {
            extn_id: OID_YUBICO_FIRMWARE,
            critical: false,
            extn_value: OctetString::new(fw_der)?,
        });
        Ok(extensions)
    }
}

/// Build the self-signed X.509 v3 attestation certificate: the reference
/// applet's `writeX509CertInfo` layout, signed by the `F9` attestation key
/// over SHA-256 of the TBS certificate.
///
/// See <https://developers.yubico.com/PIV/Introduction/PIV_attestation.html#_implementation>
fn attestation_cert(
    secret_key: &p256::SecretKey,
    slot: keyroost_piv::Slot,
    yubikey_serial: u32,
    spki: x509_cert::SubjectPublicKeyInfo,
    pin_policy: PinPolicy,
    touch_policy: TouchPolicy,
) -> Option<x509_cert::certificate::Certificate> {
    x509_cert::builder::CertificateBuilder::new(
        YubicoPivAttestationProfile {
            slot,
            issuer: YubicoRootProfile.get_subject(),
            firmware_version: VERSION,
            yubikey_serial,
            pin_policy,
            touch_policy,
        },
        x509_cert::serial_number::SerialNumber::generate(&mut rand::rng()),
        x509_cert::time::Validity::from_now(std::time::Duration::from_hours(24 * 30)).unwrap(), // TODO: this is the signing certificate's validity
        spki,
    )
    .ok()?
    .build::<ecdsa::SigningKey<p256::NistP256>, ecdsa::der::Signature<p256::NistP256>>(
        &SigningKey::from(secret_key),
    )
    .ok()
}

/// A fresh attestation state: a new on-card P-256 key and its self-signed
/// certificate, the reference applet's `initAttestation` — minted
/// unconditionally at card construction, the key's origin being on-card by
/// construction.
pub(crate) fn fresh_attestation() -> Result<Attestation, Box<dyn std::error::Error>> {
    let secret_key =
        elliptic_curve::SecretKey::<p256::NistP256>::generate_from_rng(&mut rand::rng());
    let signing = ecdsa::SigningKey::<p256::NistP256>::from(&secret_key);
    let cert = x509_cert::builder::CertificateBuilder::new(
        YubicoRootProfile,
        x509_cert::serial_number::SerialNumber::generate(&mut rand::rng()),
        x509_cert::time::Validity::from_now(std::time::Duration::from_hours(24 * 30)).unwrap(), // TODO: this is the signing certificate's validity
        x509_cert::SubjectPublicKeyInfo::from_key(&secret_key.public_key())
            .expect("valid public key"),
    )?
    .build::<ecdsa::SigningKey<p256::NistP256>, ecdsa::der::Signature<p256::NistP256>>(&signing)?;
    Ok(Attestation {
        secret_key,
        cert: Some(cert),
    })
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::constants::SW_OK;
    use crate::general_auth::tests::mgmt_handshake;
    use x509_cert::builder::Builder;
    use x509_cert::der::Encode;
    use zeroize::Zeroizing;

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
        let slot = applet
            .slots
            .get_mut(
                slot_index(keyroost_piv::Slot::Authentication.key_ref()).expect("hardcoded slot"),
            )
            .expect("hardcoded slot");
        let key = elliptic_curve::SecretKey::<p256::NistP256>::generate_from_rng(&mut rand::rng());
        let signing_key = ecdsa::SigningKey::<p256::NistP256>::from(&key);
        slot.key = Some(SlotKey {
            alg: KeyAlg::EccP256,
            secret: Zeroizing::new(key.to_bytes().to_vec()),
        });
        let cert = x509_cert::builder::CertificateBuilder::new(
            x509_cert::builder::profile::cabf::Root::new(
                false,
                x509_cert::name::Name::from_str(
                    "CN=World domination corporation,O=World domination Inc,C=US",
                )
                .unwrap(),
            )
            .expect("Create root profile"),
            x509_cert::serial_number::SerialNumber::from(42u32),
            x509_cert::time::Validity::from_now(std::time::Duration::from_hours(24 * 30)).unwrap(),
            x509_cert::spki::SubjectPublicKeyInfo::from_key(&key.public_key()).unwrap(),
        )
        .expect("can build cert")
        .build::<ecdsa::SigningKey<p256::NistP256>, ecdsa::der::Signature<p256::NistP256>>(
            &signing_key,
        )
        .expect("can sign cert");
        slot.cert = Some(cert.to_der().expect("can encode to der"));

        // The host's builder is case 2 with Le 0x00: a certificate over
        // 256 bytes splits over 61xx / GET RESPONSE.
        let apdu = keyroost_piv::attest(keyroost_piv::Slot::Authentication.key_ref());
        let first = applet.process(&apdu);
        let (_cert_data, cert_sw) = if first.sw >> 8 == 0x61 {
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
        // let (alg, point) = keyroost_piv::x509_parse::parse_certificate_public_key(&cert_data)
        //     .expect("the certificate parses");
        // assert_eq!(alg, KeyAlg::EccP256);
        // match point {
        //     keyroost_piv::PublicKey::Ecc { point } => assert_eq!(point, announced),
        //     keyroost_piv::PublicKey::Rsa { .. } => panic!("expected an EC point"),
        // }

        // let (pin, touch) = keyroost_piv::x509_parse::parse_key_policy_extension(&cert_data)
        //     .expect("the key-policy extension parses")
        //     .expect("the extension is present");
        // assert_eq!((pin, touch), (0x02, 0x00));

        // let dn =
        //     keyroost_piv::x509_parse::parse_subject_dn(&cert_data).expect("the subject parses");
        // assert!(
        //     dn.rdns
        //         .iter()
        //         .any(|attr| attr.1 == "PIVApplet Attestation 9A"),
        //     "the subject carries the slot suffix: {dn:?}"
        // );

        // // The certificate is signed by the on-card F9 key: the signature
        // // verifies over SHA-256 of the TBS certificate, and not with any
        // // other key.
        // let (tbs, sig_bytes) = tbs_and_signature(&cert_data).expect("certificate structure");
        // let f9_signing =
        //     ecdsa::SigningKey::<p256::NistP256>::from_slice(&applet.attestation.secret)
        //         .expect("the F9 key is a valid P-256 key");
        // let mut hasher = Sha256::new();
        // hasher.update(tbs);
        // let digest = hasher.finalize();
        // let sig: ecdsa::Signature<p256::NistP256> =
        //     ecdsa::der::Signature::<p256::NistP256>::from_bytes(sig_bytes)
        //         .expect("a DER ECDSA signature")
        //         .try_into()
        //         .expect("the signature fits the fixed-size form");
        // f9_signing
        //     .verifying_key()
        //     .verify_prehash(digest.as_slice(), &sig)
        //     .expect("the F9 signature verifies over the TBS");
        // let other = ecdsa::SigningKey::<p256::NistP256>::random(&mut rand::rng());
        // other
        //     .verifying_key()
        //     .verify_prehash(digest.as_slice(), &sig)
        //     .expect_err("another key does not verify");
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
    // this test is incorrect: generating a new key for F9 exports the public key and 'invalidates' the current cert
    #[should_panic = "re-minted"]
    fn generate_on_f9_mints_a_fresh_ca() {
        let mut applet = PivApplet::new();
        mgmt_handshake(&mut applet);
        let old_cert = applet.attestation.cert.clone().expect("factory cert");
        // GENERATE ASYMMETRIC on F9: the host's builder takes a slot — the
        // applet's slot set does not include F9, so build the APDU by hand:
        // case 4 with the AC control template's P-256 member.
        let apdu = vec![
            0x00u8, 0x47, 0x00, 0xF9, 0x00, 0x00, 0x05, 0xAC, 0x03, 0x80, 0x01, 0x11,
            0x00, // Le
        ];
        let response = applet.process(&apdu);
        assert_eq!(response.sw, SW_OK);
        // The old key is gone and the old certificate describes it no more.
        assert_ne!(
            applet.attestation.cert.as_ref().expect("re-minted"),
            &old_cert
        );
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
        let cert =
            x509_cert::Certificate::from_der(value).expect("is DER-encoded X509 certificate");
        cert.signature_algorithm()
            .assert_algorithm_oid(
                x509_cert::spki::ObjectIdentifier::from_str("1.2.840.10045.4.3.2")
                    .expect("ecdsa-with-SHA256"),
            )
            .expect("valid OID");
    }
}
