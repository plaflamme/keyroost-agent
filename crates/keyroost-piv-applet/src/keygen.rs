//! The key-slot key commands: GENERATE ASYMMETRIC KEY PAIR (`0x47`),
//! IMPORT ASYMMETRIC KEY (`0x86`) and MOVE KEY / DELETE (`0xF6`), the
//! first two for the NIST curves P-256, P-384 and P-521.
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

use elliptic_curve::{FieldBytes, PrimeCurve};
use num_bigint_dig::BigUint;
use num_integer::Integer;
use num_traits::{One, Zero};
use pkcs1::EncodeRsaPrivateKey;
use rsa::RsaPrivateKey;
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use zeroize::Zeroizing;

use keyroost_piv::{KeyAlg, PinPolicy, TouchPolicy};

use crate::Response;
use crate::constants::{
    SW_CLA_NOT_SUPPORTED, SW_INCORRECT_P1P2, SW_OK, SW_WRONG_DATA, SW_WRONG_LENGTH,
};
use crate::data::push_tlv;
use crate::slot::{SlotKey, rsa_modulus_len, slot_index};
use crate::{PivApplet, apdu_lc_body};

/// The public exponent every PIV RSA key carries: `0x01 0x00 0x01` (65537).
/// GENERATE keys use it because `RsaPrivateKey::new` fixes it; IMPORT
/// assumes it, exactly as the reference applet does (the import body
/// carries only the CRT components, never the exponent).
const RSA_EXPONENT: [u8; 3] = [0x01, 0x00, 0x01];

/// The NIST group orders `n`, big endian. The largest scalar the IMPORT
/// command will accept is `n - 1`. Taken from the `p256`, `p384` and
/// `p521` crates' own `ORDER` constants.
const P256_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];

const P384_ORDER: [u8; 48] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC7, 0x63, 0x4D, 0x81, 0xF4, 0x37, 0x2D, 0xDF,
    0x58, 0x1A, 0x0D, 0xB2, 0x48, 0xB0, 0xA7, 0x7A, 0xEC, 0xEC, 0x19, 0x6A, 0xCC, 0xC5, 0x29, 0x73,
];

const P521_ORDER: [u8; 66] = [
    0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFA, 0x51, 0x86, 0x87, 0x83, 0xBF, 0x2F, 0x96, 0x6B, 0x7F, 0xCC, 0x01, 0x48, 0xF7, 0x09,
    0xA5, 0xD0, 0x3B, 0xB5, 0xC9, 0xB8, 0x89, 0x9C, 0x47, 0xAE, 0xBB, 0x6F, 0xB7, 0x1E, 0x91, 0x38,
    0x64, 0x09,
];

/// An imported scalar checked for one NIST curve: the zeroized canonical
/// big-endian secret, `None` when the bytes are not a valid `1..=n-1`
/// field element for the curve.
fn imported_secret<C>(scalar: &[u8]) -> Option<Zeroizing<Vec<u8>>>
where
    C: PrimeCurve,
{
    // The caller checked the scalar is exactly the curve's field size.
    use elliptic_curve::generic_array::typenum::Unsigned;
    debug_assert_eq!(scalar.len(), C::FieldBytesSize::to_usize());
    let bytes = FieldBytes::<C>::from_slice(scalar);
    let key = elliptic_curve::SecretKey::<C>::from_bytes(bytes).ok()?;
    Some(Zeroizing::new(key.to_bytes().to_vec()))
}

/// An imported RSA key validated against its modulus size and rebuilt as
/// the card's PKCS#1 storage form. The on-wire set is the reference
/// applet's CRT member set — `01 p`, `02 q`, `03 dP`, `04 dQ`, `05 n`:
/// every component present, `p`/`q` exactly half the modulus size, `n`
/// the full size, `dP`/`dQ` non-zero and at most half the size,
/// `p`/`q`/`n` odd and greater than 1, `p != q` and `p * q == n` (checked
/// numerically with `BigUint`). Stricter than the reference applet, which
/// does none of this — a broken CRT set would otherwise be stored and fail
/// on first use. The exponent is assumed to be the PIV standard 65537
/// (see `RSA_EXPONENT`).
///
/// The wire carries the CRT halves but the card stores the full key, so
/// the private exponent is rebuilt from the primes instead:
/// `RsaPrivateKey::from_p_q` derives `d = e^{-1} mod lcm(p-1, q-1)`
/// (NIST SP 800-56B 6.2.1) and the modulus `n = p * q` itself, validates
/// the full key (`d * e ≡ 1` modulo both prime orders) and precomputes the
/// CRT exponents `to_pkcs1_der` needs. The on-wire `dP`/`dQ` are then only
/// checked for consistency with the derived `d` (`d ≡ dP (mod p-1)`,
/// `d ≡ dQ (mod q-1)`) — a mismatched set is refused, never stored.
fn imported_rsa_secret(
    p: &[u8],
    q: &[u8],
    dp: &[u8],
    dq: &[u8],
    n: &[u8],
    modulus_len: usize,
) -> Option<Vec<u8>> {
    let half = modulus_len / 2;
    if p.len() != half
        || q.len() != half
        || n.len() != modulus_len
        || dp.is_empty()
        || dq.is_empty()
        || dp.len() > half
        || dq.len() > half
    {
        return None;
    }
    for component in [&p, &q, &n] {
        let value = BigUint::from_bytes_be(component);
        if value.is_zero() || value.is_one() || value.is_even() {
            return None;
        }
    }
    let (p, q) = (BigUint::from_bytes_be(p), BigUint::from_bytes_be(q));

    let mut key = RsaPrivateKey::from_p_q(p, q, BigUint::from_bytes_be(&RSA_EXPONENT)).ok()?;

    if key.n() != &BigUint::from_bytes_be(n) {
        return None;
    }

    key.precompute().ok()?;
    if key.dp()? != &BigUint::from_bytes_be(dp) {
        return None;
    }
    if key.dq()? != &BigUint::from_bytes_be(dq) {
        return None;
    }
    Some(key.to_pkcs1_der().ok()?.as_bytes().to_vec())
}

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
            Ok((_, body, _)) => body,
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
        let secret = match alg {
            KeyAlg::EccP256 => {
                let key =
                    elliptic_curve::SecretKey::<p256::NistP256>::random(&mut rand_core::OsRng);
                Zeroizing::new(key.to_bytes().to_vec())
            }
            KeyAlg::EccP384 => {
                let key =
                    elliptic_curve::SecretKey::<p384::NistP384>::random(&mut rand_core::OsRng);
                Zeroizing::new(key.to_bytes().to_vec())
            }
            KeyAlg::EccP521 => {
                let key =
                    elliptic_curve::SecretKey::<p521::NistP521>::random(&mut rand_core::OsRng);
                Zeroizing::new(key.to_bytes().to_vec())
            }
            KeyAlg::Rsa1024 | KeyAlg::Rsa2048 | KeyAlg::Rsa3072 | KeyAlg::Rsa4096 => {
                let bits = match alg {
                    KeyAlg::Rsa1024 => 1024,
                    KeyAlg::Rsa2048 => 2048,
                    KeyAlg::Rsa3072 => 3072,
                    KeyAlg::Rsa4096 => 4096,
                    _ => unreachable!("alg is an RSA key size"),
                };
                let key = match RsaPrivateKey::new(&mut rand_core::OsRng, bits) {
                    Ok(key) => key,
                    Err(_) => return Response::sw(SW_WRONG_DATA),
                };
                // The card's storage form: the key's PKCS#1 encoding,
                // zeroized on drop. `new` always precomputes the CRT
                // exponents, which `to_pkcs1_der` needs for its
                // `crtCoefficient` field.
                match key.to_pkcs1_der() {
                    Ok(doc) => Zeroizing::new(doc.as_bytes().to_vec()),
                    Err(_) => return Response::sw(SW_WRONG_DATA),
                }
            }
            _ => return Response::sw(SW_WRONG_DATA),
        };
        let key = SlotKey { alg, secret };
        let inner = match key.public_inner() {
            Some(inner) => inner,
            None => return Response::sw(SW_WRONG_DATA),
        };
        self.commit_slot_key(index, key, false, pin_policy, touch_policy);

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
        let alg = match KeyAlg::from_id(*p1) {
            Some(alg @ (KeyAlg::EccP256 | KeyAlg::EccP384 | KeyAlg::EccP521)) => alg,
            Some(alg @ (KeyAlg::Rsa1024 | KeyAlg::Rsa2048 | KeyAlg::Rsa3072 | KeyAlg::Rsa4096)) => {
                alg
            }
            _ => return Response::sw(SW_WRONG_DATA),
        };
        let body = match apdu_lc_body(apdu) {
            Ok((_, body, _)) => body,
            Err(()) => return Response::sw(SW_WRONG_LENGTH),
        };
        let rsa = matches!(
            alg,
            KeyAlg::Rsa1024 | KeyAlg::Rsa2048 | KeyAlg::Rsa3072 | KeyAlg::Rsa4096
        );
        let import = match parse_import(body, rsa) {
            Ok(import) => import,
            Err(()) => return Response::sw(SW_WRONG_DATA),
        };

        let secret = match alg {
            KeyAlg::EccP256 | KeyAlg::EccP384 | KeyAlg::EccP521 => {
                // The scalar must be the big-endian encoding of a value in
                // 1..=n-1 for the requested curve: the curve's field
                // length, non-zero, below the group order. The range check
                // precedes `from_bytes` — it would reduce `n` and above
                // modulo `n` instead of refusing them.
                let scalar = import
                    .scalar
                    .as_ref()
                    .expect("the EC branch requires the scalar member");
                let order: &[u8] = match alg {
                    KeyAlg::EccP256 => &P256_ORDER,
                    KeyAlg::EccP384 => &P384_ORDER,
                    KeyAlg::EccP521 => &P521_ORDER,
                    _ => unreachable!("alg is one of the NIST curves"),
                };
                if scalar.len() != order.len()
                    || scalar.iter().all(|byte| *byte == 0)
                    || scalar.as_slice() >= order
                {
                    return Response::sw(SW_WRONG_DATA);
                }
                let secret = match alg {
                    KeyAlg::EccP256 => imported_secret::<p256::NistP256>(scalar),
                    KeyAlg::EccP384 => imported_secret::<p384::NistP384>(scalar),
                    KeyAlg::EccP521 => imported_secret::<p521::NistP521>(scalar),
                    _ => unreachable!("alg is one of the NIST curves"),
                };
                match secret {
                    Some(secret) => secret,
                    None => return Response::sw(SW_WRONG_DATA),
                }
            }
            KeyAlg::Rsa1024 | KeyAlg::Rsa2048 | KeyAlg::Rsa3072 | KeyAlg::Rsa4096 => {
                // The CRT component set: every member present, sizes
                // right, p * q == n.
                let (Some(p), Some(q), Some(dp), Some(dq), Some(n)) =
                    (&import.p, &import.q, &import.dp, &import.dq, &import.n)
                else {
                    return Response::sw(SW_WRONG_DATA);
                };
                let modulus_len = rsa_modulus_len(alg).expect("alg is an RSA key size");
                match imported_rsa_secret(p, q, dp, dq, n, modulus_len) {
                    Some(secret) => Zeroizing::new(secret),
                    None => return Response::sw(SW_WRONG_DATA),
                }
            }
            _ => unreachable!("alg is a NIST curve or an RSA key size"),
        };
        let key = SlotKey { alg, secret };
        self.commit_slot_key(index, key, true, import.pin_policy, import.touch_policy);
        Response::sw(SW_OK)
    }

    /// MOVE KEY (`0xF6`, Yubico extension): the host's `move_key` /
    /// `delete_key` APDU, `00 F6 <dest key_ref | 0xFF> <src key_ref>` —
    /// case 2, no body and no `Le`.
    ///
    /// A move relocates the source slot's key material and policies to the
    /// destination slot; the certificate objects are left untouched (the
    /// host contract — the host manages certificates through PUT DATA). The
    /// `0xFF` sentinel deletes the source key; policies and certificate are
    /// likewise left untouched.
    ///
    /// Refusals: locked `6982`; a non-slot reference in P1 (other than the
    /// `0xFF` delete sentinel) or P2 `6B00`; a source without a key `6A82`;
    /// a move into an occupied destination — the source itself included —
    /// `6A86` (R1: no silent key loss; the host pre-checks occupancy, so
    /// only an out-of-band tool can reach this answer).
    pub(crate) fn process_move_key(&mut self, apdu: &[u8]) -> Response {
        let [cla, _ins, p1, p2, _rest @ ..] = apdu else {
            return Response::sw(SW_WRONG_LENGTH);
        };
        if cla & 0x90 != 0 {
            return Response::sw(SW_CLA_NOT_SUPPORTED);
        }
        if let Err(sw) = self.management_unlocked() {
            return Response::sw(sw);
        }
        let source = match slot_index(*p2) {
            Some(index) => index,
            None => return Response::sw(SW_INCORRECT_P1P2),
        };
        let dest = match *p1 {
            0xFF => None,
            reference => match slot_index(reference) {
                Some(index) => Some(index),
                None => return Response::sw(SW_INCORRECT_P1P2),
            },
        };
        if self.slots[source].key.is_none() {
            return Response::sw(keyroost_piv::SW_NOT_FOUND);
        }
        if let Some(dest) = dest
            && self.slots[dest].key.is_some()
        {
            return Response::sw(SW_WRONG_DATA);
        }

        let key = self.slots[source].key.take().expect("checked above");
        let (pin_policy, touch_policy, imported) = (
            self.slots[source].pin_policy,
            self.slots[source].touch_policy,
            self.slots[source].imported,
        );
        if let Some(dest) = dest {
            self.slots[dest].key = Some(key);
            self.slots[dest].pin_policy = pin_policy;
            self.slots[dest].touch_policy = touch_policy;
            self.slots[dest].imported = imported;
        }
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

/// The body of an IMPORT ASYMMETRIC KEY command: either the EC branch —
/// a required `06 <len> <scalar>` member — or the RSA branch — the five CRT
/// components `01 P`, `02 Q`, `03 dP`, `04 dQ`, `05 n` — plus optional
/// `AA` / `AB` policy members, in any order, each at most once. Which
/// branch applies is decided by the algorithm in P1; a member of the other
/// branch refuses the command.
fn parse_import(body: &[u8], rsa: bool) -> Result<ImportKey, ()> {
    let mut scalar = None;
    let mut p = None;
    let mut q = None;
    let mut dp = None;
    let mut dq = None;
    let mut n = None;
    let mut pin_policy = None;
    let mut touch_policy = None;
    walk_tlvs(body, |tag, value| {
        match tag {
            0x06 if scalar.is_none() => scalar = Some(parse_scalar(value)?),
            0x01 if p.is_none() => p = Some(value.to_vec()),
            0x02 if q.is_none() => q = Some(value.to_vec()),
            0x03 if dp.is_none() => dp = Some(value.to_vec()),
            0x04 if dq.is_none() => dq = Some(value.to_vec()),
            0x05 if n.is_none() => n = Some(value.to_vec()),
            0xAA if pin_policy.is_none() => pin_policy = Some(parse_pin_policy(value)?),
            0xAB if touch_policy.is_none() => touch_policy = Some(parse_touch_policy(value)?),
            _ => return Err(()),
        }
        Ok(())
    })?;
    if rsa {
        // The EC scalar must not sneak in alongside the CRT set.
        if scalar.is_some() {
            return Err(());
        }
        if !(p.is_some() && q.is_some() && dp.is_some() && dq.is_some() && n.is_some()) {
            return Err(());
        }
    } else {
        // The RSA components must not sneak in alongside the scalar.
        if p.is_some() || q.is_some() || dp.is_some() || dq.is_some() || n.is_some() {
            return Err(());
        }
        if scalar.is_none() {
            return Err(());
        }
    }
    Ok(ImportKey {
        scalar,
        p,
        q,
        dp,
        dq,
        n,
        pin_policy,
        touch_policy,
    })
}

struct ImportKey {
    scalar: Option<Vec<u8>>,
    p: Option<Vec<u8>>,
    q: Option<Vec<u8>>,
    dp: Option<Vec<u8>>,
    dq: Option<Vec<u8>>,
    n: Option<Vec<u8>>,
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

/// A `06 <len> <scalar>` member: exactly the 32/48/66-byte big-endian
/// secret of one of the NIST curves.
fn parse_scalar(value: &[u8]) -> Result<Vec<u8>, ()> {
    match value.len() {
        32 | 48 | 66 => Ok(value.to_vec()),
        _ => Err(()),
    }
}

impl PivApplet {
    /// Commit a freshly generated or imported key to the slot at `index`:
    /// replace the key material, record the algorithm and origin, apply
    /// the requested policies (a `DEFAULT` pin policy restores the slot's
    /// factory policy, an absent request keeps what the slot had) and
    /// clear the slot certificate (the R5 decision: a replaced key
    /// invalidates the old certificate).
    fn commit_slot_key(
        &mut self,
        index: usize,
        key: SlotKey,
        imported: bool,
        pin_policy: Option<PinPolicy>,
        touch_policy: Option<TouchPolicy>,
    ) {
        let slot = &mut self.slots[index];
        slot.key = Some(key);
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
    use pkcs1::DecodeRsaPrivateKey;
    use rsa::traits::{PrivateKeyParts, PublicKeyParts};

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

    /// An IMPORT body: `06 <len> <scalar>` plus optional `AA`/`AB` members.
    fn ec_body(scalar: &[u8], pin: Option<u8>, touch: Option<u8>) -> Vec<u8> {
        let mut body = vec![0x06, scalar.len() as u8];
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
        let mut apdu = vec![0x00, INS_IMPORT_ASYM, alg, slot];
        if body.len() <= 255 {
            apdu.push(body.len() as u8);
        } else {
            // Extended Lc: `00 LL HH`.
            apdu.extend_from_slice(&[0x00, (body.len() >> 8) as u8, body.len() as u8]);
        }
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
            app.process(&import_apdu(0x11, 0x9E, &ec_body(&scalar, None, None)))
                .sw,
            SW_OK
        );
        // 9E is `NEVER` at the factory, so no VERIFY is needed: the GA
        // signing path signs the prehashed digest with the imported
        // scalar, verified under the point that scalar derives.
        let sk = SigningKey::from_slice(&scalar).expect("a valid scalar");
        let point = sk
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        crate::general_auth::tests::card_signature(&mut app, 0x9E, &point, &[0x2B; 32]);
    }

    /// The `81` modulus and `82` exponent in the `7F 49` template of an
    /// RSA GENERATE response.
    fn rsa_public_of(r: &Response) -> (Vec<u8>, Vec<u8>) {
        match parse_public_key(&r.data).expect("a well-formed public-key template") {
            PublicKey::Rsa { modulus, exponent } => (modulus, exponent),
            other => panic!("expected an RSA modulus, got {other:?}"),
        }
    }

    /// The GA sign round trip for an RSA slot: the host sends a raw block
    /// under the slot's algorithm id and the card's raw `m^d mod n` answer
    /// must satisfy `s^e == m (mod n)`.
    fn rsa_sign_check(app: &mut PivApplet, alg: KeyAlg, slot: u8, n: &[u8], e: &[u8], m: u8) {
        let mut block = vec![0u8; n.len()];
        block[n.len() - 1] = m;
        let r = app.process(&keyroost_piv::general_auth_sign(alg.id(), slot, &block));
        assert_eq!(r.sw, SW_OK, "signing GA: {r:?}");
        let s = keyroost_piv::parse_general_auth(&r.data, 0x82).expect("an 82 answer");
        assert_eq!(
            s.len(),
            n.len(),
            "the answer is zero-extended to the modulus size"
        );
        assert_eq!(
            BigUint::from_bytes_be(s)
                .modpow(&BigUint::from_bytes_be(e), &BigUint::from_bytes_be(n)),
            BigUint::from(m),
        );
    }

    /// An IMPORT body for the RSA branch: raw single-byte-length TLV members.
    fn rsa_members(members: &[(u8, &Vec<u8>)]) -> Vec<u8> {
        let mut body = Vec::new();
        for (tag, value) in members {
            body.push(*tag);
            body.push(value.len() as u8);
            body.extend_from_slice(value);
        }
        body
    }

    /// A host-side 1024-bit key with its CRT decomposition — the shape of
    /// the IMPORT body — and its private exponent.
    struct HostRsa {
        p: Vec<u8>,
        q: Vec<u8>,
        dp: Vec<u8>,
        dq: Vec<u8>,
        d: Vec<u8>,
        n: Vec<u8>,
    }

    fn host_rsa_1024() -> HostRsa {
        let host = RsaPrivateKey::new(&mut rand_core::OsRng, 1024).expect("a 1024-bit key");
        let (p, q) = (&host.primes()[0], &host.primes()[1]);
        let d = host.d().clone();
        let one = BigUint::from(1u32);
        HostRsa {
            p: p.to_bytes_be(),
            q: q.to_bytes_be(),
            dp: (d.clone() % (p.clone() - &one)).to_bytes_be(),
            dq: (d.clone() % (q.clone() - &one)).to_bytes_be(),
            d: d.to_bytes_be(),
            n: host.n().to_bytes_be(),
        }
    }

    #[test]
    fn generate_rsa1024_stores_pkcs1_and_signs() {
        let mut app = unlocked();
        let alg = KeyAlg::Rsa1024;
        // 9E is `NEVER` at the factory: the sign round trip needs no VERIFY.
        let r = app.process(&generate_key(
            Slot::CardAuthentication,
            alg.id(),
            PinPolicy::Default,
            TouchPolicy::Default,
        ));
        assert_eq!(r.sw, SW_OK, "GENERATE: {r:?}");
        let (n, e) = rsa_public_of(&r);
        assert_eq!(n.len(), 128);
        assert_ne!(n[127] & 1, 0, "the modulus is odd");
        assert_eq!(e, [0x01u8, 0x00, 0x01]);
        // The stored secret is the PKCS#1 key itself: it decodes and
        // carries the announced modulus and exponent.
        let key = app.slots[3].key.as_ref().expect("the generated key");
        let stored =
            RsaPrivateKey::from_pkcs1_der(key.secret.as_slice()).expect("a PKCS#1 RSAPrivateKey");
        assert_eq!(stored.n().to_bytes_be(), n);
        assert_eq!(stored.e().to_bytes_be(), e);
        rsa_sign_check(&mut app, alg, 0x9E, &n, &e, 0x2B);
    }

    #[test]
    fn imported_rsa_key_round_trips() {
        let mut app = unlocked();
        // Several keys so both `p < q` and `p > q` orderings are exercised.
        for _ in 0..4 {
            let host = host_rsa_1024();
            let body = rsa_members(&[
                (0x01, &host.p),
                (0x02, &host.q),
                (0x03, &host.dp),
                (0x04, &host.dq),
                (0x05, &host.n),
            ]);
            assert_eq!(
                app.process(&import_apdu(KeyAlg::Rsa1024.id(), 0x9E, &body))
                    .sw,
                SW_OK,
                "IMPORT"
            );
            // The stored key is the host key: same modulus, and the
            // exponent `from_p_q` derives from the primes — `e^{-1} mod
            // lambda(n)` with `lambda(n) = lcm(p-1, q-1)` — is exactly the
            // host's own `d` reduced to that modulus (the host's `d` is
            // generated modulo phi(n), a multiple of lambda(n)). The GA
            // round trip below proves the two sign the same thing.
            let key = app.slots[3].key.as_ref().expect("the imported key");
            let stored = RsaPrivateKey::from_pkcs1_der(key.secret.as_slice())
                .expect("a PKCS#1 RSAPrivateKey");
            assert_eq!(stored.n().to_bytes_be(), host.n);
            let one = BigUint::from(1u32);
            let lambda = (BigUint::from_bytes_be(&host.p) - &one)
                .lcm(&(BigUint::from_bytes_be(&host.q) - &one));
            assert_eq!(
                *stored.d(),
                BigUint::from_bytes_be(&host.d) % &lambda,
                "the stored exponent is the host's mod lambda(n)"
            );
            rsa_sign_check(
                &mut app,
                KeyAlg::Rsa1024,
                0x9E,
                &host.n,
                &[0x01, 0x00, 0x01],
                0x5A,
            );
        }
    }

    #[test]
    fn imported_rsa_refusals_leave_the_slot_empty() {
        let mut app = unlocked();
        let host = host_rsa_1024();
        let mut bad_n = host.n.clone();
        bad_n[64] ^= 1; // `p * q` no longer matches `n`
        let bad_dp = {
            let mut v = vec![0u8];
            v.extend_from_slice(&host.dp);
            v
        };
        let mut even_p = host.p.clone();
        let last = even_p.len() - 1;
        even_p[last] &= 0xFE;
        let bad_half = {
            let mut v = host.dp.clone();
            let last = v.len() - 1;
            v[last] ^= 0x01; // `dP` no longer matches `d mod (p-1)`
            v
        };
        let bodies: [Vec<u8>; 5] = [
            rsa_members(&[
                (0x01, &host.p),
                (0x02, &host.q),
                (0x03, &host.dp),
                (0x04, &host.dq),
                (0x05, &bad_n),
            ]),
            rsa_members(&[
                (0x01, &host.p),
                (0x02, &host.q),
                (0x04, &host.dq),
                (0x05, &host.n),
            ]), // missing dP
            rsa_members(&[
                (0x01, &host.p),
                (0x02, &host.q),
                (0x03, &bad_dp),
                (0x04, &host.dq),
                (0x05, &host.n),
            ]),
            rsa_members(&[
                (0x01, &even_p),
                (0x02, &host.q),
                (0x03, &host.dp),
                (0x04, &host.dq),
                (0x05, &host.n),
            ]),
            rsa_members(&[
                (0x01, &host.p),
                (0x02, &host.q),
                (0x03, &bad_half),
                (0x04, &host.dq),
                (0x05, &host.n),
            ]),
        ];
        for body in &bodies {
            assert_eq!(
                app.process(&import_apdu(KeyAlg::Rsa1024.id(), 0x9E, body))
                    .sw,
                SW_WRONG_DATA,
                "body {body:02X?}"
            );
        }
        assert!(app.slots[3].key.is_none());
    }

    /// Read an object back through the host's GET DATA builder; the test
    /// values are all small, so no `61xx` continuation is expected.
    fn read_object(app: &mut PivApplet, tag: &[u8]) -> Vec<u8> {
        let r = app.process(&keyroost_piv::get_data(tag));
        assert_eq!(r.sw, SW_OK, "GET DATA {tag:?}");
        keyroost_piv::unwrap_data_object(&r.data)
            .expect("a well-formed 53 template")
            .to_vec()
    }

    #[test]
    fn move_carries_key_and_policies_and_leaves_certs() {
        let mut app = PivApplet::new();
        mgmt_handshake(&mut app);
        let scalar = fixed_scalar();
        assert_eq!(
            app.process(&import_apdu(
                0x11,
                0x9C,
                &ec_body(&scalar, Some(0x02), Some(0x02))
            ))
            .sw,
            SW_OK
        );
        let cert_a = b"source-cert";
        let cert_b = b"dest-cert";
        assert_eq!(
            app.process(&keyroost_piv::put_data(&[0x5F, 0xC1, 0x0A], cert_a))
                .sw,
            SW_OK
        );
        assert_eq!(
            app.process(&keyroost_piv::put_data(&[0x5F, 0xC1, 0x0D], cert_b))
                .sw,
            SW_OK
        );

        assert_eq!(
            app.process(&keyroost_piv::move_key(
                keyroost_piv::Slot::Signature,
                keyroost_piv::Slot::retired(1).expect("retired 1"),
            ))
            .sw,
            SW_OK,
            "move"
        );
        let source = &app.slots[slot_index(0x9C).expect("9C")];
        let dest = &app.slots[slot_index(0x82).expect("retired 1")];
        assert!(source.key.is_none(), "the source keeps no key");
        assert_eq!(
            dest.key.as_ref().expect("the key moved").secret.as_slice(),
            &scalar
        );
        assert_eq!(dest.pin_policy, PinPolicy::Once);
        assert_eq!(dest.touch_policy, 0x02);
        assert!(dest.imported);
        // The certificate objects are left untouched (host contract).
        assert_eq!(read_object(&mut app, &[0x5F, 0xC1, 0x0A]), cert_a);
        assert_eq!(read_object(&mut app, &[0x5F, 0xC1, 0x0D]), cert_b);
    }

    #[test]
    fn delete_removes_only_the_key() {
        let mut app = PivApplet::new();
        mgmt_handshake(&mut app);
        let scalar = fixed_scalar();
        assert_eq!(
            app.process(&import_apdu(0x11, 0x9A, &ec_body(&scalar, None, None)))
                .sw,
            SW_OK
        );
        assert_eq!(
            app.process(&keyroost_piv::put_data(&[0x5F, 0xC1, 0x05], b"auth-cert"))
                .sw,
            SW_OK
        );

        assert_eq!(
            app.process(&keyroost_piv::delete_key(
                keyroost_piv::Slot::Authentication
            ))
            .sw,
            SW_OK,
            "delete"
        );
        let slot = &app.slots[slot_index(0x9A).expect("9A")];
        assert!(slot.key.is_none());
        assert_eq!(slot.pin_policy, PinPolicy::Once, "the policy is untouched");
        assert!(slot.cert.is_some(), "the certificate is untouched");
        assert_eq!(
            app.process(&keyroost_piv::get_metadata(0x9A)).sw,
            keyroost_piv::SW_REFERENCE_NOT_FOUND,
            "no key, so metadata reports the slot empty"
        );
    }

    #[test]
    fn move_and_delete_refuse_an_empty_source() {
        let mut app = PivApplet::new();
        mgmt_handshake(&mut app);
        // 9D is empty at the factory.
        assert_eq!(
            app.process(&keyroost_piv::move_key(
                keyroost_piv::Slot::KeyManagement,
                keyroost_piv::Slot::Authentication,
            ))
            .sw,
            SW_NOT_FOUND
        );
        assert_eq!(
            app.process(&keyroost_piv::delete_key(keyroost_piv::Slot::KeyManagement))
                .sw,
            SW_NOT_FOUND
        );
    }

    #[test]
    fn move_key_refusals() {
        let mut app = PivApplet::new();
        assert_eq!(
            app.process(&[0x00, 0xF6, 0x9C, 0x9A]).sw,
            SW_SECURITY_NOT_SATISFIED
        );
        mgmt_handshake(&mut app);
        // F9 is not in the slot table, in either position; neither is 9B.
        assert_eq!(app.process(&[0x00, 0xF6, 0xF9, 0x9A]).sw, SW_INCORRECT_P1P2);
        assert_eq!(app.process(&[0x00, 0xF6, 0x9C, 0xF9]).sw, SW_INCORRECT_P1P2);
        assert_eq!(app.process(&[0x00, 0xF6, 0x9B, 0x9A]).sw, SW_INCORRECT_P1P2);
        assert_eq!(
            app.process(&[0xFF, 0xF6, 0x9C, 0x9A]).sw,
            SW_CLA_NOT_SUPPORTED
        );
    }

    #[test]
    fn move_into_an_occupied_destination_is_refused() {
        let mut app = PivApplet::new();
        mgmt_handshake(&mut app);
        let scalar = fixed_scalar();
        let other = [0x5E; 32];
        assert_eq!(
            app.process(&import_apdu(0x11, 0x9C, &ec_body(&scalar, None, None)))
                .sw,
            SW_OK
        );
        assert_eq!(
            app.process(&import_apdu(0x11, 0x9D, &ec_body(&other, None, None)))
                .sw,
            SW_OK
        );

        // R1: an occupied destination (the source itself included) is
        // refused and nothing moves.
        assert_eq!(
            app.process(&keyroost_piv::move_key(
                keyroost_piv::Slot::Signature,
                keyroost_piv::Slot::KeyManagement,
            ))
            .sw,
            SW_WRONG_DATA
        );
        assert_eq!(
            app.process(&keyroost_piv::move_key(
                keyroost_piv::Slot::Signature,
                keyroost_piv::Slot::Signature,
            ))
            .sw,
            SW_WRONG_DATA
        );
        let source = &app.slots[slot_index(0x9C).expect("9C")];
        let dest = &app.slots[slot_index(0x9D).expect("9D")];
        assert_eq!(
            source.key.as_ref().expect("still there").secret.as_slice(),
            &scalar
        );
        assert_eq!(
            dest.key.as_ref().expect("still there").secret.as_slice(),
            &other
        );
    }

    /// A GENERATE APDU for a specific algorithm and slot: the host's own
    /// builder, so the test rides the exact wire shape.
    fn gen_apdu_for(slot: keyroost_piv::Slot, alg: KeyAlg) -> Vec<u8> {
        keyroost_piv::generate_key(slot, alg.id(), PinPolicy::Default, TouchPolicy::Default)
    }

    #[test]
    fn generate_produces_each_nist_curve() {
        let mut app = unlocked();
        // 9C: P-384, a 97-byte point on the curve.
        let r = app.process(&gen_apdu_for(
            keyroost_piv::Slot::Signature,
            KeyAlg::EccP384,
        ));
        assert_eq!(r.sw, SW_OK);
        let point = point_of(&r);
        assert_eq!(point.len(), 97);
        p384::ecdsa::VerifyingKey::from_sec1_bytes(&point).expect("a P-384 point");
        assert_eq!(
            app.slots[1].key.as_ref().expect("a key").alg,
            KeyAlg::EccP384
        );

        // 9D: P-521, a 133-byte point on the curve.
        let r = app.process(&gen_apdu_for(
            keyroost_piv::Slot::KeyManagement,
            KeyAlg::EccP521,
        ));
        assert_eq!(r.sw, SW_OK);
        let point = point_of(&r);
        assert_eq!(point.len(), 133);
        p521::ecdsa::VerifyingKey::from_sec1_bytes(&point).expect("a P-521 point");
        assert_eq!(
            app.slots[2].key.as_ref().expect("a key").alg,
            KeyAlg::EccP521
        );
    }

    #[test]
    fn import_accepts_p384_and_p521_scalars() {
        let mut app = unlocked();
        // P-384 into 9A: the slot then signs with the imported scalar —
        // verify the signature against the point of that scalar.
        let scalar: Vec<u8> = {
            let mut v = vec![0x2B; 48];
            v[47] = 0x01;
            v
        };
        let body = ec_body(&scalar, None, None);
        assert_eq!(
            app.process(&import_apdu(KeyAlg::EccP384.id(), 0x9A, &body))
                .sw,
            SW_OK
        );
        assert_eq!(
            app.slots[0].key.as_ref().expect("a key").alg,
            KeyAlg::EccP384
        );
        assert!(app.slots[0].imported);
        use p384::ecdsa::signature::hazmat::PrehashVerifier;
        use p384::elliptic_curve::sec1::ToEncodedPoint;
        let expected_point = p384::SecretKey::from_slice(&scalar)
            .expect("a valid scalar")
            .public_key()
            .to_encoded_point(false);
        let expected_point = expected_point.as_bytes();
        assert_eq!(
            app.process(&keyroost_piv::verify_pin(b"123456").unwrap())
                .sw,
            SW_OK
        );
        let digest = [0x2C; 48];
        let r = app.process(&keyroost_piv::general_auth_sign(
            KeyAlg::EccP384.id(),
            0x9A,
            &digest,
        ));
        assert_eq!(r.sw, SW_OK, "signing GA: {r:?}");
        let sig_der = keyroost_piv::parse_general_auth(&r.data, 0x82).expect("an 82 answer");
        let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(expected_point).expect("the point");
        let sig = p384::ecdsa::Signature::from_der(sig_der).expect("a DER signature");
        vk.verify_prehash(&digest, &sig).expect("a valid signature");

        // P-521 into the first retired slot. The scalar must sit below
        // the group order, whose leading byte is `0x01`.
        let scalar: Vec<u8> = {
            let mut v = vec![0x01; 66];
            v[65] = 0x01;
            v
        };
        let body = ec_body(&scalar, None, None);
        assert_eq!(
            app.process(&import_apdu(KeyAlg::EccP521.id(), 0x82, &body))
                .sw,
            SW_OK
        );
        assert_eq!(
            app.slots[4].key.as_ref().expect("a key").alg,
            KeyAlg::EccP521
        );
        assert!(app.slots[4].imported);
    }

    #[test]
    fn import_refuses_wrong_length_and_out_of_range_scalars() {
        let mut app = unlocked();
        // A length mismatch for the requested curve: 48 bytes for P-256,
        // 32 bytes for P-384, 48 bytes for P-521.
        let long: Vec<u8> = vec![0x2B; 48];
        let short = [0x2B; 32];
        let mid: Vec<u8> = vec![0x2B; 48];
        assert_eq!(
            app.process(&import_apdu(
                KeyAlg::EccP256.id(),
                0x9C,
                &ec_body(&long, None, None)
            ))
            .sw,
            SW_WRONG_DATA
        );
        assert_eq!(
            app.process(&import_apdu(
                KeyAlg::EccP384.id(),
                0x9C,
                &ec_body(&short, None, None)
            ))
            .sw,
            SW_WRONG_DATA
        );
        assert_eq!(
            app.process(&import_apdu(
                KeyAlg::EccP521.id(),
                0x9C,
                &ec_body(&mid, None, None)
            ))
            .sw,
            SW_WRONG_DATA
        );
        // Zero scalars and group orders, per curve: the range check refuses
        // them before the field conversion.
        for (alg, size) in [
            (KeyAlg::EccP256, 32usize),
            (KeyAlg::EccP384, 48usize),
            (KeyAlg::EccP521, 66usize),
        ] {
            let zero = vec![0u8; size];
            assert_eq!(
                app.process(&import_apdu(alg.id(), 0x9C, &ec_body(&zero, None, None)))
                    .sw,
                SW_WRONG_DATA
            );
            let order = match alg {
                KeyAlg::EccP256 => P256_ORDER.to_vec(),
                KeyAlg::EccP384 => P384_ORDER.to_vec(),
                KeyAlg::EccP521 => P521_ORDER.to_vec(),
                _ => unreachable!("a NIST curve"),
            };
            assert_eq!(
                app.process(&import_apdu(alg.id(), 0x9C, &ec_body(&order, None, None)))
                    .sw,
                SW_WRONG_DATA
            );
        }
        // Nothing landed in 9C.
        assert!(app.slots[1].key.is_none());
    }
}
