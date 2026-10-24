//! GENERAL AUTHENTICATE (0x87) — the SP 800-73-4 dynamic-auth half: the 9B
//! management-key witness / challenge exchange and the one-shot per-slot
//! ECDSA signing and ECDH key agreement of the NIST-curve slots.

use keyroost_piv::{KEY_REF_MANAGEMENT, KeyAlg, MgmtAlg};

use crate::constants::{
    GA_MAX_CHALLENGE, GA_TAG_CHALLENGE, GA_TAG_DYN_AUTH, GA_TAG_EXP, GA_TAG_RESPONSE,
    GA_TAG_WITNESS, SW_CLA_NOT_SUPPORTED, SW_DATA_INVALID, SW_INCORRECT_P1P2, SW_WRONG_DATA,
    SW_WRONG_LENGTH,
};
use crate::slot::{slot_index, SlotKey};
use crate::{PivApplet, Response, apdu_lc_body};

impl PivApplet {
    /// GENERAL AUTHENTICATE (0x87): the SP 800-73-4 dynamic-authentication
    /// exchange — the 9B management-key mutual auth this applet implements.
    ///
    /// The body is the dynamic-auth template `7C [80 witness] [81
    /// challenge] [82 response] [85 exponent]`, where an *empty* member
    /// names what the host wants (at most one) and a *non-empty* member
    /// carries data. Mirrors the card's `processGeneralAuth` /
    /// `processGenAuthSym` for P2=`9B`:
    ///
    /// - `6B00` when P1 is not the stored management algorithm, when P2 is
    ///   not a slot reference the applet knows, or — with an asymmetric P1
    ///   (`06`/`07`/`11`/`14`) — whenever: the slot holds no key.
    /// - The body is either an empty witness tag (`80`) — a witness
    ///   request — or a non-empty witness (`80`): the current challenge
    ///   encrypted with the management key (a re-issued witness invalidates
    ///   the pending one), optionally with the host's challenge under `81`.
    ///   Any other member or shape is refused `6B00`: the reference's
    ///   `81`/`82` shapes prove nothing to the applet.
    /// - A witness request issues a fresh challenge and answers
    ///   `7C 80 <n> <encrypted challenge>`. A correct witness sets the
    ///   slot's unlocked status and answers `9000` with no data, or
    ///   `7C 82 <n> <encrypted host challenge>` when one was offered;
    ///   a wrong witness — or one after the challenge was already
    ///   consumed — is `6A86`. Issue and check both re-lock the slot,
    ///   so a witness request after a successful handshake demands a
    ///   full mutual auth again.
    ///
    /// Every slot reference (9A/9C/9D/9E and the retired slots
    /// `82`–`95`) goes through the slot path: the slot's PIN policy is
    /// enforced (`6986` while it is not satisfied), the slot must hold a
    /// key and P1 must be the slot's algorithm byte (`6B00` otherwise),
    /// and the body is the one-shot dynamic-auth template — an empty `82`
    /// plus exactly one data member: a 32-byte digest under `81` (ECDSA
    /// signing — the applet signs the host's pre-hashed digest) or a
    /// 65-byte uncompressed peer point under `85` (ECDH — the applet
    /// answers the shared secret's x-coordinate). `9B` is the management
    /// key; every other P2 — `9F`, `58`–`5A`, the vendor-extension
    /// references, … — answers `6B00` outright.
    pub(crate) fn process_general_authenticate(&mut self, apdu: &[u8]) -> Response {
        let [cla, _, p1, p2, ..] = apdu else {
            // `process` guarantees the 4-byte header.
            unreachable!("process guarantees the 4-byte header");
        };
        if cla & 0x90 != 0 {
            return Response::sw(SW_CLA_NOT_SUPPORTED);
        }
        // P2 is the key reference: a slot reference goes to the slot path,
        // `9B` is the management key, everything else is refused.
        match slot_index(*p2) {
            Some(index) => self.ga_slot(index, *p1, apdu_lc_body(apdu)),
            None => match *p2 {
                KEY_REF_MANAGEMENT => self.ga_management(*p1, apdu_lc_body(apdu)),
                _ => Response::sw(SW_INCORRECT_P1P2),
            },
        }
    }

    /// The slot half of GENERAL AUTHENTICATE (9A/9C/9D/9E and the retired
    /// slots): the slot's PIN policy is enforced, the slot must hold a
    /// key, P1 must be the slot's algorithm byte, and the body is the
    /// one-shot dynamic-auth template — an empty `82` plus exactly one
    /// data member. The applet answers the signature or shared secret
    /// under `82`.
    fn ga_slot(
        &self,
        index: usize,
        p1: u8,
        lc_body: Result<(usize, &[u8], &[u8]), ()>,
    ) -> Response {
        if let Err(sw) = self.slot_pin_gate(&self.slots[index]) {
            return Response::sw(sw);
        }
        let Some(key) = self.slots[index].key.as_ref() else {
            return Response::sw(SW_INCORRECT_P1P2);
        };
        if p1 != key.alg.id() {
            return Response::sw(SW_INCORRECT_P1P2);
        }
        let (_lc, body, _) = match lc_body {
            Ok(triple) => triple,
            Err(()) => return Response::sw(SW_WRONG_LENGTH),
        };
        let t = match parse_ga_template(body) {
            Ok(t) => t,
            Err(sw) => return Response::sw(sw),
        };
        // The one-shot slot shape: an empty `82` plus a single data
        // member. Anything else is a wrong member.
        if t.wanted != Some(GA_TAG_RESPONSE) || t.response.is_some() || t.witness.is_some() {
            return Response::sw(SW_INCORRECT_P1P2);
        }
        match (t.challenge, t.exponent) {
            (Some(digest), None) => {
                // The member must be the slot's sign input: the curve's
                // field size for EC (the host hashes with the curve's
                // hash), the modulus size for RSA (the host's pre-encoded
                // DigestInfo block).
                let Some(size) = ga_sign_block_bytes(key.alg) else {
                    return Response::sw(SW_WRONG_DATA);
                };
                if digest.len() != size {
                    return Response::sw(SW_WRONG_DATA);
                }
                slot_sign(key, digest)
            }
            (None, Some(peer)) => {
                // The peer must be an uncompressed point of the slot curve.
                let Some(size) = ec_point_bytes(key.alg) else {
                    return Response::sw(SW_WRONG_DATA);
                };
                if peer.len() != size {
                    return Response::sw(SW_WRONG_DATA);
                }
                slot_ecdh(key, peer)
            }
            _ => Response::sw(SW_INCORRECT_P1P2),
        }
    }

    /// The 9B (management-key) half of GENERAL AUTHENTICATE: P1 selects the
    /// symmetric or an asymmetric algorithm, the body carries the
    /// dynamic-auth template.
    fn ga_management(
        &mut self,
        p1: u8,
        lc_body: Result<(usize, &[u8], &[u8]), ()>,
    ) -> Response {
        let (_lc, body, _) = match lc_body {
            Ok(triple) => triple,
            Err(()) => return Response::sw(SW_WRONG_LENGTH),
        };
        let tmpl = match parse_ga_template(body) {
            Ok(t) => t,
            Err(sw) => return Response::sw(sw),
        };
        match MgmtAlg::from_id(p1) {
            Some(alg) => self.ga_sym(alg, tmpl),
            // Asymmetric (or unknown) algorithm: no key slot, so no
            // exchange — the reference fails on the missing key.
            None => Response::sw(SW_INCORRECT_P1P2),
        }
    }

    /// The symmetric 9B dynamic-auth exchange (the card's
    /// `processGenAuthSym`), once the template is parsed.
    fn ga_sym(&mut self, alg: MgmtAlg, t: GaTemplate) -> Response {
        if self.mgmt.alg() != alg {
            return Response::sw(SW_INCORRECT_P1P2);
        }
        let bs = alg.block_size();
        // The witness flow is the only supported symmetric exchange: a
        // witness request (an empty `80`) or a witness value, optionally
        // with the host's challenge under `81`. The reference's other
        // shapes prove nothing — a `82` value is a replay of the card's
        // own ciphertext, a clear `81` challenge would let any observer
        // forge the witness, a wanted `81` hands the clear challenge to
        // whoever holds it — so they are refused.
        if t.response.is_some() {
            return Response::sw(SW_INCORRECT_P1P2);
        }
        match (t.wanted, t.witness, t.challenge) {
            (Some(GA_TAG_WITNESS), None, None) => {
                let enc = self.mgmt.issue();
                Response::ok(ga_response(GA_TAG_WITNESS, &enc))
            }
            (None, Some(w), host_chal) => {
                if w.len() != bs {
                    return Response::sw(SW_WRONG_DATA);
                }
                if host_chal.is_some_and(|hc| {
                    hc.is_empty() || hc.len() > GA_MAX_CHALLENGE || hc.len() % bs != 0
                }) {
                    return Response::sw(SW_WRONG_DATA);
                }
                match self.mgmt.check(w, host_chal) {
                    Ok(resp) => Response::ok(match resp {
                        Some(enc) => ga_response(GA_TAG_RESPONSE, &enc),
                        None => Vec::new(),
                    }),
                    Err(_) => Response::sw(SW_WRONG_DATA),
                }
            }
            _ => Response::sw(SW_INCORRECT_P1P2),
        }
    }
}

/// The size of the `81` member a GA signature on `alg` expects: the curve's
/// field byte size for EC (the host hashes with the curve's hash) and the
/// modulus size for RSA (the host sends the pre-encoded PKCS#1 v1.5
/// DigestInfo block — the card applies no padding).
fn ga_sign_block_bytes(alg: KeyAlg) -> Option<usize> {
    match alg {
        KeyAlg::EccP256 => Some(32),
        KeyAlg::EccP384 => Some(48),
        KeyAlg::EccP521 => Some(66),
        KeyAlg::Rsa1024 => Some(128),
        KeyAlg::Rsa2048 => Some(256),
        KeyAlg::Rsa3072 => Some(384),
        KeyAlg::Rsa4096 => Some(512),
        _ => None,
    }
}

/// The uncompressed-point size a GA key agreement on `alg` expects.
fn ec_point_bytes(alg: KeyAlg) -> Option<usize> {
    match alg {
        KeyAlg::EccP256 => Some(65),
        KeyAlg::EccP384 => Some(97),
        KeyAlg::EccP521 => Some(129),
        _ => None,
    }
}

/// The signature half of the slot GA: ECDSA for the EC slots (the host
/// sends the pre-hashed digest — hashed with the slot curve's hash, SHA-
/// 256/384/512 for P-256/384/521 — and the applet answers the DER-encoded
/// signature under `82`), the raw CRT operation for the RSA slots (the
/// host's pre-encoded DigestInfo block comes back raw under `82`).
fn slot_sign(key: &SlotKey, digest: &[u8]) -> Response {
    match key.alg {
        KeyAlg::EccP256 => sign_p256(key, digest),
        KeyAlg::EccP384 => sign_p384(key, digest),
        KeyAlg::EccP521 => sign_p521(key, digest),
        KeyAlg::Rsa1024 | KeyAlg::Rsa2048 | KeyAlg::Rsa3072 | KeyAlg::Rsa4096 => {
            slot_rsa_raw(key, digest)
        }
        _ => Response::sw(SW_WRONG_DATA),
    }
}

/// The RSA half of the slot GA: the raw `m^d mod n` operation. The host
/// sends the pre-encoded PKCS#1 v1.5 DigestInfo block — exactly the
/// modulus size, numerically below `n` — and the applet answers the
/// zero-extended raw signature block under `82`; the card applies no
/// padding, so a block that is not below `n` is refused rather than
/// mangled. The slot's PKCS#1 key is deserialized and the raw operation
/// runs through the `rsa` crate's hazmat `rsa_decrypt` — no blinding
/// (`rng = None`), no check — which works the key's CRT exponents when
/// they are present and falls back to `c^d mod n` otherwise.
fn slot_rsa_raw(key: &SlotKey, block: &[u8]) -> Response {
    use num_bigint_dig::BigUint;
    use pkcs1::DecodeRsaPrivateKey;
    use rsa::hazmat::rsa_decrypt;
    use rsa::RsaPrivateKey;
    use rsa::traits::PublicKeyParts;

    let key = match RsaPrivateKey::from_pkcs1_der(key.secret.as_slice()) {
        Ok(key) => key,
        Err(_) => return Response::sw(SW_WRONG_DATA),
    };
    let n = key.n().to_bytes_be();
    if block.len() != n.len() {
        return Response::sw(SW_WRONG_DATA);
    }
    let c = BigUint::from_bytes_be(block);
    if &c >= key.n() {
        return Response::sw(SW_WRONG_DATA);
    }
    let m = match rsa_decrypt::<rand_core::OsRng>(None, &key, &c) {
        Ok(m) => m,
        Err(_) => return Response::sw(SW_WRONG_DATA),
    };

    // Zero-extend the residue to the full modulus size.
    let m_be = m.to_bytes_be();
    let mut out = vec![0u8; n.len()];
    let offset = n.len() - m_be.len();
    out[offset..].copy_from_slice(&m_be);
    Response::ok(ga_response(GA_TAG_RESPONSE, &out))
}

/// The ECDSA half for one curve: the `32`/`48`/`66`-byte scalar is the
/// head of the slot's uniform `66`-byte buffer.
fn sign_p256(key: &SlotKey, digest: &[u8]) -> Response {
    use ecdsa::signature::hazmat::PrehashSigner;
    let signing = match ecdsa::SigningKey::<p256::NistP256>::from_slice(&key.secret[..32]) {
        Ok(signing) => signing,
        Err(_) => return Response::sw(SW_WRONG_DATA),
    };
    // The annotation pins the `Signature<C>` impl: with the `der` feature
    // the `PrehashSigner` impl for `der::Signature<C>` is also in scope.
    let sig: ecdsa::Signature<p256::NistP256> =
        match signing.sign_prehash(digest) {
            Ok(sig) => sig,
            Err(_) => return Response::sw(SW_WRONG_DATA),
        };
    Response::ok(ga_response(GA_TAG_RESPONSE, sig.to_der().as_bytes()))
}

/// The ECDSA half for P-384 (the host hashes with SHA-384).
fn sign_p384(key: &SlotKey, digest: &[u8]) -> Response {
    use ecdsa::signature::hazmat::PrehashSigner;
    let signing = match ecdsa::SigningKey::<p384::NistP384>::from_slice(&key.secret[..48]) {
        Ok(signing) => signing,
        Err(_) => return Response::sw(SW_WRONG_DATA),
    };
    let sig: ecdsa::Signature<p384::NistP384> =
        match signing.sign_prehash(digest) {
            Ok(sig) => sig,
            Err(_) => return Response::sw(SW_WRONG_DATA),
        };
    Response::ok(ga_response(GA_TAG_RESPONSE, sig.to_der().as_bytes()))
}

/// The ECDSA half for P-521 (the host hashes with SHA-512).
fn sign_p521(key: &SlotKey, digest: &[u8]) -> Response {
    use ecdsa::signature::hazmat::PrehashSigner;
    // `NistP521` does not implement the `ecdsa` crate's generic signing
    // bounds (no `DigestPrimitive` impl), so the curve's own key type
    // signs instead — the same `PrehashSigner` trait.
    let signing = match p521::ecdsa::SigningKey::from_slice(&key.secret[..]) {
        Ok(signing) => signing,
        Err(_) => return Response::sw(SW_WRONG_DATA),
    };
    let sig: ecdsa::Signature<p521::NistP521> =
        match signing.sign_prehash(digest) {
            Ok(sig) => sig,
            Err(_) => return Response::sw(SW_WRONG_DATA),
        };
    Response::ok(ga_response(GA_TAG_RESPONSE, sig.to_der().as_bytes()))
}

/// The ECDH half of the slot GA: the peer's uncompressed point is checked
/// on the slot's curve and the applet answers the shared secret — the
/// x-coordinate of the product, `32`/`48`/`66` bytes for
/// P-256/384/521 — as the raw value under `82`.
fn slot_ecdh(key: &SlotKey, peer: &[u8]) -> Response {
    match key.alg {
        KeyAlg::EccP256 => ecdh_p256(key, peer),
        KeyAlg::EccP384 => ecdh_p384(key, peer),
        KeyAlg::EccP521 => ecdh_p521(key, peer),
        _ => Response::sw(SW_WRONG_DATA),
    }
}

/// The ECDH half for one curve: the host sends the peer's uncompressed
/// point under `85` and the card answers the shared secret's x-coordinate
/// under `82`.
fn ecdh_p256(key: &SlotKey, peer: &[u8]) -> Response {
    let secret =
        match elliptic_curve::SecretKey::<p256::NistP256>::from_slice(&key.secret[..32]) {
            Ok(secret) => secret,
            Err(_) => return Response::sw(SW_WRONG_DATA),
        };
    let peer = match elliptic_curve::PublicKey::<p256::NistP256>::from_sec1_bytes(peer) {
        Ok(peer) => peer,
        Err(_) => return Response::sw(SW_WRONG_DATA),
    };
    let shared =
        elliptic_curve::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
    Response::ok(ga_response(GA_TAG_RESPONSE, shared.raw_secret_bytes()))
}

/// The ECDH half for P-384: the shared secret is the 48-byte x-coordinate.
fn ecdh_p384(key: &SlotKey, peer: &[u8]) -> Response {
    let secret =
        match elliptic_curve::SecretKey::<p384::NistP384>::from_slice(&key.secret[..48]) {
            Ok(secret) => secret,
            Err(_) => return Response::sw(SW_WRONG_DATA),
        };
    let peer = match elliptic_curve::PublicKey::<p384::NistP384>::from_sec1_bytes(peer) {
        Ok(peer) => peer,
        Err(_) => return Response::sw(SW_WRONG_DATA),
    };
    let shared =
        elliptic_curve::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
    Response::ok(ga_response(GA_TAG_RESPONSE, shared.raw_secret_bytes()))
}

/// The ECDH half for P-521: the shared secret is the 66-byte x-coordinate.
fn ecdh_p521(key: &SlotKey, peer: &[u8]) -> Response {
    let secret =
        match elliptic_curve::SecretKey::<p521::NistP521>::from_slice(&key.secret[..]) {
            Ok(secret) => secret,
            Err(_) => return Response::sw(SW_WRONG_DATA),
        };
    let peer = match elliptic_curve::PublicKey::<p521::NistP521>::from_sec1_bytes(peer) {
        Ok(peer) => peer,
        Err(_) => return Response::sw(SW_WRONG_DATA),
    };
    let shared =
        elliptic_curve::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
    Response::ok(ga_response(GA_TAG_RESPONSE, shared.raw_secret_bytes()))
}

/// One parsed SP 800-73-4 dynamic-auth template: the empty member the host
/// wants (if any), and the values of the non-empty members — the first of
/// each, as the card's rescan would find them.
#[derive(Default)]
struct GaTemplate<'a> {
    /// The single empty tag (`80`/`81`/`82`), if the host named one.
    wanted: Option<u8>,
    /// The first non-empty witness (`80`), if any.
    witness: Option<&'a [u8]>,
    /// The first non-empty challenge (`81`), if any.
    challenge: Option<&'a [u8]>,
    /// The first non-empty response (`82`), if any.
    response: Option<&'a [u8]>,
    /// The first non-empty exponent (`85`), if any.
    exponent: Option<&'a [u8]>,
}

/// Build the card's GA answer: the `7C` wrapper around one tagged value.
fn ga_response(tag: u8, value: &[u8]) -> Vec<u8> {
    fn length(data: &mut Vec<u8>, len: usize) {
        if len <= 127 {
            data.push(len as u8);
        } else if len < 256 {
            data.push(0x81);
            data.push(len as u8);
        } else {
            data.push(0x82);
            data.push((len >> 8) as u8);
            data.push(len as u8);
        }
    }
    let mut inner = vec![tag];
    length(&mut inner, value.len());
    inner.extend_from_slice(value);
    let mut data = vec![GA_TAG_DYN_AUTH];
    length(&mut data, inner.len());
    data.extend_from_slice(&inner);
    data
}

/// Parse the GA body as the card's dispatcher does: the `7C` wrapper (with
/// its own 1-, 2- or 3-byte length) followed by a scan of the members — the
/// scan runs to the end of the APDU body, not just the declared `7C`
/// length. `6B00` on a structurally broken template (truncated lengths,
/// underrun), `6A86` on a protocol violation (two empty tags, an unknown or
/// non-80/81/82 empty tag).
fn parse_ga_template<'a>(body: &'a [u8]) -> Result<GaTemplate<'a>, u16> {
    let Some((&outer, rest)) = body.split_first() else {
        return Err(SW_WRONG_DATA);
    };
    if outer != GA_TAG_DYN_AUTH {
        return Err(SW_WRONG_DATA);
    }
    let (declared, after_header) = read_tlv_length(rest)?;
    if rest.len() < after_header + declared {
        return Err(SW_DATA_INVALID);
    }
    let mut t = GaTemplate::default();
    // The scan region: everything after the 7C header — the reference's
    // stream ends at the APDU body's end, whatever the 7C length said.
    let mut rest = &body[1 + after_header..];
    while let Some((&tag, r1)) = rest.split_first() {
        // `r1` is everything after the tag byte: the length header plus the
        // value. The member consumes `thdr + tlen` of it.
        let (tlen, thdr) = read_tlv_length(r1)?;
        let value_end = thdr + tlen;
        if r1.len() < value_end {
            return Err(SW_DATA_INVALID);
        }
        let value = &r1[thdr..value_end];
        if tlen == 0 {
            if t.wanted.is_some() {
                return Err(SW_WRONG_DATA);
            }
            match tag {
                GA_TAG_WITNESS | GA_TAG_CHALLENGE | GA_TAG_RESPONSE => {
                    t.wanted = Some(tag);
                }
                _ => return Err(SW_WRONG_DATA),
            }
        } else {
            match tag {
                GA_TAG_WITNESS => {
                    if t.witness.is_none() {
                        t.witness = Some(value);
                    }
                }
                GA_TAG_RESPONSE => {
                    if t.response.is_none() {
                        t.response = Some(value);
                    }
                }
                GA_TAG_CHALLENGE => {
                    if t.challenge.is_none() {
                        t.challenge = Some(value);
                    }
                }
                GA_TAG_EXP => {
                    if t.exponent.is_none() {
                        t.exponent = Some(value);
                    }
                }
                _ => return Err(SW_WRONG_DATA),
            }
        }
        rest = &r1[value_end..];
    }
    Ok(t)
}

/// Read a PIV TLV length (short form, or `81`/`82` long form) and return
/// (value, header bytes consumed). `6B00` on truncation or an invalid
/// length byte (`80`, `83`+).
fn read_tlv_length(buf: &[u8]) -> Result<(usize, usize), u16> {
    match buf.first().copied() {
        Some(n) if n <= 0x7F => Ok((usize::from(n), 1)),
        Some(0x81) => {
            let b = *buf.get(1).ok_or(SW_DATA_INVALID)?;
            Ok((usize::from(b), 2))
        }
        Some(0x82) => {
            let b = buf.get(2..4).ok_or(SW_DATA_INVALID)?;
            let v = (usize::from(b[0])) << 8 | usize::from(b[1]);
            Ok((v, 3))
        }
        _ => Err(SW_DATA_INVALID),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::constants::{
        DEFAULT_MGMT_KEY, DEFAULT_PUK_TRIES, SW_OK, SW_SECURITY_STATUS_NOT_SATISFIED,
    };
    use crate::tries_sw;
    use aes::cipher::{BlockDecrypt, KeyInit};

    /// The GA dynamic-auth body: `7C` wrapping the given tagged members.
    pub(crate) fn ga_body(members: &[&[u8]]) -> Vec<u8> {
        let mut inner = Vec::new();
        for m in members {
            inner.extend_from_slice(m);
        }
        let mut body = vec![0x7C, inner.len() as u8];
        body.extend_from_slice(&inner);
        body
    }

    /// A GA APDU: `00 87 p1 9B Lc body`.
    pub(crate) fn ga_apdu(p1: u8, body: &[u8]) -> Vec<u8> {
        let mut apdu = vec![0x00, 0x87, p1, KEY_REF_MANAGEMENT, body.len() as u8];
        apdu.extend_from_slice(body);
        apdu
    }

    /// A full 9B management-key handshake against a fresh applet using the
    /// factory 3DES key: a witness round, then a response round proving the
    /// witness — afterwards the session is unlocked.
    /// The host's management-key handshake (keyroost-transport's
    /// `authenticate_management`), factory 3DES: the witness round, then
    /// the decrypted witness plus a fresh host challenge — the exact APDUs
    /// `general_auth_request_witness` and `general_auth_mutual` build.
    /// Returns the card's step-2 `7C` data and the host challenge the
    /// caller can check the card encrypted.
    pub(crate) fn mgmt_handshake(applet: &mut PivApplet) -> (Vec<u8>, [u8; 8]) {
        // Step 1 (general_auth_request_witness): 7C 02 80 00.
        let r = applet.process(&ga_apdu(0x03, &ga_body(&[&[0x80, 0x00]])));
        assert_eq!(r.sw, SW_OK, "witness round: {r:?}");
        assert_eq!(r.data[0], 0x7C);
        // The 7C wraps tag + length + 8-byte value: 2 + 8.
        assert_eq!(r.data[1], 10);
        assert_eq!(r.data[2], 0x80);
        assert_eq!(r.data[3], 8);
        // The host decrypts the witness with the management key — the
        // clear challenge is the key proof.
        let witness = des_decrypt(&r.data[4..12]);
        // Step 2 (general_auth_mutual): the clear witness plus a fresh
        // host challenge; the card answers 7C .. 82 .. <enc(challenge)>.
        let challenge: [u8; 8] = [0x42; 8];
        let mut members = vec![0x80, 0x08];
        members.extend_from_slice(&witness);
        members.extend_from_slice(&[0x81, 0x08]);
        members.extend_from_slice(&challenge);
        let r = applet.process(&ga_apdu(0x03, &ga_body(&[&members])));
        assert_eq!(r.sw, SW_OK, "mutual round: {r:?}");
        assert_eq!(r.data[0], 0x7C);
        assert_eq!(r.data[2], 0x82);
        assert_eq!(r.data[3], 8);
        (r.data, challenge)
    }

    /// Decrypt an 8-byte block with the stored 3DES management key.
    fn des_decrypt(data: &[u8]) -> [u8; 8] {
        let c = des::TdesEde3::new_from_slice(&DEFAULT_MGMT_KEY).unwrap();
        let mut block = cipher::generic_array::GenericArray::clone_from_slice(data);
        c.decrypt_block(&mut block);
        block.into()
    }

    /// Burn every PUK retry with wrong PUKs, asserting each `63Cx` along
    /// the way; afterwards the PUK is blocked.
    pub(crate) fn block_puk(applet: &mut PivApplet) {
        for tries in (1..=DEFAULT_PUK_TRIES).rev() {
            let resp = applet.process(&keyroost_piv::unblock_pin(b"00000000", b"123456").unwrap());
            assert_eq!(resp.sw, tries_sw(tries - 1));
        }
    }

    #[test]
    fn ga_witness_round_answers_an_encrypted_challenge() {
        let mut applet = PivApplet::new();
        let r1 = applet.process(&ga_apdu(0x03, &ga_body(&[&[0x80, 0x00]])));
        assert_eq!(r1.sw, SW_OK);
        assert_eq!(r1.data.len(), 12);
        let r2 = applet.process(&ga_apdu(0x03, &ga_body(&[&[0x80, 0x00]])));
        assert_eq!(r2.sw, SW_OK);
        // A fresh challenge every time — the witnesses differ.
        assert_ne!(&r1.data[4..12], &r2.data[4..12]);
    }

    #[test]
    fn ga_full_handshake_unlocks_and_responds() {
        let mut applet = PivApplet::new();
        let (data, challenge) = mgmt_handshake(&mut applet);
        // Mutual auth: the 0x82 response decrypts to the host challenge.
        assert_eq!(des_decrypt(&data[4..12]), challenge);
    }

    /// A management write, the way the set-management-key command sends
    /// it: the 9B key reference, the 24-byte 3DES length, a zero key.
    fn set_mgmt_key_apdu() -> Vec<u8> {
        let mut apdu = vec![0x00, 0xFF, 0xFF, 0xFF, 27];
        apdu.extend_from_slice(&[0x03, KEY_REF_MANAGEMENT, 0x18]);
        apdu.extend_from_slice(&[0u8; 24]);
        apdu
    }

    #[test]
    fn ga_witness_request_re_locks_the_slot() {
        let mut applet = PivApplet::new();
        mgmt_handshake(&mut applet);
        // The session is unlocked: a management write goes through.
        let apdu = set_mgmt_key_apdu();
        let r = applet.process(&apdu);
        assert_eq!(r.sw, SW_OK, "unlocked session: {r:?}");
        // A witness request re-locks the slot (issue() clears the flag)...
        let r = applet.process(&ga_apdu(0x03, &ga_body(&[&[0x80, 0x00]])));
        assert_eq!(r.sw, SW_OK);
        // ...so the same write now fails until a full mutual auth again.
        let r = applet.process(&apdu);
        assert_eq!(r.sw, SW_SECURITY_STATUS_NOT_SATISFIED, "re-locked: {r:?}");
    }

    #[test]
    fn ga_challenged_body_without_a_witness_is_incorrect_p1p2() {
        let mut applet = PivApplet::new();
        // Only a non-empty challenge, no witness: the shape is refused
        // outright — there is nothing to check it against, and a clear
        // challenge proves nothing.
        let r = applet.process(&ga_apdu(
            0x03,
            &ga_body(&[&[0x81, 0x08, 0, 1, 2, 3, 4, 5, 6, 7]]),
        ));
        assert_eq!(r.sw, SW_INCORRECT_P1P2);
        // After a handshake the answer is the same — the shape, not the
        // state, is what is refused.
        mgmt_handshake(&mut applet);
        let r = applet.process(&ga_apdu(
            0x03,
            &ga_body(&[&[0x81, 0x08, 0, 1, 2, 3, 4, 5, 6, 7]]),
        ));
        assert_eq!(r.sw, SW_INCORRECT_P1P2);
    }

    #[test]
    fn ga_wrong_witness_is_wrong_data_and_consumes_the_challenge() {
        let mut applet = PivApplet::new();
        let r1 = applet.process(&ga_apdu(0x03, &ga_body(&[&[0x80, 0x00]])));
        assert_eq!(r1.sw, SW_OK);
        // A corrupted witness — the applet's challenge is consumed.
        let mut bad = vec![0x80, 0x08];
        bad.extend_from_slice(&r1.data[4..12]);
        bad[2] ^= 1;
        let r = applet.process(&ga_apdu(0x03, &ga_body(&[&bad])));
        assert_eq!(r.sw, SW_WRONG_DATA);
        // The real witness no longer verifies — the challenge is gone.
        let mut good = vec![0x80, 0x08];
        good.extend_from_slice(&r1.data[4..12]);
        let r = applet.process(&ga_apdu(0x03, &ga_body(&[&good])));
        assert_eq!(r.sw, SW_WRONG_DATA);
    }

    #[test]
    fn ga_reissued_witness_invalidates_the_old_one() {
        let mut applet = PivApplet::new();
        let r1 = applet.process(&ga_apdu(0x03, &ga_body(&[&[0x80, 0x00]])));
        let r2 = applet.process(&ga_apdu(0x03, &ga_body(&[&[0x80, 0x00]])));
        assert_eq!(r1.sw, SW_OK);
        assert_eq!(r2.sw, SW_OK);
        // Presenting the first witness fails — the second issued it away.
        let mut body = vec![0x80, 0x08];
        body.extend_from_slice(&r1.data[4..12]);
        let r = applet.process(&ga_apdu(0x03, &ga_body(&[&body])));
        assert_eq!(r.sw, SW_WRONG_DATA);
    }

    #[test]
    fn ga_response_member_is_incorrect_p1p2() {
        let mut applet = PivApplet::new();
        // A 0x82 member is refused outright — a replay of the card's own
        // ciphertext proves nothing, so its length is never even looked at.
        let body = ga_body(&[&[0x82, 4, 0, 1, 2, 3]]);
        let r = applet.process(&ga_apdu(0x03, &body));
        assert_eq!(r.sw, SW_INCORRECT_P1P2);
    }

    #[test]
    fn ga_wrong_algorithm_is_incorrect_p1p2() {
        let mut applet = PivApplet::new();
        // The applet is 3DES; P1 = AES-256 is not its algorithm.
        let r = applet.process(&ga_apdu(0x0C, &ga_body(&[&[0x80, 0x00]])));
        assert_eq!(r.sw, SW_INCORRECT_P1P2);
        // And an asymmetric P1 with a signing-shaped body too.
        let mut members = vec![0x81, 0x08, 0, 1, 2, 3, 4, 5, 6, 7];
        members.extend_from_slice(&[0x82, 0x00]);
        let r = applet.process(&ga_apdu(0x14, &ga_body(&[&members])));
        assert_eq!(r.sw, SW_INCORRECT_P1P2);
    }

    #[test]
    fn ga_slot_refs_are_policy_gated_and_non_slot_p2s_refused() {
        let mut applet = PivApplet::new();
        // Non-slot P2s: `6B00` outright.
        for p2 in [0x58u8, 0x00u8] {
            let r = applet.process(&ga_apdu_for_p2(p2));
            assert_eq!(r.sw, SW_INCORRECT_P1P2);
        }
        // 9E is a slot (factory NEVER) — ungated, refused for the missing
        // key.
        let r = applet.process(&ga_apdu_for_p2(0x9E));
        assert_eq!(r.sw, SW_INCORRECT_P1P2);
        // 9A/9C/9D and the retired slots: PIN-gated — locked first.
        for p2 in [0x9Au8, 0x9Cu8, 0x9Du8, 0x82u8, 0x8Cu8] {
            let r = applet.process(&ga_apdu_for_p2(p2));
            assert_eq!(r.sw, SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        // After the PIN is verified the applet has no key material for
        // them. The ONCE slots pass on the session flag; the ALWAYS latch
        // is consumed by the first slot APDU, so the 9C GA that does not
        // follow the VERIFY is gated again.
        let r = applet.process(&keyroost_piv::verify_pin(b"123456").unwrap());
        assert_eq!(r.sw, SW_OK);
        let r = applet.process(&ga_apdu_for_p2(0x9A));
        assert_eq!(r.sw, SW_INCORRECT_P1P2);
        let r = applet.process(&ga_apdu_for_p2(0x9C));
        assert_eq!(r.sw, SW_SECURITY_STATUS_NOT_SATISFIED);
        for p2 in [0x9Du8, 0x82u8, 0x8Cu8] {
            let r = applet.process(&ga_apdu_for_p2(p2));
            assert_eq!(r.sw, SW_INCORRECT_P1P2);
        }
    }

    /// A GA APDU for a slot reference other than 9B: `00 87 00 p2 00`.
    fn ga_apdu_for_p2(p2: u8) -> Vec<u8> {
        vec![0x00, 0x87, 0x00, p2, 0x00]
    }

    #[test]
    fn ga_broken_templates_are_wrong_length_or_wrong_data() {
        let mut applet = PivApplet::new();
        // Lc overrunning the APDU.
        let r = applet.process(&[0x00, 0x87, 0x03, KEY_REF_MANAGEMENT, 0x08, 0x7C, 0x00]);
        assert_eq!(r.sw, SW_WRONG_LENGTH);
        // No 7C wrapper at all.
        let r = applet.process(&ga_apdu(0x03, &[0x80, 0x00]));
        assert_eq!(r.sw, SW_WRONG_DATA);
        // Two empty tags.
        let r = applet.process(&ga_apdu(0x03, &ga_body(&[&[0x80, 0x00], &[0x81, 0x00]])));
        assert_eq!(r.sw, SW_WRONG_DATA);
        // An unknown empty tag.
        let r = applet.process(&ga_apdu(0x03, &ga_body(&[&[0x85, 0x00]])));
        assert_eq!(r.sw, SW_WRONG_DATA);
        // A member that overruns the body.
        let r = applet.process(&ga_apdu(0x03, &ga_body(&[&[0x81, 0x08, 0, 1, 2]])));
        assert_eq!(r.sw, SW_DATA_INVALID);
        // The 7C wrapper's length underdeclared: the scan still runs to the
        // end of the body — here to a second empty tag, a protocol error.
        let body = vec![0x7C, 0x02, 0x80, 0x00, 0x81, 0x00];
        let r = applet.process(&ga_apdu(0x03, &body));
        assert_eq!(r.sw, SW_WRONG_DATA);
    }

    #[test]
    fn ga_rejects_cla_bits() {
        let mut applet = PivApplet::new();
        let mut apdu = ga_apdu(0x03, &ga_body(&[&[0x80, 0x00]]));
        apdu[0] = 0x80;
        let r = applet.process(&apdu);
        assert_eq!(r.sw, SW_CLA_NOT_SUPPORTED);
    }

    /// Management unlock plus a key of `alg` in `slot`; returns the
    /// uncompressed public point the card announced.
    fn slot_with_key(applet: &mut PivApplet, slot: keyroost_piv::Slot, alg: keyroost_piv::KeyAlg) -> Vec<u8> {
        mgmt_handshake(applet);
        let r = applet.process(&keyroost_piv::generate_key(
            slot,
            alg.id(),
            keyroost_piv::PinPolicy::Default,
            keyroost_piv::TouchPolicy::Default,
        ));
        assert_eq!(r.sw, SW_OK, "GENERATE: {r:?}");
        match keyroost_piv::parse_public_key(&r.data).expect("a well-formed public-key template") {
            keyroost_piv::PublicKey::Ecc { point } => point,
            other => panic!("expected an EC point, got {other:?}"),
        }
    }

    /// Management unlock plus a P-256 key in `slot`.
    fn slot_with_p256(applet: &mut PivApplet, slot: keyroost_piv::Slot) -> Vec<u8> {
        slot_with_key(applet, slot, keyroost_piv::KeyAlg::EccP256)
    }

    /// Run the host's signing GA against the slot and verify the card's
    /// DER signature under the point the card announced.
    pub(crate) fn card_signature(applet: &mut PivApplet, key_ref: u8, point: &[u8], digest: &[u8; 32]) {
        use p256::ecdsa::signature::hazmat::PrehashVerifier;
        let r = applet.process(&keyroost_piv::general_auth_sign(
            keyroost_piv::KeyAlg::EccP256.id(),
            key_ref,
            digest,
        ));
        assert_eq!(r.sw, SW_OK, "signing GA: {r:?}");
        let sig_der = keyroost_piv::parse_general_auth(&r.data, 0x82).expect("an 82 answer");
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(point).expect("the announced point");
        let sig = p256::ecdsa::Signature::from_der(sig_der).expect("a DER signature");
        vk.verify_prehash(digest, &sig).expect("a valid signature");
    }

    #[test]
    fn ga_slot_signs_the_hosts_prehashed_digest() {
        let mut applet = PivApplet::new();
        let point = slot_with_p256(&mut applet, keyroost_piv::Slot::Authentication); // 9A: ONCE
        assert_eq!(
            applet.process(&keyroost_piv::verify_pin(b"123456").unwrap()).sw,
            SW_OK
        );
        card_signature(&mut applet, 0x9A, &point, &[0x2B; 32]);
    }

    #[test]
    fn ga_slot_ecdh_answers_the_shared_x_coordinate() {
        let mut applet = PivApplet::new();
        let point = slot_with_p256(&mut applet, keyroost_piv::Slot::CardAuthentication); // 9E: NEVER
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let mut rng = rand_core::OsRng;
        let peer = p256::ecdh::EphemeralSecret::random(&mut rng);
        let r = applet.process(&keyroost_piv::general_auth_key_agree(
            keyroost_piv::KeyAlg::EccP256.id(),
            0x9E,
            peer.public_key().to_encoded_point(false).as_bytes(),
        ));
        assert_eq!(r.sw, SW_OK, "key agreement GA: {r:?}");
        let z = keyroost_piv::parse_general_auth(&r.data, 0x82).expect("an 82 answer");
        assert_eq!(z.len(), 32);
        let card_pub = p256::PublicKey::from_sec1_bytes(&point).expect("the announced point");
        let expected = peer.diffie_hellman(&card_pub);
        assert_eq!(z, expected.raw_secret_bytes().as_slice());
    }

    #[test]
    fn ga_slot_signs_a_p384_digest() {
        let mut applet = PivApplet::new();
        let point = slot_with_key(
            &mut applet,
            keyroost_piv::Slot::Authentication, // 9A: ONCE
            keyroost_piv::KeyAlg::EccP384,
        );
        assert_eq!(point.len(), 97);
        assert_eq!(
            applet.process(&keyroost_piv::verify_pin(b"123456").unwrap()).sw,
            SW_OK
        );
        let digest = [0x2C; 48];
        let r = applet.process(&keyroost_piv::general_auth_sign(
            keyroost_piv::KeyAlg::EccP384.id(),
            0x9A,
            &digest,
        ));
        assert_eq!(r.sw, SW_OK, "signing GA: {r:?}");
        let sig_der = keyroost_piv::parse_general_auth(&r.data, 0x82).expect("an 82 answer");
        use p384::ecdsa::signature::hazmat::PrehashVerifier;
        let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(&point).expect("the announced point");
        let sig = p384::ecdsa::Signature::from_der(sig_der).expect("a DER signature");
        vk.verify_prehash(&digest, &sig).expect("a valid signature");
    }

    #[test]
    fn ga_slot_ecdh_answers_the_p384_shared_x_coordinate() {
        let mut applet = PivApplet::new();
        let point = slot_with_key(
            &mut applet,
            keyroost_piv::Slot::CardAuthentication, // 9E: NEVER
            keyroost_piv::KeyAlg::EccP384,
        );
        use p384::elliptic_curve::sec1::ToEncodedPoint;
        let mut rng = rand_core::OsRng;
        let peer = p384::ecdh::EphemeralSecret::random(&mut rng);
        let r = applet.process(&keyroost_piv::general_auth_key_agree(
            keyroost_piv::KeyAlg::EccP384.id(),
            0x9E,
            peer.public_key().to_encoded_point(false).as_bytes(),
        ));
        assert_eq!(r.sw, SW_OK, "key agreement GA: {r:?}");
        let z = keyroost_piv::parse_general_auth(&r.data, 0x82).expect("an 82 answer");
        assert_eq!(z.len(), 48);
        let card_pub = p384::PublicKey::from_sec1_bytes(&point).expect("the announced point");
        let expected = peer.diffie_hellman(&card_pub);
        assert_eq!(z, expected.raw_secret_bytes().as_slice());
    }

    #[test]
    fn ga_slot_always_policy_tracks_the_verify() {
        let mut applet = PivApplet::new();
        let point = slot_with_p256(&mut applet, keyroost_piv::Slot::Signature); // 9C: ALWAYS
        let digest = [0x5A; 32];
        // No VERIFY: gated.
        let r = applet.process(&keyroost_piv::general_auth_sign(
            keyroost_piv::KeyAlg::EccP256.id(),
            0x9C,
            &digest,
        ));
        assert_eq!(r.sw, SW_SECURITY_STATUS_NOT_SATISFIED);
        // A VERIFY followed by another APDU consumes the latch: gated again.
        assert_eq!(
            applet.process(&keyroost_piv::verify_pin(b"123456").unwrap()).sw,
            SW_OK
        );
        assert_eq!(applet.process(&keyroost_piv::select_full()).sw, SW_OK);
        let r = applet.process(&keyroost_piv::general_auth_sign(
            keyroost_piv::KeyAlg::EccP256.id(),
            0x9C,
            &digest,
        ));
        assert_eq!(r.sw, SW_SECURITY_STATUS_NOT_SATISFIED);
        // A VERIFY immediately followed by the GA: the signature verifies
        // under the announced point.
        assert_eq!(
            applet.process(&keyroost_piv::verify_pin(b"123456").unwrap()).sw,
            SW_OK
        );
        card_signature(&mut applet, 0x9C, &point, &digest);
    }

    #[test]
    fn ga_slot_refuses_a_p1_that_is_not_the_slots_algorithm() {
        let mut applet = PivApplet::new();
        let _point = slot_with_p256(&mut applet, keyroost_piv::Slot::Authentication);
        assert_eq!(
            applet.process(&keyroost_piv::verify_pin(b"123456").unwrap()).sw,
            SW_OK
        );
        let r = applet.process(&keyroost_piv::general_auth_sign(
            keyroost_piv::KeyAlg::EccP384.id(),
            0x9A,
            &[0x2B; 32],
        ));
        assert_eq!(r.sw, SW_INCORRECT_P1P2);
    }

    #[test]
    fn ga_slot_rsa_signs_the_hosts_preencoded_block() {
        let mut applet = PivApplet::new();
        mgmt_handshake(&mut applet);
        // 9E is `NEVER` at the factory: the sign round trip needs no VERIFY.
        let r = applet.process(&keyroost_piv::generate_key(
            keyroost_piv::Slot::CardAuthentication,
            keyroost_piv::KeyAlg::Rsa1024.id(),
            keyroost_piv::PinPolicy::Default,
            keyroost_piv::TouchPolicy::Default,
        ));
        assert_eq!(r.sw, SW_OK, "GENERATE: {r:?}");
        let (n, e) = match keyroost_piv::parse_public_key(&r.data).expect("a template") {
            keyroost_piv::PublicKey::Rsa { modulus, exponent } => (modulus, exponent),
            other => panic!("expected an RSA modulus, got {other:?}"),
        };
        // The host's pre-encoded DigestInfo block — exactly the modulus size.
        let mut block = vec![0u8; n.len()];
        block[n.len() - 1] = 0x2B;
        let r = applet.process(&keyroost_piv::general_auth_sign(
            keyroost_piv::KeyAlg::Rsa1024.id(),
            0x9E,
            &block,
        ));
        assert_eq!(r.sw, SW_OK, "signing GA: {r:?}");
        let s = keyroost_piv::parse_general_auth(&r.data, 0x82).expect("an 82 answer");
        assert_eq!(s.len(), n.len(), "the answer is zero-extended to the modulus size");
        use num_bigint_dig::BigUint;
        assert_eq!(
            BigUint::from_bytes_be(s)
                .modpow(&BigUint::from_bytes_be(&e), &BigUint::from_bytes_be(&n)),
            BigUint::from(0x2Bu8),
            "s^e == m (mod n)"
        );
        // A short block is the wrong length, whatever it says.
        let r = applet.process(&keyroost_piv::general_auth_sign(
            keyroost_piv::KeyAlg::Rsa1024.id(),
            0x9E,
            &block[..block.len() - 1],
        ));
        assert_eq!(r.sw, SW_WRONG_DATA);
        // A block >= n is not a valid residue.
        let r = applet.process(&keyroost_piv::general_auth_sign(
            keyroost_piv::KeyAlg::Rsa1024.id(),
            0x9E,
            &n,
        ));
        assert_eq!(r.sw, SW_WRONG_DATA);
    }

    #[test]
    fn ga_to_the_attest_slot_is_not_dispatched() {
        let mut applet = PivApplet::new();
        let r = applet.process(&keyroost_piv::general_auth_sign(
            keyroost_piv::KeyAlg::EccP256.id(),
            0xF9,
            &[0x2B; 32],
        ));
        assert_eq!(r.sw, SW_INCORRECT_P1P2);
    }

    #[test]
    fn ga_slot_sign_wants_exactly_a_32_byte_digest() {
        let mut applet = PivApplet::new();
        let _point = slot_with_p256(&mut applet, keyroost_piv::Slot::Authentication);
        assert_eq!(
            applet.process(&keyroost_piv::verify_pin(b"123456").unwrap()).sw,
            SW_OK
        );
        let r = applet.process(&keyroost_piv::general_auth_sign(
            keyroost_piv::KeyAlg::EccP256.id(),
            0x9A,
            &[0x2B; 20],
        ));
        assert_eq!(r.sw, SW_WRONG_DATA);
    }

    #[test]
    fn ga_slot_ecdh_wants_a_65_byte_point_on_the_curve() {
        let mut applet = PivApplet::new();
        let _point = slot_with_p256(&mut applet, keyroost_piv::Slot::CardAuthentication);
        // 64 bytes: not a point encoding.
        let r = applet.process(&keyroost_piv::general_auth_key_agree(
            keyroost_piv::KeyAlg::EccP256.id(),
            0x9E,
            &[0x04; 64],
        ));
        assert_eq!(r.sw, SW_WRONG_DATA);
        // 65 bytes but off the curve.
        let mut off_curve = [0x11; 65];
        off_curve[0] = 0x04;
        let r = applet.process(&keyroost_piv::general_auth_key_agree(
            keyroost_piv::KeyAlg::EccP256.id(),
            0x9E,
            &off_curve,
        ));
        assert_eq!(r.sw, SW_WRONG_DATA);
    }

    #[test]
    fn ga_slot_refuses_wrong_member_shapes() {
        let mut applet = PivApplet::new();
        let _point = slot_with_p256(&mut applet, keyroost_piv::Slot::Authentication);
        assert_eq!(
            applet.process(&keyroost_piv::verify_pin(b"123456").unwrap()).sw,
            SW_OK
        );
        let digest = [0x2B; 32];
        // A non-empty 82 member: not the one-shot slot shape.
        let mut body = vec![0x7C, 3 + 4 + 34, 0x82, 0x04, 0xDE, 0xAD, 0xBE, 0xEF, 0x81, 0x20];
        body.extend_from_slice(&digest);
        let mut apdu = vec![0x00, 0x87, 0x11, 0x9A, body.len() as u8];
        apdu.extend_from_slice(&body);
        apdu.push(0x00);
        let r = applet.process(&apdu);
        assert_eq!(r.sw, SW_INCORRECT_P1P2);
        // Both an 81 and an 85 member: not the one-shot slot shape.
        let mut body = vec![0x7C, 3 + 34 + 2 + 65, 0x81, 0x20];
        body.extend_from_slice(&digest);
        body.extend_from_slice(&[0x85, 0x41, 0x04]);
        body.extend_from_slice(&[0x02; 64]);
        let mut apdu = vec![0x00, 0x87, 0x11, 0x9A, body.len() as u8];
        apdu.extend_from_slice(&body);
        apdu.push(0x00);
        let r = applet.process(&apdu);
        assert_eq!(r.sw, SW_INCORRECT_P1P2);
        // A lone empty 82 (no data member at all): not the one-shot slot
        // shape.
        let r = applet.process(&[0x00, 0x87, 0x11, 0x9A, 0x04, 0x7C, 0x02, 0x82, 0x00, 0x00]);
        assert_eq!(r.sw, SW_INCORRECT_P1P2);
    }
}
