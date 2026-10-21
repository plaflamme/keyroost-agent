//! GENERAL AUTHENTICATE (0x87) — the 9B management-key dynamic-auth half of
//! the SP 800-73-4 exchange.

use keyroost_piv::{KEY_REF_MANAGEMENT, MgmtAlg};

use crate::constants::{
    GA_MAX_CHALLENGE, GA_TAG_CHALLENGE, GA_TAG_DYN_AUTH, GA_TAG_EXP, GA_TAG_RESPONSE,
    GA_TAG_WITNESS, SW_CLA_NOT_SUPPORTED, SW_DATA_INVALID, SW_INCORRECT_P1P2,
    SW_SECURITY_STATUS_NOT_SATISFIED, SW_WRONG_DATA, SW_WRONG_LENGTH,
};
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
    ///   (`06`/`07`/`11`/`14`) — when the template has the signing shape
    ///   (a challenge offered for a response) and the slot has no key.
    /// - A non-empty witness (`80`) must be the current challenge encrypted
    ///   with the management key (a re-issued witness invalidates the
    ///   pending one); a non-empty response (`82`) must decrypt to it. A
    ///   correct verification sets the slot's unlocked status. A wrong
    ///   value — or the challenge no longer valid — is `6A86`.
    /// - Wanted `80` (witness): the applet issues a fresh challenge and
    ///   answers `7C 80 <n> <encrypted challenge>`. Wanted `81`:
    ///   `7C 81 <n> <challenge>` in the clear. Wanted `82` (response): the
    ///   body's challenge is encrypted and answered `7C 82 <n> <encrypted>`
    ///   — `6A86` without a challenge, `6986` while the slot is still
    ///   locked. A no-empty-tag body with a challenge (the yubico-piv-tool
    ///   shape) wants a response; a fully empty body answers `9000` with no
    ///   data.
    ///
    /// P2=`9A`/`9C`/`9D` (and the `82`–`8C` history slots) need the PIN
    /// verified in this session — `6986` until it is — then answer `6B00`
    /// (the applet holds no key material for them yet). Every other P2 —
    /// `9E`, `9F`, `58`–`5A`, … — answers `6B00` outright.
    ///
    /// The per-slot signing / key agreement half (the `58`–`82`/`9E`/`9F`
    /// slots' RSA and ECDSA operations) lands with the key slots.
    pub(crate) fn process_general_authenticate(&mut self, apdu: &[u8]) -> Response {
        let [cla, _, p1, p2, ..] = apdu else {
            // `process` guarantees the 4-byte header.
            unreachable!("process guarantees the 4-byte header");
        };
        if cla & 0x90 != 0 {
            return Response::sw(SW_CLA_NOT_SUPPORTED);
        }
        match *p2 {
            KEY_REF_MANAGEMENT => self.ga_management(*p1, apdu_lc_body(apdu)),
            0x9A | 0x9C | 0x9D => self.ga_gated_slot(),
            0x82..=0x8C => self.ga_gated_slot(),
            _ => Response::sw(SW_INCORRECT_P1P2),
        }
    }

    /// The PIN-gated slot references (`9A`/`9C`/`9D`, history `82`–`8C`):
    /// `6986` until the PIN is verified in this session, `6B00` after (the
    /// applet holds no key material for them yet).
    fn ga_gated_slot(&self) -> Response {
        if self.pin.verified {
            Response::sw(SW_INCORRECT_P1P2)
        } else {
            Response::sw(SW_SECURITY_STATUS_NOT_SATISFIED)
        }
    }

    /// The 9B (management-key) half of GENERAL AUTHENTICATE: P1 selects the
    /// symmetric or an asymmetric algorithm, the body carries the
    /// dynamic-auth template.
    fn ga_management(&mut self, p1: u8, lc_body: Result<(u8, &[u8]), ()>) -> Response {
        let (_lc, body) = match lc_body {
            Ok(pair) => pair,
            Err(()) => return Response::sw(SW_WRONG_LENGTH),
        };
        let tmpl = match parse_ga_template(body) {
            Ok(t) => t,
            Err(sw) => return Response::sw(sw),
        };
        match MgmtAlg::from_id(p1) {
            Some(alg) => self.ga_sym(alg, tmpl),
            // Asymmetric (or unknown) algorithm: the reference allows only
            // the signing shape, then fails on the missing key.
            None => {
                if tmpl.is_sign_shape() {
                    Response::sw(SW_INCORRECT_P1P2)
                } else {
                    Response::sw(SW_WRONG_DATA)
                }
            }
        }
    }

    /// The symmetric 9B dynamic-auth exchange (the card's
    /// `processGenAuthSym`), once the template is parsed.
    fn ga_sym(&mut self, alg: MgmtAlg, t: GaTemplate) -> Response {
        if self.mgmt.alg() != alg {
            return Response::sw(SW_INCORRECT_P1P2);
        }
        let bs = alg.block_size();
        // The reference's special case: a body with a challenge and no
        // empty tag wants a response.
        let mut wanted = t.wanted;
        if wanted.is_none() && t.has_challenge {
            wanted = Some(GA_TAG_RESPONSE);
        }

        // Witness/response verification — the card's `comp` pass. The
        // witness (0x80) is the challenge in the clear: the host only
        // knows it because it decrypted the card's ciphertext with the
        // management key. The proof value (the 0x81 challenge, or a 0x82
        // value) is checked the way the card checks it — decrypted and
        // compared — and only when the witness did not already consume
        // the challenge, which is also why a host that presents both
        // gets its 0x81 taken raw, never decrypted.
        if t.witness.is_some() || t.challenge.is_some() || t.response.is_some() {
            let mut comp = false;
            if let Some(w) = t.witness {
                if w.len() != bs {
                    return Response::sw(SW_WRONG_DATA);
                }
                match self.mgmt.check_witness(w) {
                    None => return Response::sw(SW_WRONG_DATA),
                    Some(matched) => comp = matched,
                }
                // The witness consumes the challenge — a proof value in the
                // same body is never checked, so the host's raw 0x81
                // challenge passes through to the 0x82 response undecrypted.
            }
            // The proof value (the 0x81 challenge, or a 0x82 value) is
            // checked the way the card checks it — decrypted and compared —
            // and only when a witness did not just consume the challenge.
            let proof = t.challenge.or(t.response);
            if let Some(p) = proof {
                if p.len() != bs {
                    return Response::sw(SW_WRONG_DATA);
                }
                if let Some(matched) = self.mgmt.check_proof(p) {
                    comp = matched;
                }
            }
            if comp {
                self.mgmt.unlock();
            } else {
                return Response::sw(SW_WRONG_DATA);
            }
            if wanted.is_none() {
                return Response::ok(Vec::new());
            }
        }

        match wanted {
            Some(GA_TAG_WITNESS) => {
                self.mgmt.issue_challenge();
                let enc = self
                    .mgmt
                    .encrypt(self.mgmt.challenge().expect("just issued"));
                Response::ok(ga_response(GA_TAG_WITNESS, &enc))
            }
            Some(GA_TAG_CHALLENGE) => {
                self.mgmt.issue_challenge();
                Response::ok(ga_response(
                    GA_TAG_CHALLENGE,
                    self.mgmt.challenge().expect("just issued"),
                ))
            }
            Some(GA_TAG_RESPONSE) => {
                if !t.has_challenge {
                    return Response::sw(SW_WRONG_DATA);
                }
                if !self.mgmt.unlocked() {
                    return Response::sw(SW_SECURITY_STATUS_NOT_SATISFIED);
                }
                let Some(host_chal) = t.challenge else {
                    return Response::sw(SW_WRONG_DATA);
                };
                if host_chal.is_empty()
                    || host_chal.len() > GA_MAX_CHALLENGE
                    || host_chal.len() % bs != 0
                {
                    return Response::sw(SW_WRONG_DATA);
                }
                let enc = self.mgmt.encrypt(host_chal);
                Response::ok(ga_response(GA_TAG_RESPONSE, &enc))
            }
            _ => Response::sw(SW_WRONG_DATA),
        }
    }
}

/// One parsed SP 800-73-4 dynamic-auth template: the empty member the host
/// wants (if any), and the values of the non-empty members — the first of
/// each, as the card's rescan would find them.
struct GaTemplate<'a> {
    /// The single empty tag (`80`/`81`/`82`), if the host named one.
    wanted: Option<u8>,
    /// The first non-empty witness (`80`), if any.
    witness: Option<&'a [u8]>,
    /// The first non-empty challenge (`81`), if any.
    challenge: Option<&'a [u8]>,
    /// The first non-empty response (`82`), if any.
    response: Option<&'a [u8]>,
    /// Whether a non-empty challenge or exponent was present.
    has_challenge: bool,
}

impl<'a> GaTemplate<'a> {
    /// The reference's asymmetric-only shape: a challenge offered for a
    /// response, nothing else.
    fn is_sign_shape(&self) -> bool {
        self.has_challenge
            && self.witness.is_none()
            && self.response.is_none()
            && self.wanted == Some(GA_TAG_RESPONSE)
    }
}

/// Build the card's GA answer: the `7C` wrapper around one tagged value.
fn ga_response(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut data = vec![
        GA_TAG_DYN_AUTH,
        value.len() as u8 + 2,
        tag,
        value.len() as u8,
    ];
    data.extend_from_slice(value);
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
    let mut t = GaTemplate {
        wanted: None,
        witness: None,
        challenge: None,
        response: None,
        has_challenge: false,
    };
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
                    t.has_challenge = true;
                    if t.challenge.is_none() {
                        t.challenge = Some(value);
                    }
                }
                GA_TAG_EXP => t.has_challenge = true,
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
    use crate::constants::{DEFAULT_MGMT_KEY, DEFAULT_PUK_TRIES, SW_OK};
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
    fn ga_challenge_round_answers_the_clear_challenge() {
        let mut applet = PivApplet::new();
        let r = applet.process(&ga_apdu(0x03, &ga_body(&[&[0x81, 0x00]])));
        assert_eq!(r.sw, SW_OK);
        assert_eq!(r.data[0], 0x7C);
        assert_eq!(r.data[2], 0x81);
        assert_eq!(r.data.len(), 12);
    }

    #[test]
    fn ga_full_handshake_unlocks_and_responds() {
        let mut applet = PivApplet::new();
        let (data, challenge) = mgmt_handshake(&mut applet);
        // Mutual auth: the 0x82 response decrypts to the host challenge.
        assert_eq!(des_decrypt(&data[4..12]), challenge);
    }

    #[test]
    fn ga_response_proof_without_a_witness_unlocks() {
        let mut applet = PivApplet::new();
        let r1 = applet.process(&ga_apdu(0x03, &ga_body(&[&[0x80, 0x00]])));
        assert_eq!(r1.sw, SW_OK);
        // No witness: the proof is the card's challenge re-encrypted, offered
        // under 0x82 — the card decrypts and compares it to the challenge.
        let mut body = vec![0x82, 0x08];
        body.extend_from_slice(&r1.data[4..12]);
        let r = applet.process(&ga_apdu(0x03, &ga_body(&[&body])));
        assert_eq!(r.sw, SW_OK, "decrypted proof: {r:?}");
        assert!(r.data.is_empty());
        // The session is unlocked: a management write goes through.
        let mut apdu = vec![0x00, 0xFF, 0xFF, 0xFF, 27];
        apdu.extend_from_slice(&[0x03, KEY_REF_MANAGEMENT, 0x18]);
        apdu.extend_from_slice(&[0u8; 24]);
        let r = applet.process(&apdu);
        assert_eq!(r.sw, SW_OK, "unlocked session: {r:?}");
    }

    #[test]
    fn ga_challenged_body_without_a_valid_challenge_is_wrong_data() {
        let mut applet = PivApplet::new();
        // Only a non-empty challenge, no witness round before it — the card
        // has no valid challenge to check the proof against, so the `comp`
        // pass fails before the response is considered.
        let r = applet.process(&ga_apdu(
            0x03,
            &ga_body(&[&[0x81, 0x08, 0, 1, 2, 3, 4, 5, 6, 7]]),
        ));
        assert_eq!(r.sw, SW_WRONG_DATA);
        // After a handshake the challenge is spent, so the same APDU still
        // refuses.
        mgmt_handshake(&mut applet);
        let r = applet.process(&ga_apdu(
            0x03,
            &ga_body(&[&[0x81, 0x08, 0, 1, 2, 3, 4, 5, 6, 7]]),
        ));
        assert_eq!(r.sw, SW_WRONG_DATA);
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
    fn ga_response_of_wrong_length_is_wrong_data() {
        let mut applet = PivApplet::new();
        // A witness round first, so the challenge is valid and the length
        // check — not a spent challenge — is what fires.
        let r = applet.process(&ga_apdu(0x03, &ga_body(&[&[0x80, 0x00]])));
        assert_eq!(r.sw, SW_OK);
        // A 4-byte response where the 3DES block size is 8.
        let body = ga_body(&[&[0x82, 4, 0, 1, 2, 3]]);
        let r = applet.process(&ga_apdu(0x03, &body));
        assert_eq!(r.sw, SW_WRONG_DATA);
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
    fn ga_unknown_p2_is_incorrect_p1p2_and_pin_gated_slots_need_the_pin() {
        let mut applet = PivApplet::new();
        // 9E is not a slot reference the applet knows.
        for p2 in [0x9Eu8, 0x58u8, 0x00u8] {
            let r = applet.process(&ga_apdu_for_p2(p2));
            assert_eq!(r.sw, SW_INCORRECT_P1P2);
        }
        // 9A/9C/9D and the history slots: PIN-gated — locked first.
        for p2 in [0x9Au8, 0x9Cu8, 0x9Du8, 0x82u8, 0x8Cu8] {
            let r = applet.process(&ga_apdu_for_p2(p2));
            assert_eq!(r.sw, SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        // After the PIN is verified the applet has no key material for them.
        let r = applet.process(&keyroost_piv::verify_pin(b"123456").unwrap());
        assert_eq!(r.sw, SW_OK);
        for p2 in [0x9Au8, 0x9Cu8, 0x9Du8, 0x82u8, 0x8Cu8] {
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
}
