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
