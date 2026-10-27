//! GET DATA (0xCB) and PUT DATA (0xDB): the card's data objects — the 24
//! slot certificates plus the CHUID, the PIN-protected data object and the
//! Yubico admin object — stored opaquely as the raw value of their `53`
//! template and served back verbatim.
//!
//! A slot certificate lives on the slot itself ([`Slot::cert`]), so the
//! certificate objects are per-slot state while the three non-slot objects
//! live in [`PivData`]. Both are opaque: the applet neither parses nor
//! rewrites a value, so a certificate written with the host's
//! [`keyroost_piv::encode_certificate`] (DER or gzip, `CertInfo` `0x00`/`0x01`)
//! reads back byte-identical.

use crate::constants::{
    SW_CLA_NOT_SUPPORTED, SW_DATA_INVALID, SW_INCORRECT_P1P2, SW_OK, SW_WRONG_LENGTH,
};
use crate::{PivApplet, Response, apdu_lc_body, apdu_le};
use keyroost_piv::{OBJECT_ADMIN_DATA, OBJECT_CHUID, OBJECT_PIN_PROTECTED_DATA};

/// The `F9` attestation certificate object tag (the Yubico PIV Attestation
/// Certificate), the one data object the applet mints at construction.
const ATTESTATION_OBJECT_TAG: [u8; 3] = [0x5F, 0xFF, 0x01];

/// The non-slot data objects: the CHUID (`5F C1 02`), the PIN-protected
/// data object (`5F C1 09`) and the Yubico admin object (`5F FF 00`), each
/// stored opaquely as the value of its `53` template, `None` until first
/// written.
#[derive(Default)]
pub(crate) struct PivData {
    /// The CHUID (card holder unique identifier), `None` at the factory.
    pub(crate) chuid: Option<Vec<u8>>,
    /// The PIN-protected data object, `None` at the factory.
    pub(crate) pin_protected: Option<Vec<u8>>,
    /// The Yubico admin object (`5F FF 00`), `None` at the factory.
    pub(crate) admin_data: Option<Vec<u8>>,
}

impl PivData {
    /// The object stored under `tag`, or `None` when no object exists under
    /// it (or `tag` is not a non-slot object tag).
    pub(crate) fn get(&self, tag: &[u8; 3]) -> Option<&[u8]> {
        match *tag {
            OBJECT_CHUID => self.chuid.as_deref(),
            OBJECT_PIN_PROTECTED_DATA => self.pin_protected.as_deref(),
            OBJECT_ADMIN_DATA => self.admin_data.as_deref(),
            _ => None,
        }
    }

    /// Store `value` under `tag`, returning whether the tag names a known
    /// non-slot object.
    pub(crate) fn put(&mut self, tag: &[u8; 3], value: Vec<u8>) -> bool {
        match *tag {
            OBJECT_CHUID => {
                self.chuid = Some(value);
                true
            }
            OBJECT_PIN_PROTECTED_DATA => {
                self.pin_protected = Some(value);
                true
            }
            OBJECT_ADMIN_DATA => {
                self.admin_data = Some(value);
                true
            }
            _ => false,
        }
    }
}

/// The slot index whose certificate lives under the given `5C`-selector
/// tag — `5F C1 05` (`9A`), `5F C1 0A` (`9C`), `5F C1 0B` (`9D`),
/// `5F C1 01` (`9E`) and `5F C1 0C+n` for retired slot `n` — or `None`
/// for a non-slot object tag.
pub(crate) fn cert_slot_index(tag: &[u8; 3]) -> Option<usize> {
    match tag {
        [0x5F, 0xC1, 0x05] => Some(0),
        [0x5F, 0xC1, 0x0A] => Some(1),
        [0x5F, 0xC1, 0x0B] => Some(2),
        [0x5F, 0xC1, 0x01] => Some(3),
        [0x5F, 0xC1, third] if (0x0D..=0x20).contains(third) => Some(3 + usize::from(third - 0x0C)),
        _ => None,
    }
}

impl PivApplet {
    /// GET DATA (0xCB, P1P2=`3FFF`): read a data object by its
    /// `5C`-wrapped tag — a slot certificate, the CHUID, an admin object —
    /// and return it wrapped in the `53` data template.
    ///
    /// The value is served verbatim, however it was written. A case-4 `Le`
    /// smaller than the wrapped value re-enters the usual `61xx` / GET
    /// RESPONSE continuation; a tag no object exists under answers `6A82`.
    pub(crate) fn process_get_data(&mut self, apdu: &[u8]) -> Response {
        let [cla, _, p1, p2, ..] = apdu else {
            unreachable!("process guarantees the 4-byte header");
        };
        if cla & 0x90 != 0 {
            return Response::sw(SW_CLA_NOT_SUPPORTED);
        }
        if *p1 != 0x3F || *p2 != 0xFF {
            return Response::sw(SW_INCORRECT_P1P2);
        }
        let Ok((_lc, body, tail)) = apdu_lc_body(apdu) else { return Response::sw(SW_WRONG_LENGTH) };
        let Ok(le) = apdu_le(tail) else { return Response::sw(SW_WRONG_LENGTH) };
        let Some(tag) = selector_tag(body) else { return Response::sw(SW_DATA_INVALID) };
        match self.data_object_value(&tag) {
            Some(value) => {
                let mut full = Vec::with_capacity(2 + value.len());
                push_tlv(&mut full, &[0x53], value);
                self.split_for_le(full, le)
            }
            None => Response::sw(keyroost_piv::SW_NOT_FOUND),
        }
    }

    /// PUT DATA (0xDB, P1P2=`3FFF`): write a data object — a slot
    /// certificate or a non-slot object — under its `5C`-wrapped tag.
    ///
    /// Management-gated like the other slot commands (the `9B` management
    /// session unlocked, else `6982`). The value is the `53` template's
    /// content, stored verbatim: writing the empty value is how the host
    /// clears a slot certificate.
    pub(crate) fn process_put_data(&mut self, apdu: &[u8]) -> Response {
        let [cla, _, p1, p2, ..] = apdu else {
            unreachable!("process guarantees the 4-byte header");
        };
        if cla & 0x90 != 0 {
            return Response::sw(SW_CLA_NOT_SUPPORTED);
        }
        if *p1 != 0x3F || *p2 != 0xFF {
            return Response::sw(SW_INCORRECT_P1P2);
        }
        if let Err(sw) = self.management_unlocked() {
            return Response::sw(sw);
        }
        let Ok((_, body, _)) = apdu_lc_body(apdu) else { return Response::sw(SW_WRONG_LENGTH) };
        let Some((tag, value)) = parse_put_body(body) else { return Response::sw(SW_DATA_INVALID) };
        if self.store_data_object(&tag, value) { Response::sw(SW_OK) } else { Response::sw(keyroost_piv::SW_NOT_FOUND) }
    }

    /// The value stored under the object `tag` — the slot's certificate for
    /// a slot tag, the `F9` attestation certificate for `5F FF 01`, the
    /// corresponding [`PivData`] object otherwise — or `None` when nothing
    /// has been stored under it.
    pub(crate) fn data_object_value(&self, tag: &[u8; 3]) -> Option<&[u8]> {
        if *tag == ATTESTATION_OBJECT_TAG {
            return self.attestation.cert.as_deref();
        }
        match cert_slot_index(tag) {
            Some(index) => self.slots[index].cert.as_deref(),
            None => self.data.get(tag),
        }
    }

    /// Store `value` under the object `tag`: the slot's certificate for a
    /// slot tag, the `F9` attestation certificate for `5F FF 01`, the
    /// corresponding [`PivData`] object otherwise. Returns whether the tag
    /// names a known object.
    pub(crate) fn store_data_object(&mut self, tag: &[u8; 3], value: Vec<u8>) -> bool {
        if *tag == ATTESTATION_OBJECT_TAG {
            self.attestation.cert = Some(value);
            return true;
        }
        match cert_slot_index(tag) {
            Some(index) => {
                self.slots[index].cert = Some(value);
                true
            }
            None => self.data.put(tag, value),
        }
    }
}

/// The `5C` selector's 3-byte object tag from a GET/PUT DATA body: `None`
/// when the body is not a well-formed `5C 03 <tag>` selector.
fn selector_tag(body: &[u8]) -> Option<[u8; 3]> {
    let [0x5C, 0x03, t0, t1, t2, ..] = body else {
        return None;
    };
    Some([*t0, *t1, *t2])
}

/// A PUT DATA body's object tag and value: a `5C 03 <tag>` selector
/// followed by a `53 <len> <value>` template whose value runs to the end of
/// the body. `None` when any of it is broken.
fn parse_put_body(body: &[u8]) -> Option<([u8; 3], Vec<u8>)> {
    let tag = selector_tag(body)?;
    let template = body.get(5..)?;
    if *template.first()? != 0x53 {
        return None;
    }
    let (len, value) = ber_length(template.get(1..)?)?;
    if value.len() != len {
        return None;
    }
    Some((tag, value.to_vec()))
}

/// A BER length in its short or 1-2-byte long form, at the head of `rest`:
/// the declared length and the following bytes. `None` when the form is
/// broken or the declared length overruns what is present.
fn ber_length(rest: &[u8]) -> Option<(usize, &[u8])> {
    let first = *rest.first()?;
    if first < 0x80 {
        return Some((usize::from(first), rest.get(1..)?));
    }
    let count = usize::from(first & 0x7F);
    let digits = rest.get(1..=count)?;
    if count > 2 {
        return None;
    }
    let len = digits
        .iter()
        .fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
    let value = rest.get(1 + count..)?;
    if value.len() < len {
        return None;
    }
    Some((len, value))
}

/// Append `tag` + BER length + `value` to `out` — short form up to `0x7F`,
/// `81`/`82` long form above, the same encoding the host's `put_data`
/// builder emits.
pub(crate) fn push_tlv(out: &mut Vec<u8>, tag: &[u8], value: &[u8]) {
    out.extend_from_slice(tag);
    match value.len() {
        n if n <= 0x7F => out.push(n as u8),
        n if n <= 0xFF => out.extend_from_slice(&[0x81, n as u8]),
        n => out.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]),
    }
    out.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::general_auth::tests::mgmt_handshake;
    use keyroost_piv::{CertInfo, encode_certificate, get_data, put_data, unwrap_data_object};

    /// The three-byte certificate-object tag of slot `index` — the inverse
    /// of [`cert_slot_index`], used to walk all 24 objects in the tests.
    fn slot_cert_tag(index: usize) -> [u8; 3] {
        match index {
            0 => [0x5F, 0xC1, 0x05],
            1 => [0x5F, 0xC1, 0x0A],
            2 => [0x5F, 0xC1, 0x0B],
            3 => [0x5F, 0xC1, 0x01],
            i => [0x5F, 0xC1, 0x0C + (i - 3) as u8],
        }
    }

    fn all_object_tags() -> [[u8; 3]; 27] {
        let mut tags = [slot_cert_tag(0); 27];
        for (i, tag) in tags[..24].iter_mut().enumerate() {
            *tag = slot_cert_tag(i);
        }
        tags[24] = OBJECT_CHUID;
        tags[25] = OBJECT_PIN_PROTECTED_DATA;
        tags[26] = OBJECT_ADMIN_DATA;
        tags
    }

    /// PUT then GET every object class — all 24 slot certificates plus the
    /// three non-slot objects — asserting the value reads back
    /// byte-identical through the host's own builders and parser.
    #[test]
    fn put_get_round_trips_every_object_class() {
        let mut applet = PivApplet::new();
        let (_step2, _challenge) = mgmt_handshake(&mut applet);
        let value = [0xA5u8; 16];
        for tag in all_object_tags() {
            let resp = applet.process(&put_data(&tag, &value));
            assert_eq!(resp.sw, keyroost_piv::SW_OK, "PUT {tag:02X?}");
            let resp = applet.process(&get_data(&tag));
            assert_eq!(resp.sw, keyroost_piv::SW_OK, "GET {tag:02X?}");
            let inner = unwrap_data_object(&resp.data).expect("a well-formed 53 template");
            assert_eq!(inner, value.as_slice(), "round trip {tag:02X?}");
        }
    }

    /// A certificate built with the host's encoder — DER plus the CertInfo
    /// `0x01` gzip flag — is stored opaquely: the `53` value PUT DATA wrote
    /// is what GET DATA returns, byte for byte.
    #[test]
    fn a_certificate_reads_back_byte_identical() {
        let mut applet = PivApplet::new();
        let (_step2, _challenge) = mgmt_handshake(&mut applet);
        let der = [0x30u8; 120];
        let cert = encode_certificate(&der, CertInfo::Gzip);
        let tag = slot_cert_tag(0);
        let resp = applet.process(&put_data(&tag, &cert));
        assert_eq!(resp.sw, keyroost_piv::SW_OK);
        let resp = applet.process(&get_data(&tag));
        assert_eq!(resp.sw, keyroost_piv::SW_OK);
        let inner = unwrap_data_object(&resp.data).expect("a well-formed 53 template");
        assert_eq!(inner, cert.as_slice());
    }

    /// The factory-fresh applet stores no object: every object tag answers
    /// `6A82` until first written.
    #[test]
    fn factory_applet_has_no_objects() {
        let mut applet = PivApplet::new();
        for tag in all_object_tags() {
            let resp = applet.process(&get_data(&tag));
            assert_eq!(resp.sw, keyroost_piv::SW_NOT_FOUND, "GET {tag:02X?}");
        }
    }

    /// PUT DATA is management-gated: locked answers `6982` and stores
    /// nothing; unlocked answers `9000`.
    #[test]
    fn put_data_requires_the_management_session() {
        let mut applet = PivApplet::new();
        let tag = slot_cert_tag(1);
        let locked = applet.process(&put_data(&tag, &[0x11; 4]));
        assert_eq!(locked.sw, keyroost_piv::SW_SECURITY_NOT_SATISFIED);
        let (_step2, _challenge) = mgmt_handshake(&mut applet);
        let unlocked = applet.process(&put_data(&tag, &[0x11; 4]));
        assert_eq!(unlocked.sw, keyroost_piv::SW_OK);
    }

    /// A GET DATA body that is not a `5C 03 <tag>` selector answers `6B00`.
    #[test]
    fn get_data_rejects_a_broken_selector() {
        let mut applet = PivApplet::new();
        // No body at all.
        assert_eq!(
            applet.process(&[0x00, 0xCB, 0x3F, 0xFF, 0x00]).sw,
            SW_DATA_INVALID
        );
        // A selector of the wrong length.
        let broken = [0x00u8, 0xCB, 0x3F, 0xFF, 0x04, 0x5C, 0x02, 0x5F, 0xC1, 0x00];
        assert_eq!(applet.process(&broken).sw, SW_DATA_INVALID);
    }

    /// A PUT DATA body missing its `53` template, underrunning its declared
    /// length, or trailing garbage answers `6B00`.
    #[test]
    fn put_data_rejects_a_broken_template() {
        let mut applet = PivApplet::new();
        let (_step2, _challenge) = mgmt_handshake(&mut applet);
        // Selector only — the `53` template is missing.
        let no_template = [0x00u8, 0xDB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x05];
        assert_eq!(applet.process(&no_template).sw, SW_DATA_INVALID);
        // Declared length overruns the body.
        let underrun = [
            0x00u8, 0xDB, 0x3F, 0xFF, 0x09, 0x5C, 0x03, 0x5F, 0xC1, 0x05, 0x53, 0x05, 0xAA, 0xBB,
        ];
        assert_eq!(applet.process(&underrun).sw, SW_DATA_INVALID);
        // Garbage after the `53` template's value.
        let trailing = [
            0x00u8, 0xDB, 0x3F, 0xFF, 0x0A, 0x5C, 0x03, 0x5F, 0xC1, 0x05, 0x53, 0x01, 0xAA, 0x00,
            0x00,
        ];
        assert_eq!(applet.process(&trailing).sw, SW_DATA_INVALID);
    }

    /// PUT DATA for a tag no object exists under answers `6A82`.
    #[test]
    fn put_data_rejects_an_unknown_tag() {
        let mut applet = PivApplet::new();
        let (_step2, _challenge) = mgmt_handshake(&mut applet);
        let resp = applet.process(&put_data(&[0x5F, 0xC1, 0x77], &[0x11]));
        assert_eq!(resp.sw, keyroost_piv::SW_NOT_FOUND);
    }

    /// A case-4 `Le` smaller than the wrapped value re-enters the `61xx` /
    /// GET RESPONSE continuation, reassembling to the full `53` template.
    #[test]
    fn get_data_continues_past_a_small_le() {
        let mut applet = PivApplet::new();
        let (_step2, _challenge) = mgmt_handshake(&mut applet);
        let value = [0x5Au8; 300];
        let tag = slot_cert_tag(0);
        let resp = applet.process(&put_data(&tag, &value));
        assert_eq!(resp.sw, keyroost_piv::SW_OK);
        // The host's builder asks for Le `0x00` (256) — the 304-byte
        // template overflows by 48.
        let first = applet.process(&get_data(&tag));
        assert_eq!(first.data.len(), 256);
        assert_eq!(first.sw, 0x6130);
        let rest = applet.process(&[0x00, 0xC0, 0x00, 0x00, 0x00]);
        assert_eq!(rest.data.len(), 48);
        assert_eq!(rest.sw, keyroost_piv::SW_OK);
        let mut full = first.data;
        full.extend_from_slice(&rest.data);
        let inner = unwrap_data_object(&full).expect("a well-formed 53 template");
        assert_eq!(inner, value.as_slice());
    }

    /// PUT DATA answers `9000` with no data, like the card.
    #[test]
    fn put_data_answers_a_bare_9000() {
        let mut applet = PivApplet::new();
        let (_step2, _challenge) = mgmt_handshake(&mut applet);
        let resp = applet.process(&put_data(&OBJECT_CHUID, &[0x01, 0x02]));
        assert_eq!(resp.data, Vec::<u8>::new());
        assert_eq!(resp.sw, keyroost_piv::SW_OK);
    }
}
