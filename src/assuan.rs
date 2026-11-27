/// Maximum Assuan protocol line length (including trailing LF) per libassuan.
#[allow(dead_code)]
pub(crate) const MAX_LINE_LEN: usize = 1000;

pub(crate) const GPG_ERR_CODE_MASK: u32 = 0xFFFF;
pub(crate) const GPG_ERR_SOURCE_MASK: u32 = 0x7F;
pub(crate) const GPG_ERR_SOURCE_SHIFT: u32 = 24;

#[allow(dead_code)]
pub(crate) const GPG_ERR_SOURCE_GPGAGENT: u32 = 4;
pub(crate) const GPG_ERR_SOURCE_PINENTRY: u32 = 5;

#[allow(dead_code)]
pub(crate) const GPG_ERR_NO_SECKEY: u32 = 17;
#[allow(dead_code)]
pub(crate) const GPG_ERR_NO_DATA: u32 = 58;
#[allow(dead_code)]
pub(crate) const GPG_ERR_NOT_IMPLEMENTED: u32 = 69;
#[allow(dead_code)]
pub(crate) const GPG_ERR_INV_DATA: u32 = 79;
#[allow(dead_code)]
pub(crate) const GPG_ERR_BAD_PIN: u32 = 87;
pub(crate) const GPG_ERR_CANCELED: u32 = 99;
#[allow(dead_code)]
pub(crate) const GPG_ERR_UNKNOWN_COMMAND: u32 = 175;

pub(crate) const GPG_ERR_CANCELED_PINENTRY: u32 =
    gpg_err_make(GPG_ERR_SOURCE_PINENTRY, GPG_ERR_CANCELED);

/// Construct a `libgpg-error` code from a source and error code.
pub(crate) const fn gpg_err_make(source: u32, code: u32) -> u32 {
    ((source & GPG_ERR_SOURCE_MASK) << GPG_ERR_SOURCE_SHIFT) | (code & GPG_ERR_CODE_MASK)
}

/// Return whether `code` represents a cancellation error from `pinentry` or any GPG source.
pub(crate) const fn is_cancelled_err(code: u32) -> bool {
    code == GPG_ERR_CANCELED_PINENTRY || (code & GPG_ERR_CODE_MASK) == GPG_ERR_CANCELED
}

/// Percent-encode a string for transmission on an Assuan protocol line.
pub(crate) fn percent_encode(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '%' => encoded.push_str("%25"),
            '\r' => encoded.push_str("%0D"),
            '\n' => encoded.push_str("%0A"),
            '\0' => encoded.push_str("%00"),
            other => encoded.push(other),
        }
    }
    encoded
}

/// Decode a single ASCII hexadecimal digit into its 4-bit value.
pub(crate) const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Percent-decode an Assuan data payload into `out`.
pub(crate) fn percent_decode(input: &str, out: &mut Vec<u8>) -> Result<(), &'static str> {
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err("truncated percent-escape in data line");
            }
            let hi = hex_value(bytes[i + 1]).ok_or("invalid percent-escape in data line")?;
            let lo = hex_value(bytes[i + 2]).ok_or("invalid percent-escape in data line")?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        GPG_ERR_BAD_PIN, GPG_ERR_CANCELED, GPG_ERR_CANCELED_PINENTRY, GPG_ERR_INV_DATA,
        GPG_ERR_NO_DATA, GPG_ERR_NO_SECKEY, GPG_ERR_NOT_IMPLEMENTED, GPG_ERR_SOURCE_GPGAGENT,
        GPG_ERR_SOURCE_PINENTRY, GPG_ERR_UNKNOWN_COMMAND, MAX_LINE_LEN, gpg_err_make, hex_value,
        is_cancelled_err, percent_decode, percent_encode,
    };

    #[test]
    fn percent_encode_and_decode_roundtrip() {
        let original = "pin%12\r\nline2\0end";
        let encoded = percent_encode(original);
        assert_eq!(encoded, "pin%2512%0D%0Aline2%00end");

        let mut decoded = Vec::new();
        percent_decode(&encoded, &mut decoded).unwrap();
        assert_eq!(decoded, original.as_bytes());
    }

    #[test]
    fn percent_decode_handles_lowercase_and_uppercase_hex() {
        let mut out = Vec::new();
        percent_decode("%2a%2B%0a%0D", &mut out).unwrap();
        assert_eq!(out, b"*+\n\r");
    }

    #[test]
    fn percent_decode_rejects_malformed_escapes() {
        let mut out = Vec::new();
        assert!(percent_decode("abc%", &mut out).is_err());
        assert!(percent_decode("abc%2", &mut out).is_err());
        assert!(percent_decode("abc%ZZ", &mut out).is_err());
    }

    #[test]
    fn hex_value_decodes_valid_and_rejects_invalid_digits() {
        assert_eq!(hex_value(b'0'), Some(0));
        assert_eq!(hex_value(b'9'), Some(9));
        assert_eq!(hex_value(b'a'), Some(10));
        assert_eq!(hex_value(b'f'), Some(15));
        assert_eq!(hex_value(b'A'), Some(10));
        assert_eq!(hex_value(b'F'), Some(15));
        assert_eq!(hex_value(b'g'), None);
        assert_eq!(hex_value(b'/'), None);
    }

    #[test]
    fn gpg_err_make_constructs_libgpg_error_codes() {
        assert_eq!(MAX_LINE_LEN, 1000);
        assert_eq!(GPG_ERR_CANCELED_PINENTRY, 83_886_179);
        assert_eq!(
            gpg_err_make(GPG_ERR_SOURCE_PINENTRY, GPG_ERR_CANCELED),
            83_886_179
        );
        assert_eq!(
            gpg_err_make(GPG_ERR_SOURCE_GPGAGENT, GPG_ERR_CANCELED),
            67_108_963
        );
        assert_eq!(
            gpg_err_make(GPG_ERR_SOURCE_GPGAGENT, GPG_ERR_NO_SECKEY),
            67_108_881
        );
        assert_eq!(
            gpg_err_make(GPG_ERR_SOURCE_GPGAGENT, GPG_ERR_BAD_PIN),
            67_108_951
        );
        assert_eq!(
            gpg_err_make(GPG_ERR_SOURCE_GPGAGENT, GPG_ERR_UNKNOWN_COMMAND),
            67_109_039
        );
        assert_eq!(
            gpg_err_make(GPG_ERR_SOURCE_GPGAGENT, GPG_ERR_INV_DATA),
            67_108_943
        );
        assert_eq!(
            gpg_err_make(GPG_ERR_SOURCE_GPGAGENT, GPG_ERR_NOT_IMPLEMENTED),
            67_108_933
        );
        assert_eq!(
            gpg_err_make(GPG_ERR_SOURCE_GPGAGENT, GPG_ERR_NO_DATA),
            67_108_922
        );
    }

    #[test]
    fn is_cancelled_err_matches_pinentry_and_generic_cancel_codes() {
        assert!(is_cancelled_err(GPG_ERR_CANCELED_PINENTRY));
        assert!(is_cancelled_err(GPG_ERR_CANCELED));
        assert!(is_cancelled_err(gpg_err_make(
            GPG_ERR_SOURCE_GPGAGENT,
            GPG_ERR_CANCELED
        )));
        assert!(!is_cancelled_err(gpg_err_make(
            GPG_ERR_SOURCE_GPGAGENT,
            GPG_ERR_BAD_PIN
        )));
    }
}
