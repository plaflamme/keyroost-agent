use std::fmt;
use std::io::Write as _;

/// Maximum allowed list nesting depth when parsing canonical S-expressions.
pub(crate) const MAX_NESTING_DEPTH: usize = 64;

/// A canonical S-expression in `libgcrypt` format.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Sexp {
    Atom(Vec<u8>),
    List(Vec<Self>),
}

/// Errors returned when parsing or interpreting canonical S-expressions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SexpError {
    /// Input ended before the S-expression was complete.
    UnexpectedEof,
    /// Encountered an unexpected byte at the given offset.
    UnexpectedByte { offset: usize, byte: u8 },
    /// Atom length prefix had a leading zero or contained a non-ASCII-digit byte.
    InvalidLength { offset: usize },
    /// Atom length prefix overflowed `usize`.
    LengthOverflow { offset: usize },
    /// Atom declared more bytes than remain in the input.
    TruncatedAtom {
        offset: usize,
        declared: usize,
        remaining: usize,
    },
    /// Extra bytes remained after parsing the top-level S-expression.
    TrailingBytes { offset: usize, count: usize },
    /// List nesting exceeded [`MAX_NESTING_DEPTH`].
    MaxDepthExceeded,
    /// S-expression did not match the expected GPG protocol structure.
    InvalidStructure(&'static str),
}

impl fmt::Display for SexpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof => write!(f, "unexpected end of S-expression input"),
            Self::UnexpectedByte { offset, byte } => {
                write!(f, "unexpected byte 0x{byte:02x} at offset {offset}")
            }
            Self::InvalidLength { offset } => {
                write!(f, "invalid atom length prefix at offset {offset}")
            }
            Self::LengthOverflow { offset } => {
                write!(f, "atom length overflow at offset {offset}")
            }
            Self::TruncatedAtom {
                offset,
                declared,
                remaining,
            } => write!(
                f,
                "truncated atom at offset {offset}: declared {declared} bytes, only {remaining} remaining"
            ),
            Self::TrailingBytes { offset, count } => {
                write!(f, "{count} trailing byte(s) after S-expression at offset {offset}")
            }
            Self::MaxDepthExceeded => {
                write!(f, "S-expression nesting depth exceeded limit of {MAX_NESTING_DEPTH}")
            }
            Self::InvalidStructure(msg) => write!(f, "invalid S-expression structure: {msg}"),
        }
    }
}

impl std::error::Error for SexpError {}

/// Decoded ciphertext payload from a GPG `enc-val` S-expression.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum EncVal {
    /// RSA ciphertext integer (`a`).
    Rsa { a: Vec<u8> },
    /// ECDH ephemeral public point (`e`).
    Ecdh { e: Vec<u8> },
}

impl Sexp {
    /// Parse a single canonical S-expression from `input`.
    ///
    /// Rejects leading zeros in non-zero lengths, non-ASCII length digits,
    /// truncated atoms or lists, trailing bytes, and nesting deeper than
    /// [`MAX_NESTING_DEPTH`].
    pub(crate) fn parse(input: &[u8]) -> Result<Self, SexpError> {
        let mut parser = Parser { input, pos: 0 };
        let sexp = parser.parse_sexp(0)?;
        if parser.pos < input.len() {
            return Err(SexpError::TrailingBytes {
                offset: parser.pos,
                count: input.len() - parser.pos,
            });
        }
        Ok(sexp)
    }

    /// Serialize this S-expression into canonical `libgcrypt` byte form.
    #[must_use]
    pub(crate) fn to_canonical(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write_canonical(&mut out);
        out
    }

    fn write_canonical(&self, out: &mut Vec<u8>) {
        match self {
            Self::Atom(bytes) => {
                let _ = write!(out, "{}:", bytes.len());
                out.extend_from_slice(bytes);
            }
            Self::List(items) => {
                out.push(b'(');
                for item in items {
                    item.write_canonical(out);
                }
                out.push(b')');
            }
        }
    }

    fn atom(bytes: &[u8]) -> Self {
        Self::Atom(bytes.to_vec())
    }

    fn as_atom(&self) -> Option<&[u8]> {
        match self {
            Self::Atom(bytes) => Some(bytes.as_slice()),
            Self::List(_) => None,
        }
    }

    fn as_list(&self) -> Option<&[Self]> {
        match self {
            Self::List(items) => Some(items.as_slice()),
            Self::Atom(_) => None,
        }
    }
}

struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn parse_sexp(&mut self, depth: usize) -> Result<Sexp, SexpError> {
        let Some(&byte) = self.input.get(self.pos) else {
            return Err(SexpError::UnexpectedEof);
        };

        match byte {
            b'(' => {
                if depth >= MAX_NESTING_DEPTH {
                    return Err(SexpError::MaxDepthExceeded);
                }
                self.pos += 1;
                let mut items = Vec::new();
                loop {
                    let Some(&next) = self.input.get(self.pos) else {
                        return Err(SexpError::UnexpectedEof);
                    };
                    if next == b')' {
                        self.pos += 1;
                        return Ok(Sexp::List(items));
                    }
                    items.push(self.parse_sexp(depth + 1)?);
                }
            }
            b'0'..=b'9' => self.parse_atom(),
            _ => Err(SexpError::UnexpectedByte {
                offset: self.pos,
                byte,
            }),
        }
    }

    fn parse_atom(&mut self) -> Result<Sexp, SexpError> {
        let start = self.pos;

        if self.input[self.pos] == b'0' {
            self.pos += 1;
            return match self.input.get(self.pos) {
                Some(&b':') => {
                    self.pos += 1;
                    Ok(Sexp::Atom(Vec::new()))
                }
                None => Err(SexpError::UnexpectedEof),
                Some(_) => Err(SexpError::InvalidLength { offset: start }),
            };
        }

        let mut len: usize = 0;
        loop {
            let Some(&byte) = self.input.get(self.pos) else {
                return Err(SexpError::UnexpectedEof);
            };
            if byte == b':' {
                self.pos += 1;
                break;
            }
            if !byte.is_ascii_digit() {
                return Err(SexpError::InvalidLength { offset: self.pos });
            }
            let digit = usize::from(byte - b'0');
            len = len
                .checked_mul(10)
                .and_then(|v| v.checked_add(digit))
                .ok_or(SexpError::LengthOverflow { offset: start })?;
            self.pos += 1;
        }

        let remaining = self.input.len() - self.pos;
        if len > remaining {
            return Err(SexpError::TruncatedAtom {
                offset: self.pos,
                declared: len,
                remaining,
            });
        }

        let bytes = self.input[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(Sexp::Atom(bytes))
    }
}

/// Extract the tag and remaining items from a non-empty tagged list `(tag ...)`.
fn split_tagged_list(sexp: &Sexp) -> Result<(&[u8], &[Sexp]), SexpError> {
    let items = sexp
        .as_list()
        .ok_or(SexpError::InvalidStructure("expected a list"))?;
    let (head, tail) = items
        .split_first()
        .ok_or(SexpError::InvalidStructure("expected a non-empty tagged list"))?;
    let tag = head
        .as_atom()
        .ok_or(SexpError::InvalidStructure("expected an atom tag"))?;
    Ok((tag, tail))
}

/// Extract a single byte-string parameter from a list of sublists such as
/// `(a <bytes>)` or `(e <bytes>)`, ignoring optional `(flags ...)` and `(s ...)` sublists.
fn extract_single_param(
    entries: &[Sexp],
    param_name: &[u8],
    missing_msg: &'static str,
    duplicate_msg: &'static str,
) -> Result<Vec<u8>, SexpError> {
    let mut found: Option<Vec<u8>> = None;

    for entry in entries {
        let (tag, values) = split_tagged_list(entry)?;
        if tag == param_name {
            if found.is_some() {
                return Err(SexpError::InvalidStructure(duplicate_msg));
            }
            let [value] = values else {
                return Err(SexpError::InvalidStructure(
                    "expected a single atom value for parameter",
                ));
            };
            let bytes = value
                .as_atom()
                .ok_or(SexpError::InvalidStructure("expected an atom value for parameter"))?;
            found = Some(bytes.to_vec());
        } else if tag == b"flags" || tag == b"s" {
            // Optional metadata/session-key sublists are tolerated.
        } else {
            return Err(SexpError::InvalidStructure("unexpected sublist in algorithm parameters"));
        }
    }

    found.ok_or(SexpError::InvalidStructure(missing_msg))
}

/// Parse a GPG `enc-val` S-expression into an [`EncVal`].
///
/// Supports `(enc-val (rsa (a <bytes>)))` and `(enc-val (ecdh (e <bytes>)))`,
/// tolerating optional `(flags ...)` or `(s ...)` sublists.
pub(crate) fn parse_enc_val(sexp: &Sexp) -> Result<EncVal, SexpError> {
    let (root_tag, children) = split_tagged_list(sexp)?;
    if root_tag != b"enc-val" {
        return Err(SexpError::InvalidStructure("expected top-level enc-val list"));
    }

    let mut result: Option<EncVal> = None;

    for child in children {
        let (tag, entries) = split_tagged_list(child)?;
        match tag {
            b"flags" | b"s" => {}
            b"rsa" => {
                if result.is_some() {
                    return Err(SexpError::InvalidStructure("duplicate algorithm in enc-val"));
                }
                let a = extract_single_param(
                    entries,
                    b"a",
                    "missing RSA 'a' parameter",
                    "duplicate RSA 'a' parameter",
                )?;
                result = Some(EncVal::Rsa { a });
            }
            b"ecdh" => {
                if result.is_some() {
                    return Err(SexpError::InvalidStructure("duplicate algorithm in enc-val"));
                }
                let e = extract_single_param(
                    entries,
                    b"e",
                    "missing ECDH 'e' parameter",
                    "duplicate ECDH 'e' parameter",
                )?;
                result = Some(EncVal::Ecdh { e });
            }
            _ => {
                return Err(SexpError::InvalidStructure("unsupported algorithm in enc-val"));
            }
        }
    }

    result.ok_or(SexpError::InvalidStructure("missing algorithm in enc-val"))
}

/// Encode an RSA signature as canonical `(sig-val (rsa (s <bytes>)))`.
#[must_use]
pub(crate) fn encode_rsa_sig(s: &[u8]) -> Vec<u8> {
    Sexp::List(vec![
        Sexp::atom(b"sig-val"),
        Sexp::List(vec![
            Sexp::atom(b"rsa"),
            Sexp::List(vec![Sexp::atom(b"s"), Sexp::atom(s)]),
        ]),
    ])
    .to_canonical()
}

/// Encode an ECDSA signature as canonical `(sig-val (ecdsa (r <bytes>)(s <bytes>)))`.
#[must_use]
pub(crate) fn encode_ecdsa_sig(r: &[u8], s: &[u8]) -> Vec<u8> {
    Sexp::List(vec![
        Sexp::atom(b"sig-val"),
        Sexp::List(vec![
            Sexp::atom(b"ecdsa"),
            Sexp::List(vec![Sexp::atom(b"r"), Sexp::atom(r)]),
            Sexp::List(vec![Sexp::atom(b"s"), Sexp::atom(s)]),
        ]),
    ])
    .to_canonical()
}

/// Encode an `EdDSA` signature as canonical `(sig-val (eddsa (r <bytes>)(s <bytes>)))`.
#[must_use]
pub(crate) fn encode_eddsa_sig(r: &[u8], s: &[u8]) -> Vec<u8> {
    Sexp::List(vec![
        Sexp::atom(b"sig-val"),
        Sexp::List(vec![
            Sexp::atom(b"eddsa"),
            Sexp::List(vec![Sexp::atom(b"r"), Sexp::atom(r)]),
            Sexp::List(vec![Sexp::atom(b"s"), Sexp::atom(s)]),
        ]),
    ])
    .to_canonical()
}

/// Encode a decrypted value as canonical `(value <bytes>)`.
#[must_use]
pub(crate) fn encode_decrypt_value(value: &[u8]) -> Vec<u8> {
    Sexp::List(vec![Sexp::atom(b"value"), Sexp::atom(value)]).to_canonical()
}

/// Encode an RSA public key as canonical `(public-key (rsa (n <n>)(e <e>)))`.
#[must_use]
pub(crate) fn encode_rsa_public_key(n: &[u8], e: &[u8]) -> Vec<u8> {
    Sexp::List(vec![
        Sexp::atom(b"public-key"),
        Sexp::List(vec![
            Sexp::atom(b"rsa"),
            Sexp::List(vec![Sexp::atom(b"n"), Sexp::atom(n)]),
            Sexp::List(vec![Sexp::atom(b"e"), Sexp::atom(e)]),
        ]),
    ])
    .to_canonical()
}

/// Encode an ECC public key as canonical `(public-key (ecc (curve <name>)[(flags <flag>)](q <q>)))`.
#[must_use]
pub(crate) fn encode_ecc_public_key(curve: &str, flags: Option<&str>, q: &[u8]) -> Vec<u8> {
    let mut ecc_items = vec![
        Sexp::atom(b"ecc"),
        Sexp::List(vec![Sexp::atom(b"curve"), Sexp::atom(curve.as_bytes())]),
    ];
    if let Some(flag) = flags {
        ecc_items.push(Sexp::List(vec![
            Sexp::atom(b"flags"),
            Sexp::atom(flag.as_bytes()),
        ]));
    }
    ecc_items.push(Sexp::List(vec![Sexp::atom(b"q"), Sexp::atom(q)]));

    Sexp::List(vec![Sexp::atom(b"public-key"), Sexp::List(ecc_items)]).to_canonical()
}

#[cfg(test)]
mod tests {
    use super::{
        EncVal, MAX_NESTING_DEPTH, Sexp, SexpError, encode_decrypt_value, encode_ecdsa_sig,
        encode_eddsa_sig, encode_rsa_sig, parse_enc_val,
    };

    #[test]
    fn roundtrip_atoms_and_nested_lists() {
        let cases = vec![
            Sexp::Atom(Vec::new()),
            Sexp::Atom(b"hello".to_vec()),
            Sexp::Atom(vec![0x00, b'(', b')', b':', 0xff, 0x0a]),
            Sexp::List(Vec::new()),
            Sexp::List(vec![
                Sexp::Atom(b"enc-val".to_vec()),
                Sexp::List(vec![
                    Sexp::Atom(b"rsa".to_vec()),
                    Sexp::List(vec![
                        Sexp::Atom(b"a".to_vec()),
                        Sexp::Atom(vec![0x01, 0x02, 0x03, 0x04]),
                    ]),
                ]),
            ]),
        ];

        for original in cases {
            let encoded = original.to_canonical();
            let decoded = Sexp::parse(&encoded).expect("canonical encoding must parse");
            assert_eq!(decoded, original);
            assert_eq!(decoded.to_canonical(), encoded);
        }
    }

    #[test]
    fn parse_exact_canonical_vectors() {
        assert_eq!(Sexp::parse(b"0:").unwrap(), Sexp::Atom(Vec::new()));
        assert_eq!(Sexp::parse(b"3:rsa").unwrap(), Sexp::Atom(b"rsa".to_vec()));
        assert_eq!(Sexp::parse(b"()").unwrap(), Sexp::List(Vec::new()));
        assert_eq!(
            Sexp::parse(b"(5:value3:\x00\xff:)").unwrap(),
            Sexp::List(vec![
                Sexp::Atom(b"value".to_vec()),
                Sexp::Atom(vec![0x00, 0xff, b':']),
            ])
        );
    }

    #[test]
    fn rejects_empty_and_truncated_inputs() {
        assert_eq!(Sexp::parse(b""), Err(SexpError::UnexpectedEof));
        assert_eq!(Sexp::parse(b"0"), Err(SexpError::UnexpectedEof));
        assert_eq!(Sexp::parse(b"12"), Err(SexpError::UnexpectedEof));
        assert_eq!(Sexp::parse(b"("), Err(SexpError::UnexpectedEof));
        assert_eq!(Sexp::parse(b"(3:abc"), Err(SexpError::UnexpectedEof));
        assert_eq!(
            Sexp::parse(b"4:abc"),
            Err(SexpError::TruncatedAtom {
                offset: 2,
                declared: 4,
                remaining: 3,
            })
        );
    }

    #[test]
    fn rejects_leading_zeros_and_non_ascii_lengths() {
        assert_eq!(
            Sexp::parse(b"00:"),
            Err(SexpError::InvalidLength { offset: 0 })
        );
        assert_eq!(
            Sexp::parse(b"01:a"),
            Err(SexpError::InvalidLength { offset: 0 })
        );
        assert_eq!(
            Sexp::parse(b"1a:x"),
            Err(SexpError::InvalidLength { offset: 1 })
        );
        assert_eq!(
            Sexp::parse(b"1\xff:x"),
            Err(SexpError::InvalidLength { offset: 1 })
        );
        assert_eq!(
            Sexp::parse(b"\xff:x"),
            Err(SexpError::UnexpectedByte {
                offset: 0,
                byte: 0xff,
            })
        );
        assert_eq!(
            Sexp::parse(b":abc"),
            Err(SexpError::UnexpectedByte {
                offset: 0,
                byte: b':',
            })
        );
        assert_eq!(
            Sexp::parse(b"-1:a"),
            Err(SexpError::UnexpectedByte {
                offset: 0,
                byte: b'-',
            })
        );
        assert_eq!(
            Sexp::parse(b"99999999999999999999999999999999:a"),
            Err(SexpError::LengthOverflow { offset: 0 })
        );
    }

    #[test]
    fn rejects_trailing_bytes_and_whitespace() {
        assert_eq!(
            Sexp::parse(b"3:abcd"),
            Err(SexpError::TrailingBytes {
                offset: 5,
                count: 1,
            })
        );
        assert_eq!(
            Sexp::parse(b"(3:abc))"),
            Err(SexpError::TrailingBytes {
                offset: 7,
                count: 1,
            })
        );
        assert_eq!(
            Sexp::parse(b"( 3:abc)"),
            Err(SexpError::UnexpectedByte {
                offset: 1,
                byte: b' ',
            })
        );
        assert_eq!(
            Sexp::parse(b")"),
            Err(SexpError::UnexpectedByte {
                offset: 0,
                byte: b')',
            })
        );
    }

    #[test]
    fn enforces_max_nesting_depth() {
        let mut at_limit = Vec::with_capacity(MAX_NESTING_DEPTH * 2);
        at_limit.resize(MAX_NESTING_DEPTH, b'(');
        at_limit.resize(MAX_NESTING_DEPTH * 2, b')');
        assert!(Sexp::parse(&at_limit).is_ok());

        let mut over_limit = Vec::with_capacity((MAX_NESTING_DEPTH + 1) * 2);
        over_limit.resize(MAX_NESTING_DEPTH + 1, b'(');
        over_limit.resize((MAX_NESTING_DEPTH + 1) * 2, b')');
        assert_eq!(Sexp::parse(&over_limit), Err(SexpError::MaxDepthExceeded));
    }

    #[test]
    fn parse_enc_val_rsa_with_and_without_flags() {
        let raw = b"(7:enc-val(3:rsa(1:a4:\xde\xad\xbe\xef)))";
        let sexp = Sexp::parse(raw).unwrap();
        assert_eq!(
            parse_enc_val(&sexp),
            Ok(EncVal::Rsa {
                a: vec![0xde, 0xad, 0xbe, 0xef],
            })
        );

        let with_flags = b"(7:enc-val(5:flags5:pkcs1)(3:rsa(1:a2:\x01\x02)))";
        let sexp_flags = Sexp::parse(with_flags).unwrap();
        assert_eq!(
            parse_enc_val(&sexp_flags),
            Ok(EncVal::Rsa {
                a: vec![0x01, 0x02],
            })
        );

        let trailing_flags = b"(7:enc-val(3:rsa(5:flags4:oaep)(1:a1:\x42))(5:flags5:pkcs1))";
        let sexp_trailing = Sexp::parse(trailing_flags).unwrap();
        assert_eq!(
            parse_enc_val(&sexp_trailing),
            Ok(EncVal::Rsa { a: vec![0x42] })
        );
    }

    #[test]
    fn parse_enc_val_ecdh_with_optional_s_and_flags() {
        let minimal = b"(7:enc-val(4:ecdh(1:e3:\x04\x11\x22)))";
        assert_eq!(
            parse_enc_val(&Sexp::parse(minimal).unwrap()),
            Ok(EncVal::Ecdh {
                e: vec![0x04, 0x11, 0x22],
            })
        );

        let with_s_and_flags =
            b"(7:enc-val(5:flags3:raw)(4:ecdh(1:s4:\xaa\xbb\xcc\xdd)(1:e3:\x04\xaa\xbb)))";
        assert_eq!(
            parse_enc_val(&Sexp::parse(with_s_and_flags).unwrap()),
            Ok(EncVal::Ecdh {
                e: vec![0x04, 0xaa, 0xbb],
            })
        );
    }

    #[test]
    fn parse_enc_val_rejects_malformed_structures() {
        let invalid_cases: &[&[u8]] = &[
            b"7:enc-val",
            b"()",
            b"(7:sig-val(3:rsa(1:a1:x)))",
            b"(7:enc-val)",
            b"(7:enc-val(5:flags5:pkcs1))",
            b"(7:enc-val(3:elg(1:a1:x)))",
            b"(7:enc-val(3:rsa))",
            b"(7:enc-val(3:rsa(1:a)))",
            b"(7:enc-val(3:rsa(1:a1:x1:y)))",
            b"(7:enc-val(3:rsa(1:a(1:x))))",
            b"(7:enc-val(3:rsa(1:a1:x)(1:a1:y)))",
            b"(7:enc-val(3:rsa(1:a1:x))(4:ecdh(1:e1:y)))",
            b"(7:enc-val(4:ecdh(1:s2:ab)))",
            b"(7:enc-val(4:ecdh(1:e1:x)(1:e1:y)))",
            b"(7:enc-val(4:ecdh(1:z1:x)(1:e1:y)))",
        ];

        for raw in invalid_cases {
            let sexp = Sexp::parse(raw).expect("test input should be syntactically valid");
            assert!(
                parse_enc_val(&sexp).is_err(),
                "expected parse_enc_val to reject {}",
                String::from_utf8_lossy(raw)
            );
        }
    }

    #[test]
    fn encode_rsa_sig_format() {
        let encoded = encode_rsa_sig(&[0x01, 0x02, 0x03]);
        assert_eq!(encoded, b"(7:sig-val(3:rsa(1:s3:\x01\x02\x03)))");
        assert_eq!(
            Sexp::parse(&encoded).unwrap(),
            Sexp::List(vec![
                Sexp::Atom(b"sig-val".to_vec()),
                Sexp::List(vec![
                    Sexp::Atom(b"rsa".to_vec()),
                    Sexp::List(vec![
                        Sexp::Atom(b"s".to_vec()),
                        Sexp::Atom(vec![0x01, 0x02, 0x03]),
                    ]),
                ]),
            ])
        );
    }

    #[test]
    fn encode_ecdsa_sig_format() {
        let encoded = encode_ecdsa_sig(&[0xaa, 0xbb], &[0xcc, 0xdd, 0xee]);
        assert_eq!(
            encoded,
            b"(7:sig-val(5:ecdsa(1:r2:\xaa\xbb)(1:s3:\xcc\xdd\xee)))"
        );
        assert_eq!(
            Sexp::parse(&encoded).unwrap(),
            Sexp::List(vec![
                Sexp::Atom(b"sig-val".to_vec()),
                Sexp::List(vec![
                    Sexp::Atom(b"ecdsa".to_vec()),
                    Sexp::List(vec![
                        Sexp::Atom(b"r".to_vec()),
                        Sexp::Atom(vec![0xaa, 0xbb]),
                    ]),
                    Sexp::List(vec![
                        Sexp::Atom(b"s".to_vec()),
                        Sexp::Atom(vec![0xcc, 0xdd, 0xee]),
                    ]),
                ]),
            ])
        );
    }

    #[test]
    fn encode_eddsa_sig_format() {
        let encoded = encode_eddsa_sig(&[0x10, 0x20], &[0x30, 0x40]);
        assert_eq!(
            encoded,
            b"(7:sig-val(5:eddsa(1:r2:\x10\x20)(1:s2:\x30\x40)))"
        );
        assert_eq!(
            Sexp::parse(&encoded).unwrap(),
            Sexp::List(vec![
                Sexp::Atom(b"sig-val".to_vec()),
                Sexp::List(vec![
                    Sexp::Atom(b"eddsa".to_vec()),
                    Sexp::List(vec![
                        Sexp::Atom(b"r".to_vec()),
                        Sexp::Atom(vec![0x10, 0x20]),
                    ]),
                    Sexp::List(vec![
                        Sexp::Atom(b"s".to_vec()),
                        Sexp::Atom(vec![0x30, 0x40]),
                    ]),
                ]),
            ])
        );
    }

    #[test]
    fn encode_decrypt_value_format() {
        let encoded = encode_decrypt_value(b"\x00secret");
        assert_eq!(encoded, b"(5:value7:\x00secret)");
        assert_eq!(
            Sexp::parse(&encoded).unwrap(),
            Sexp::List(vec![
                Sexp::Atom(b"value".to_vec()),
                Sexp::Atom(b"\x00secret".to_vec()),
            ])
        );
    }

    #[test]
    fn error_display_is_non_empty() {
        let errors = [
            SexpError::UnexpectedEof,
            SexpError::UnexpectedByte {
                offset: 1,
                byte: 0x20,
            },
            SexpError::InvalidLength { offset: 0 },
            SexpError::LengthOverflow { offset: 0 },
            SexpError::TruncatedAtom {
                offset: 2,
                declared: 10,
                remaining: 3,
            },
            SexpError::TrailingBytes {
                offset: 4,
                count: 2,
            },
            SexpError::MaxDepthExceeded,
            SexpError::InvalidStructure("test"),
        ];
        for err in errors {
            assert_ne!(err.to_string(), "");
        }
    }
}
