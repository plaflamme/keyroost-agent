use std::fmt::Write as _;

use keyroost_openpgp::{
    AlgorithmAttributes, Curve, KeyCrt, PublicKey, aid_manufacturer_id, manufacturer_name,
    parse_algorithm_attributes,
};
use tokio::io::AsyncWrite;
use tracing::warn;

use crate::{
    assuan::{GPG_ERR_INV_DATA, GPG_ERR_NO_DATA, GPG_ERR_NOT_IMPLEMENTED, GPG_ERR_UNKNOWN_COMMAND},
    card::openpgp::{OpenPgpCardStatus, OpenPgpKeyInfo},
    protocol::gpg::{
        GpgCardBackend,
        keygrip::compute_keygrip,
        server::{
            AGENT_VERSION, GPG_OPENPGP_SLOTS, ServerContext, map_card_error, send_data_bytes,
            send_err, split_command, write_line,
        },
        sexp::{encode_ecc_public_key, encode_rsa_public_key},
    },
};

/// Conservative read-only `EXTCAP` capabilities line for `OpenPGP` card emulation.
const READ_ONLY_EXTCAP: &str = "gc=0 ki=0 fc=0 pd=0 mcl3=0 aac=0 sm=0 si=0 dec=0 bt=0";

/// Dispatch a read-only `SCD <subcmd> [args]` command.
pub(super) async fn handle_scd<W, C>(
    args: &str,
    ctx: &ServerContext<C>,
    writer: &mut W,
) -> Result<(), std::io::Error>
where
    W: AsyncWrite + Unpin,
    C: GpgCardBackend,
{
    let trimmed = args.trim();
    if trimmed.is_empty() {
        return send_err(writer, GPG_ERR_INV_DATA, "Missing SCD subcommand").await;
    }

    let (subcmd_raw, subargs) = split_command(trimmed);
    let subcmd = subcmd_raw.to_ascii_uppercase();

    match subcmd.as_str() {
        "NOP" | "RESTART" | "BYE" | "OPTION" => write_line(writer, "OK").await,
        "SERIALNO" => handle_serialno(subargs, ctx, writer).await,
        "GETINFO" => handle_getinfo(subargs, ctx, writer).await,
        "LEARN" => handle_learn(subargs, ctx, writer).await,
        "READKEY" => handle_readkey(subargs, ctx, writer).await,
        "GETATTR" => handle_getattr(subargs, ctx, writer).await,
        "SETATTR" | "GENKEY" | "WRITEKEY" | "WRITECERT" | "PASSWD" | "CHECKPIN" | "RESET"
        | "SETDATA" | "PKSIGN" | "PKDECRYPT" | "PKAUTH" | "RANDOM" | "APDU" | "KILLSCD" => {
            send_err(
                writer,
                GPG_ERR_NOT_IMPLEMENTED,
                "Read-only SCD emulation: command not supported",
            )
            .await
        }
        _ => send_err(writer, GPG_ERR_UNKNOWN_COMMAND, "Unknown SCD command").await,
    }
}

async fn fetch_status<W, C>(
    ctx: &ServerContext<C>,
    writer: &mut W,
) -> Result<Option<OpenPgpCardStatus>, std::io::Error>
where
    W: AsyncWrite + Unpin,
    C: GpgCardBackend,
{
    let Some(card) = &ctx.card else {
        send_err(writer, GPG_ERR_NO_DATA, "No OpenPGP card configured").await?;
        return Ok(None);
    };

    match card.card_status().await {
        Ok(status) => Ok(Some(status)),
        Err(err) => {
            let (code, msg) = map_card_error(&err);
            send_err(writer, code, &msg).await?;
            Ok(None)
        }
    }
}

async fn handle_serialno<W, C>(
    args: &str,
    ctx: &ServerContext<C>,
    writer: &mut W,
) -> Result<(), std::io::Error>
where
    W: AsyncWrite + Unpin,
    C: GpgCardBackend,
{
    for token in args.split_whitespace() {
        if let Some(demand) = token.strip_prefix("--demand=") {
            if !demand.eq_ignore_ascii_case("openpgp") {
                return send_err(writer, GPG_ERR_NOT_IMPLEMENTED, "Unsupported card application")
                    .await;
            }
        } else if token.starts_with("--") {
            // Ignore benign flags such as --all.
        } else if !token.eq_ignore_ascii_case("openpgp") {
            return send_err(writer, GPG_ERR_NOT_IMPLEMENTED, "Unsupported card application").await;
        }
    }

    let Some(status) = fetch_status(ctx, writer).await? else {
        return Ok(());
    };

    let aid_hex = encode_hex_upper(&status.aid);
    write_line(writer, &format!("S SERIALNO {aid_hex} 0")).await?;
    write_line(writer, "OK").await
}

async fn handle_getinfo<W, C>(
    args: &str,
    ctx: &ServerContext<C>,
    writer: &mut W,
) -> Result<(), std::io::Error>
where
    W: AsyncWrite + Unpin,
    C: GpgCardBackend,
{
    let Some(what) = args.split_whitespace().next() else {
        return send_err(writer, GPG_ERR_INV_DATA, "Missing SCD GETINFO subcommand").await;
    };

    match what.to_ascii_lowercase().as_str() {
        "version" => {
            send_data_bytes(writer, AGENT_VERSION.as_bytes()).await?;
            write_line(writer, "OK").await
        }
        "pid" => {
            let pid = std::process::id().to_string();
            send_data_bytes(writer, pid.as_bytes()).await?;
            write_line(writer, "OK").await
        }
        "app_list" => {
            send_data_bytes(writer, b"openpgp\n").await?;
            write_line(writer, "OK").await
        }
        "reader_list" => {
            let Some(status) = fetch_status(ctx, writer).await? else {
                return Ok(());
            };
            let line = format!("{}\n", status.reader);
            send_data_bytes(writer, line.as_bytes()).await?;
            write_line(writer, "OK").await
        }
        _ => send_err(writer, GPG_ERR_INV_DATA, "Unknown SCD GETINFO subcommand").await,
    }
}

async fn handle_learn<W, C>(
    args: &str,
    ctx: &ServerContext<C>,
    writer: &mut W,
) -> Result<(), std::io::Error>
where
    W: AsyncWrite + Unpin,
    C: GpgCardBackend,
{
    let mut only_keypairinfo = false;
    for token in args.split_whitespace() {
        match token {
            "--force" => {}
            "--keypairinfo" => only_keypairinfo = true,
            t if t.starts_with("--") => {}
            _ => {
                return send_err(writer, GPG_ERR_INV_DATA, "Unexpected argument to SCD LEARN")
                    .await;
            }
        }
    }

    let Some(status) = fetch_status(ctx, writer).await? else {
        return Ok(());
    };
    let Some(card) = &ctx.card else {
        return send_err(writer, GPG_ERR_NO_DATA, "No OpenPGP card configured").await;
    };

    let keys = match card.list_keys(&GPG_OPENPGP_SLOTS).await {
        Ok(keys) => keys,
        Err(err) => {
            let (code, msg) = map_card_error(&err);
            return send_err(writer, code, &msg).await;
        }
    };

    let aid_hex = encode_hex_upper(&status.aid);
    write_line(writer, &format!("S SERIALNO {aid_hex}")).await?;
    write_line(writer, "S APPTYPE OPENPGP").await?;

    if !only_keypairinfo {
        write_line(writer, &format!("S EXTCAP {READ_ONLY_EXTCAP}")).await?;
        emit_key_fprs(writer, &status).await?;
        emit_key_attrs(writer, &status).await?;
    }

    emit_keypairinfo(writer, &keys).await?;

    if !only_keypairinfo {
        emit_chv_status(writer, &status).await?;
        if let Some(count) = status.signature_count {
            write_line(writer, &format!("S SIG-COUNTER {count}")).await?;
        }
    }

    write_line(writer, "OK").await
}

async fn handle_readkey<W, C>(
    args: &str,
    ctx: &ServerContext<C>,
    writer: &mut W,
) -> Result<(), std::io::Error>
where
    W: AsyncWrite + Unpin,
    C: GpgCardBackend,
{
    let mut keyref: Option<&str> = None;
    for token in args.split_whitespace() {
        if token == "--advanced" {
            // Canonical S-expression output is always returned.
        } else if token.starts_with("--") {
            // Ignore unknown flags gracefully.
        } else if keyref.is_none() {
            keyref = Some(token);
        } else {
            return send_err(writer, GPG_ERR_INV_DATA, "Too many arguments to SCD READKEY").await;
        }
    }

    let Some(keyref) = keyref else {
        return send_err(writer, GPG_ERR_INV_DATA, "Missing keyref for SCD READKEY").await;
    };

    let Some(slot) = parse_openpgp_keyref(keyref) else {
        return send_err(writer, GPG_ERR_INV_DATA, "Invalid OpenPGP keyref").await;
    };

    let Some(card) = &ctx.card else {
        return send_err(writer, GPG_ERR_NO_DATA, "No OpenPGP card configured").await;
    };

    let keys = match card.list_keys(&[slot]).await {
        Ok(keys) => keys,
        Err(err) => {
            let (code, msg) = map_card_error(&err);
            return send_err(writer, code, &msg).await;
        }
    };

    let Some(key) = keys.into_iter().find(|k| k.slot == slot) else {
        return send_err(writer, GPG_ERR_NO_DATA, "No key in requested slot").await;
    };

    let encoded = match encode_public_key_sexp(key.attrs, &key.public_key) {
        Ok(bytes) => bytes,
        Err(msg) => return send_err(writer, GPG_ERR_INV_DATA, &msg).await,
    };

    send_data_bytes(writer, &encoded).await?;
    write_line(writer, "OK").await
}

async fn handle_getattr<W, C>(
    args: &str,
    ctx: &ServerContext<C>,
    writer: &mut W,
) -> Result<(), std::io::Error>
where
    W: AsyncWrite + Unpin,
    C: GpgCardBackend,
{
    let Some(attr) = args.split_whitespace().next() else {
        return send_err(writer, GPG_ERR_INV_DATA, "Missing attribute name").await;
    };

    let attr_upper = attr.to_ascii_uppercase();

    // Unavailable read-only OpenPGP card attributes that gpg --card-status may probe.
    if matches!(
        attr_upper.as_str(),
        "DISP-NAME"
            | "DISP-LANG"
            | "DISP-SEX"
            | "PUBKEY-URL"
            | "LOGIN-DATA"
            | "PRIVATE-DO-1"
            | "PRIVATE-DO-2"
            | "PRIVATE-DO-3"
            | "PRIVATE-DO-4"
            | "KEY-TIME"
            | "CA-FPR"
            | "KDF"
            | "UIF"
    ) {
        return send_err(writer, GPG_ERR_NO_DATA, "Attribute not available").await;
    }

    if !matches!(
        attr_upper.as_str(),
        "KEY-FPR"
            | "KEY-ATTR"
            | "CHV-STATUS"
            | "SIG-COUNTER"
            | "EXTCAP"
            | "APP-VERSION"
            | "MANUFACTURER"
    ) {
        return send_err(writer, GPG_ERR_NOT_IMPLEMENTED, "Unsupported attribute").await;
    }

    let Some(status) = fetch_status(ctx, writer).await? else {
        return Ok(());
    };

    match attr_upper.as_str() {
        "KEY-FPR" => {
            emit_key_fprs(writer, &status).await?;
            write_line(writer, "OK").await
        }
        "KEY-ATTR" => {
            emit_key_attrs(writer, &status).await?;
            write_line(writer, "OK").await
        }
        "CHV-STATUS" => {
            emit_chv_status(writer, &status).await?;
            write_line(writer, "OK").await
        }
        "SIG-COUNTER" => {
            if let Some(count) = status.signature_count {
                write_line(writer, &format!("S SIG-COUNTER {count}")).await?;
                write_line(writer, "OK").await
            } else {
                send_err(writer, GPG_ERR_NO_DATA, "No signature counter").await
            }
        }
        "EXTCAP" => {
            write_line(writer, &format!("S EXTCAP {READ_ONLY_EXTCAP}")).await?;
            write_line(writer, "OK").await
        }
        "APP-VERSION" => {
            if status.aid.len() >= 8 {
                let major = status.aid[6];
                let minor = status.aid[7];
                write_line(writer, &format!("S APP-VERSION {major:x}.{minor:x}")).await?;
                write_line(writer, "OK").await
            } else {
                send_err(writer, GPG_ERR_NO_DATA, "AID too short for app version").await
            }
        }
        "MANUFACTURER" => {
            if let Some(id) = aid_manufacturer_id(&status.aid) {
                let name = manufacturer_name(id).unwrap_or("unknown");
                write_line(writer, &format!("S MANUFACTURER {id:04X} {name}")).await?;
                write_line(writer, "OK").await
            } else {
                send_err(writer, GPG_ERR_NO_DATA, "Manufacturer ID unavailable").await
            }
        }
        _ => unreachable!(),
    }
}

async fn emit_key_fprs<W: AsyncWrite + Unpin>(
    writer: &mut W,
    status: &OpenPgpCardStatus,
) -> Result<(), std::io::Error> {
    let slots = [
        (1u8, &status.fingerprint_sig),
        (2u8, &status.fingerprint_dec),
        (3u8, &status.fingerprint_aut),
    ];
    for (slot_no, fpr) in slots {
        if *fpr != [0u8; 20] {
            let fpr_hex = encode_hex_upper(fpr);
            write_line(writer, &format!("S KEY-FPR {slot_no} {fpr_hex}")).await?;
        }
    }
    Ok(())
}

async fn emit_key_attrs<W: AsyncWrite + Unpin>(
    writer: &mut W,
    status: &OpenPgpCardStatus,
) -> Result<(), std::io::Error> {
    let slots = [
        (1u8, status.sig_attrs.as_slice()),
        (2u8, status.dec_attrs.as_slice()),
        (3u8, status.aut_attrs.as_slice()),
    ];
    for (slot_no, raw_attrs) in slots {
        if raw_attrs.is_empty() {
            continue;
        }
        if let Ok(attrs) = parse_algorithm_attributes(raw_attrs) {
            let (algo_id, spec) = format_key_attr(attrs);
            write_line(writer, &format!("S KEY-ATTR {slot_no} {algo_id} {spec}")).await?;
        }
    }
    Ok(())
}

async fn emit_keypairinfo<W: AsyncWrite + Unpin>(
    writer: &mut W,
    keys: &[OpenPgpKeyInfo],
) -> Result<(), std::io::Error> {
    for key in keys {
        match compute_keygrip(key.attrs, &key.public_key) {
            Ok(kg) => {
                let idstr = slot_idstr(key.slot);
                write_line(writer, &format!("S KEYPAIRINFO {kg} {idstr}")).await?;
            }
            Err(err) => {
                warn!(slot = ?key.slot, "skipping OpenPGP slot with invalid keygrip: {err}");
            }
        }
    }
    Ok(())
}

async fn emit_chv_status<W: AsyncWrite + Unpin>(
    writer: &mut W,
    status: &OpenPgpCardStatus,
) -> Result<(), std::io::Error> {
    write_line(
        writer,
        &format!(
            "S CHV-STATUS +1 127 127 127 {} {} {}",
            status.tries_pw1, status.tries_rc, status.tries_pw3
        ),
    )
    .await
}

fn format_key_attr(attrs: AlgorithmAttributes) -> (u8, String) {
    match attrs {
        AlgorithmAttributes::Rsa(rsa) => (1, format!("rsa{}", rsa.n_bits)),
        AlgorithmAttributes::Ecc { kind, curve, .. } => {
            (kind.id(), scd_key_attr_curve_name(curve).to_owned())
        }
    }
}

const fn scd_key_attr_curve_name(curve: Curve) -> &'static str {
    match curve {
        Curve::Ed25519 => "ed25519",
        Curve::X25519 => "cv25519",
        Curve::NistP256 => "nistp256",
        Curve::NistP384 => "nistp384",
        Curve::NistP521 => "nistp521",
        Curve::Secp256k1 => "secp256k1",
        Curve::BrainpoolP256r1 => "brainpoolP256r1",
        Curve::BrainpoolP384r1 => "brainpoolP384r1",
        Curve::BrainpoolP512r1 => "brainpoolP512r1",
    }
}

const fn libgcrypt_curve_name(curve: Curve) -> &'static str {
    match curve {
        Curve::Ed25519 => "Ed25519",
        Curve::X25519 => "Curve25519",
        Curve::NistP256 => "NIST P-256",
        Curve::NistP384 => "NIST P-384",
        Curve::NistP521 => "NIST P-521",
        Curve::Secp256k1 => "secp256k1",
        Curve::BrainpoolP256r1 => "brainpoolP256r1",
        Curve::BrainpoolP384r1 => "brainpoolP384r1",
        Curve::BrainpoolP512r1 => "brainpoolP512r1",
    }
}

const fn slot_idstr(slot: KeyCrt) -> &'static str {
    match slot {
        KeyCrt::Sign => "OPENPGP.1",
        KeyCrt::Decrypt => "OPENPGP.2",
        KeyCrt::Auth => "OPENPGP.3",
    }
}

fn parse_openpgp_keyref(keyref: &str) -> Option<KeyCrt> {
    match keyref.to_ascii_uppercase().as_str() {
        "OPENPGP.1" => Some(KeyCrt::Sign),
        "OPENPGP.2" => Some(KeyCrt::Decrypt),
        "OPENPGP.3" => Some(KeyCrt::Auth),
        _ => None,
    }
}

fn encode_std_mpi(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let first_non_zero = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    let stripped = &bytes[first_non_zero..];
    if stripped.is_empty() {
        return Err("RSA public key integer is empty or zero".to_owned());
    }
    if stripped[0] & 0x80 != 0 {
        let mut out = Vec::with_capacity(stripped.len() + 1);
        out.push(0x00);
        out.extend_from_slice(stripped);
        Ok(out)
    } else {
        Ok(stripped.to_vec())
    }
}

fn encode_public_key_sexp(
    attrs: AlgorithmAttributes,
    pubkey: &PublicKey,
) -> Result<Vec<u8>, String> {
    match (attrs, pubkey) {
        (AlgorithmAttributes::Rsa(_), PublicKey::Rsa { modulus, exponent }) => {
            let n = encode_std_mpi(modulus)?;
            let e = encode_std_mpi(exponent)?;
            Ok(encode_rsa_public_key(&n, &e))
        }
        (AlgorithmAttributes::Ecc { curve, .. }, PublicKey::Ecc { point }) => {
            let curve_name = libgcrypt_curve_name(curve);
            match curve {
                Curve::Ed25519 => {
                    let q = normalize_25519_readkey_point(curve, point)?;
                    Ok(encode_ecc_public_key(curve_name, Some("eddsa"), &q))
                }
                Curve::X25519 => {
                    let q = normalize_25519_readkey_point(curve, point)?;
                    Ok(encode_ecc_public_key(curve_name, Some("djb-tweak"), &q))
                }
                _ => {
                    let expected_len = 1 + 2 * curve.field_len();
                    if point.len() != expected_len || point.first() != Some(&0x04) {
                        return Err(format!(
                            "invalid {} public point: expected {expected_len}-byte uncompressed point",
                            curve.label()
                        ));
                    }
                    Ok(encode_ecc_public_key(curve_name, None, point))
                }
            }
        }
        _ => Err("algorithm attributes do not match public key type".to_owned()),
    }
}

fn normalize_25519_readkey_point(curve: Curve, point: &[u8]) -> Result<Vec<u8>, String> {
    match point {
        [0x40, rest @ ..] if rest.len() == 32 => Ok(point.to_vec()),
        _ if point.len() == 32 => {
            let mut out = Vec::with_capacity(33);
            out.push(0x40);
            out.extend_from_slice(point);
            Ok(out)
        }
        _ => Err(format!(
            "invalid {} public point length: expected 32 bytes (or 33 with 0x40 prefix), got {}",
            curve.label(),
            point.len()
        )),
    }
}

fn encode_hex_upper(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02X}");
    }
    out
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use keyroost_openpgp::{
        AlgorithmAttributes, Curve, EccKind, KeyCrt, PublicKey, RsaAttributes, RsaImportFormat,
    };
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    use crate::{
        assuan::{
            GPG_ERR_INV_DATA, GPG_ERR_NO_DATA, GPG_ERR_NOT_IMPLEMENTED, GPG_ERR_SOURCE_GPGAGENT,
            GPG_ERR_UNKNOWN_COMMAND, gpg_err_make, percent_decode,
        },
        card::{
            CardOperationOutcome,
            openpgp::{OpenPgpCardStatus, OpenPgpKeyInfo},
        },
        idle::IdleTracker,
        pinentry::PinentryEnv,
        protocol::gpg::{
            GpgCardBackend,
            cache::GpgKeyCache,
            keygrip::{Keygrip, compute_keygrip},
            server::serve_connection,
            sexp::Sexp,
        },
    };

    /// Full 16-byte `OpenPGP` v3.4 AID with Yubico manufacturer ID (`0006`) and serial `0x12345678`.
    fn yubico_aid() -> Vec<u8> {
        vec![
            0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x03, 0x04, 0x00, 0x06, 0x12, 0x34, 0x56, 0x78,
            0x00, 0x00,
        ]
    }

    fn rsa_raw_attrs(n_bits: u16) -> Vec<u8> {
        let [hi, lo] = n_bits.to_be_bytes();
        vec![0x01, hi, lo, 0x00, 0x20, 0x00]
    }

    fn ecc_raw_attrs(kind: EccKind, curve: Curve) -> Vec<u8> {
        let mut out = vec![kind.id()];
        out.extend_from_slice(curve.oid());
        out
    }

    fn rsa_key_info(slot: KeyCrt) -> (OpenPgpKeyInfo, Keygrip) {
        let attrs = AlgorithmAttributes::Rsa(RsaAttributes {
            n_bits: 2048,
            e_bits: 32,
            format: RsaImportFormat::Standard,
        });
        let mut modulus = vec![0xA5; 256];
        modulus[255] = 0x01;
        let public_key = PublicKey::Rsa {
            modulus,
            exponent: vec![0x01, 0x00, 0x01],
        };
        let kg = compute_keygrip(attrs, &public_key).unwrap();
        let info = OpenPgpKeyInfo {
            slot,
            attrs,
            public_key,
            fingerprint: [0x11; 20],
            aid: yubico_aid(),
            serial: Some(0x1234_5678),
            full_serial: Some(0x1234_5678),
        };
        (info, kg)
    }

    fn ecdsa_p256_key_info(slot: KeyCrt) -> (OpenPgpKeyInfo, Keygrip) {
        let attrs = AlgorithmAttributes::Ecc {
            kind: EccKind::Ecdsa,
            curve: Curve::NistP256,
            import_with_public_key: false,
        };
        let mut point = vec![0x04];
        point.extend_from_slice(&[0x33; 64]);
        let public_key = PublicKey::Ecc { point };
        let kg = compute_keygrip(attrs, &public_key).unwrap();
        let info = OpenPgpKeyInfo {
            slot,
            attrs,
            public_key,
            fingerprint: [0x22; 20],
            aid: yubico_aid(),
            serial: Some(0x1234_5678),
            full_serial: Some(0x1234_5678),
        };
        (info, kg)
    }

    fn ed25519_key_info(slot: KeyCrt) -> (OpenPgpKeyInfo, Keygrip) {
        let attrs = AlgorithmAttributes::Ecc {
            kind: EccKind::EdDsa,
            curve: Curve::Ed25519,
            import_with_public_key: false,
        };
        let public_key = PublicKey::Ecc {
            point: vec![0x44; 32],
        };
        let kg = compute_keygrip(attrs, &public_key).unwrap();
        let info = OpenPgpKeyInfo {
            slot,
            attrs,
            public_key,
            fingerprint: [0x33; 20],
            aid: yubico_aid(),
            serial: Some(0x1234_5678),
            full_serial: Some(0x1234_5678),
        };
        (info, kg)
    }

    fn cv25519_key_info(slot: KeyCrt) -> (OpenPgpKeyInfo, Keygrip) {
        let attrs = AlgorithmAttributes::Ecc {
            kind: EccKind::Ecdh,
            curve: Curve::X25519,
            import_with_public_key: false,
        };
        let public_key = PublicKey::Ecc {
            point: vec![0x55; 32],
        };
        let kg = compute_keygrip(attrs, &public_key).unwrap();
        let info = OpenPgpKeyInfo {
            slot,
            attrs,
            public_key,
            fingerprint: [0x44; 20],
            aid: yubico_aid(),
            serial: Some(0x1234_5678),
            full_serial: Some(0x1234_5678),
        };
        (info, kg)
    }

    struct MockScdState {
        status: OpenPgpCardStatus,
        keys: Vec<OpenPgpKeyInfo>,
    }

    #[derive(Clone)]
    struct MockScdCard {
        state: Arc<Mutex<MockScdState>>,
    }

    impl MockScdCard {
        fn new(status: OpenPgpCardStatus, keys: Vec<OpenPgpKeyInfo>) -> Self {
            Self {
                state: Arc::new(Mutex::new(MockScdState { status, keys })),
            }
        }
    }

    impl GpgCardBackend for MockScdCard {
        fn card_status(
            &self,
        ) -> impl std::future::Future<Output = Result<OpenPgpCardStatus, crate::Error>> + Send
        {
            let status = self.state.lock().unwrap().status.clone();
            std::future::ready(Ok(status))
        }

        fn list_keys(
            &self,
            slots: &[KeyCrt],
        ) -> impl std::future::Future<Output = Result<Vec<OpenPgpKeyInfo>, crate::Error>> + Send
        {
            let keys = self
                .state
                .lock()
                .unwrap()
                .keys
                .iter()
                .filter(|k| slots.contains(&k.slot))
                .cloned()
                .collect();
            std::future::ready(Ok(keys))
        }

        fn sign_raw(
            &self,
            _slot: KeyCrt,
            _expected_serial: Option<u128>,
            _data: &[u8],
            _prompt_desc: Option<&str>,
            _prompt_env: Option<&PinentryEnv>,
        ) -> impl std::future::Future<
            Output = Result<CardOperationOutcome<Vec<u8>>, crate::Error>,
        > + Send {
            std::future::ready(Ok(CardOperationOutcome::NotFound))
        }

        fn decrypt_rsa(
            &self,
            _expected_serial: Option<u128>,
            _cryptogram: &[u8],
            _prompt_desc: Option<&str>,
            _prompt_env: Option<&PinentryEnv>,
        ) -> impl std::future::Future<
            Output = Result<CardOperationOutcome<Vec<u8>>, crate::Error>,
        > + Send {
            std::future::ready(Ok(CardOperationOutcome::NotFound))
        }

        fn decrypt_ecdh(
            &self,
            _expected_serial: Option<u128>,
            _ephemeral_point: &[u8],
            _prompt_desc: Option<&str>,
            _prompt_env: Option<&PinentryEnv>,
        ) -> impl std::future::Future<
            Output = Result<CardOperationOutcome<Vec<u8>>, crate::Error>,
        > + Send {
            std::future::ready(Ok(CardOperationOutcome::NotFound))
        }

        fn disconnect(&self) -> impl std::future::Future<Output = ()> + Send {
            std::future::ready(())
        }
    }

    struct TestClient {
        reader: BufReader<tokio::io::ReadHalf<tokio::io::DuplexStream>>,
        writer: tokio::io::WriteHalf<tokio::io::DuplexStream>,
    }

    impl TestClient {
        async fn read_line(&mut self) -> String {
            let mut line = String::new();
            let n = self.reader.read_line(&mut line).await.unwrap();
            assert!(n > 0, "unexpected EOF from server");
            line.trim_end_matches(['\r', '\n']).to_owned()
        }

        async fn send_line(&mut self, line: &str) {
            self.writer.write_all(line.as_bytes()).await.unwrap();
            self.writer.write_all(b"\n").await.unwrap();
            self.writer.flush().await.unwrap();
        }

        async fn command(&mut self, cmd: &str) -> (Vec<String>, Vec<u8>, String) {
            self.send_line(cmd).await;
            let mut status_lines = Vec::new();
            let mut data = Vec::new();
            loop {
                let line = self.read_line().await;
                if let Some(payload) = line.strip_prefix("D ") {
                    percent_decode(payload, &mut data).unwrap();
                } else if line.starts_with("S ") {
                    status_lines.push(line);
                } else {
                    return (status_lines, data, line);
                }
            }
        }
    }

    async fn spawn_server(
        card: Option<MockScdCard>,
    ) -> (TestClient, tokio::task::JoinHandle<()>) {
        let (client_stream, server_stream) = tokio::io::duplex(65536);
        let handle = tokio::spawn(async move {
            let _ = serve_connection(
                server_stream,
                card,
                IdleTracker::new(),
                None,
                GpgKeyCache::new(),
                None,
            )
            .await;
        });

        let (read_half, writer) = tokio::io::split(client_stream);
        let mut client = TestClient {
            reader: BufReader::new(read_half),
            writer,
        };
        let greeting = client.read_line().await;
        assert!(greeting.starts_with("OK"));
        (client, handle)
    }

    fn err_prefix(code: u32) -> String {
        format!("ERR {}", gpg_err_make(GPG_ERR_SOURCE_GPGAGENT, code))
    }

    fn default_status() -> OpenPgpCardStatus {
        OpenPgpCardStatus {
            reader: "Yubico YubiKey OTP+FIDO+CCID 00 00".to_owned(),
            aid: yubico_aid(),
            sig_attrs: ecc_raw_attrs(EccKind::EdDsa, Curve::Ed25519),
            dec_attrs: ecc_raw_attrs(EccKind::Ecdh, Curve::X25519),
            aut_attrs: rsa_raw_attrs(2048),
            fingerprint_sig: [0x33; 20],
            fingerprint_dec: [0x44; 20],
            fingerprint_aut: [0x00; 20],
            tries_pw1: 3,
            tries_rc: 0,
            tries_pw3: 3,
            signature_count: Some(42),
            serial: Some(0x1234_5678),
            full_serial: Some(0x1234_5678),
        }
    }

    #[tokio::test]
    async fn scd_serialno_returns_aid_and_validates_application() {
        let card = MockScdCard::new(default_status(), Vec::new());
        let (mut client, handle) = spawn_server(Some(card)).await;

        let (status, data, term) = client.command("SCD SERIALNO").await;
        assert_eq!(term, "OK");
        assert_eq!(data, b"");
        assert_eq!(
            status,
            vec!["S SERIALNO D2760001240103040006123456780000 0"]
        );

        let (status, _, term) = client.command("scd serialno openpgp").await;
        assert_eq!(term, "OK");
        assert_eq!(
            status,
            vec!["S SERIALNO D2760001240103040006123456780000 0"]
        );

        let (_, _, term) = client.command("SCD SERIALNO piv").await;
        assert!(term.starts_with(&err_prefix(GPG_ERR_NOT_IMPLEMENTED)));

        let (_, _, term) = client.command("BYE").await;
        assert!(term.starts_with("OK"));
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn scd_serialno_without_card_returns_no_data() {
        let (mut client, handle) = spawn_server(None).await;

        let (_, _, term) = client.command("SCD SERIALNO").await;
        assert!(term.starts_with(&err_prefix(GPG_ERR_NO_DATA)));

        let (_, _, term) = client.command("BYE").await;
        assert!(term.starts_with("OK"));
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn scd_getinfo_supports_version_reader_list_and_app_list() {
        let card = MockScdCard::new(default_status(), Vec::new());
        let (mut client, handle) = spawn_server(Some(card)).await;

        let (_, data, term) = client.command("SCD GETINFO version").await;
        assert_eq!(term, "OK");
        assert_eq!(data, b"2.4.0");

        let (_, data, term) = client.command("SCD GETINFO reader_list").await;
        assert_eq!(term, "OK");
        assert_eq!(data, b"Yubico YubiKey OTP+FIDO+CCID 00 00\n");

        let (_, data, term) = client.command("SCD GETINFO app_list").await;
        assert_eq!(term, "OK");
        assert_eq!(data, b"openpgp\n");

        let (_, _, term) = client.command("SCD GETINFO unknown_item").await;
        assert!(term.starts_with(&err_prefix(GPG_ERR_INV_DATA)));

        let (_, _, term) = client.command("BYE").await;
        assert!(term.starts_with("OK"));
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn scd_learn_emits_full_card_metadata_and_keypairinfo_mode() {
        let (sig_key, sig_kg) = ed25519_key_info(KeyCrt::Sign);
        let (dec_key, dec_kg) = cv25519_key_info(KeyCrt::Decrypt);
        let card = MockScdCard::new(default_status(), vec![sig_key, dec_key]);
        let (mut client, handle) = spawn_server(Some(card)).await;

        let (status, data, term) = client.command("SCD LEARN --force").await;
        assert_eq!(term, "OK");
        assert_eq!(data, b"");
        assert!(status.contains(&"S SERIALNO D2760001240103040006123456780000".to_owned()));
        assert!(status.contains(&"S APPTYPE OPENPGP".to_owned()));
        assert!(status.contains(&format!("S KEY-FPR 1 {}", "33".repeat(20))));
        assert!(status.contains(&format!("S KEY-FPR 2 {}", "44".repeat(20))));
        // Slot 3 fingerprint is all-zero and must not be emitted.
        assert!(!status.iter().any(|l| l.starts_with("S KEY-FPR 3 ")));
        assert!(status.contains(&"S KEY-ATTR 1 22 ed25519".to_owned()));
        assert!(status.contains(&"S KEY-ATTR 2 18 cv25519".to_owned()));
        assert!(status.contains(&"S KEY-ATTR 3 1 rsa2048".to_owned()));
        assert!(status.contains(&format!("S KEYPAIRINFO {sig_kg} OPENPGP.1")));
        assert!(status.contains(&format!("S KEYPAIRINFO {dec_kg} OPENPGP.2")));
        assert!(status.contains(&"S CHV-STATUS +1 127 127 127 3 0 3".to_owned()));
        assert!(status.contains(&"S SIG-COUNTER 42".to_owned()));

        // --keypairinfo omits non-keypair status lines
        let (kp_status, _, term) = client.command("SCD LEARN --keypairinfo").await;
        assert_eq!(term, "OK");
        assert_eq!(
            kp_status,
            vec![
                "S SERIALNO D2760001240103040006123456780000".to_owned(),
                "S APPTYPE OPENPGP".to_owned(),
                format!("S KEYPAIRINFO {sig_kg} OPENPGP.1"),
                format!("S KEYPAIRINFO {dec_kg} OPENPGP.2"),
            ]
        );

        let (_, _, term) = client.command("BYE").await;
        assert!(term.starts_with("OK"));
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn scd_readkey_returns_canonical_sexps_for_rsa_ed25519_cv25519() {
        let (rsa_key, _) = rsa_key_info(KeyCrt::Sign);
        let (cv_key, _) = cv25519_key_info(KeyCrt::Decrypt);
        let (ed_key, _) = ed25519_key_info(KeyCrt::Auth);
        let card = MockScdCard::new(default_status(), vec![rsa_key, cv_key, ed_key]);
        let (mut client, handle) = spawn_server(Some(card)).await;

        // RSA (MSB 0xA5 gets leading 0x00 in STD MPI form)
        let (_, data, term) = client.command("SCD READKEY OPENPGP.1").await;
        assert_eq!(term, "OK");
        let parsed = Sexp::parse(&data).expect("valid canonical RSA S-expression");
        let mut expected_n = vec![0x00];
        expected_n.extend(std::iter::repeat_n(0xA5, 255));
        expected_n.push(0x01);
        assert_eq!(
            parsed,
            Sexp::List(vec![
                Sexp::Atom(b"public-key".to_vec()),
                Sexp::List(vec![
                    Sexp::Atom(b"rsa".to_vec()),
                    Sexp::List(vec![Sexp::Atom(b"n".to_vec()), Sexp::Atom(expected_n)]),
                    Sexp::List(vec![
                        Sexp::Atom(b"e".to_vec()),
                        Sexp::Atom(vec![0x01, 0x00, 0x01]),
                    ]),
                ]),
            ])
        );

        // Cv25519 with --advanced
        let (_, data, term) = client.command("SCD READKEY --advanced OPENPGP.2").await;
        assert_eq!(term, "OK");
        let parsed = Sexp::parse(&data).expect("valid canonical Cv25519 S-expression");
        let mut expected_cv_q = vec![0x40];
        expected_cv_q.extend_from_slice(&[0x55; 32]);
        assert_eq!(
            parsed,
            Sexp::List(vec![
                Sexp::Atom(b"public-key".to_vec()),
                Sexp::List(vec![
                    Sexp::Atom(b"ecc".to_vec()),
                    Sexp::List(vec![
                        Sexp::Atom(b"curve".to_vec()),
                        Sexp::Atom(b"Curve25519".to_vec()),
                    ]),
                    Sexp::List(vec![
                        Sexp::Atom(b"flags".to_vec()),
                        Sexp::Atom(b"djb-tweak".to_vec()),
                    ]),
                    Sexp::List(vec![Sexp::Atom(b"q".to_vec()), Sexp::Atom(expected_cv_q)]),
                ]),
            ])
        );

        // Ed25519
        let (_, data, term) = client.command("SCD READKEY OPENPGP.3").await;
        assert_eq!(term, "OK");
        let parsed = Sexp::parse(&data).expect("valid canonical Ed25519 S-expression");
        let mut expected_ed_q = vec![0x40];
        expected_ed_q.extend_from_slice(&[0x44; 32]);
        assert_eq!(
            parsed,
            Sexp::List(vec![
                Sexp::Atom(b"public-key".to_vec()),
                Sexp::List(vec![
                    Sexp::Atom(b"ecc".to_vec()),
                    Sexp::List(vec![
                        Sexp::Atom(b"curve".to_vec()),
                        Sexp::Atom(b"Ed25519".to_vec()),
                    ]),
                    Sexp::List(vec![
                        Sexp::Atom(b"flags".to_vec()),
                        Sexp::Atom(b"eddsa".to_vec()),
                    ]),
                    Sexp::List(vec![Sexp::Atom(b"q".to_vec()), Sexp::Atom(expected_ed_q)]),
                ]),
            ])
        );

        // Invalid keyref
        let (_, _, term) = client.command("SCD READKEY OPENPGP.9").await;
        assert!(term.starts_with(&err_prefix(GPG_ERR_INV_DATA)));

        let (_, _, term) = client.command("BYE").await;
        assert!(term.starts_with("OK"));
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn scd_readkey_returns_canonical_sexp_for_ecdsa_and_handles_empty_slot() {
        let (ecdsa_key, _) = ecdsa_p256_key_info(KeyCrt::Sign);
        let card = MockScdCard::new(default_status(), vec![ecdsa_key]);
        let (mut client, handle) = spawn_server(Some(card)).await;

        let (_, data, term) = client.command("SCD READKEY OPENPGP.1").await;
        assert_eq!(term, "OK");
        let parsed = Sexp::parse(&data).expect("valid canonical ECDSA S-expression");
        let mut expected_p256_q = vec![0x04];
        expected_p256_q.extend_from_slice(&[0x33; 64]);
        assert_eq!(
            parsed,
            Sexp::List(vec![
                Sexp::Atom(b"public-key".to_vec()),
                Sexp::List(vec![
                    Sexp::Atom(b"ecc".to_vec()),
                    Sexp::List(vec![
                        Sexp::Atom(b"curve".to_vec()),
                        Sexp::Atom(b"NIST P-256".to_vec()),
                    ]),
                    Sexp::List(vec![Sexp::Atom(b"q".to_vec()), Sexp::Atom(expected_p256_q)]),
                ]),
            ])
        );

        // Empty slot -> NO_DATA
        let (_, _, term) = client.command("SCD READKEY OPENPGP.2").await;
        assert!(term.starts_with(&err_prefix(GPG_ERR_NO_DATA)));

        let (_, _, term) = client.command("BYE").await;
        assert!(term.starts_with("OK"));
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn scd_getattr_supports_status_attributes_and_handles_missing() {
        let card = MockScdCard::new(default_status(), Vec::new());
        let (mut client, handle) = spawn_server(Some(card)).await;

        let (status, _, term) = client.command("SCD GETATTR KEY-FPR").await;
        assert_eq!(term, "OK");
        assert_eq!(
            status,
            vec![
                format!("S KEY-FPR 1 {}", "33".repeat(20)),
                format!("S KEY-FPR 2 {}", "44".repeat(20)),
            ]
        );

        let (status, _, term) = client.command("SCD GETATTR KEY-ATTR").await;
        assert_eq!(term, "OK");
        assert_eq!(
            status,
            vec![
                "S KEY-ATTR 1 22 ed25519",
                "S KEY-ATTR 2 18 cv25519",
                "S KEY-ATTR 3 1 rsa2048",
            ]
        );

        let (status, _, term) = client.command("SCD GETATTR CHV-STATUS").await;
        assert_eq!(term, "OK");
        assert_eq!(status, vec!["S CHV-STATUS +1 127 127 127 3 0 3"]);

        let (status, _, term) = client.command("SCD GETATTR SIG-COUNTER").await;
        assert_eq!(term, "OK");
        assert_eq!(status, vec!["S SIG-COUNTER 42"]);

        let (status, _, term) = client.command("SCD GETATTR EXTCAP").await;
        assert_eq!(term, "OK");
        assert_eq!(status.len(), 1);
        assert!(status[0].starts_with("S EXTCAP "));

        let (status, _, term) = client.command("SCD GETATTR APP-VERSION").await;
        assert_eq!(term, "OK");
        assert_eq!(status, vec!["S APP-VERSION 3.4"]);

        let (status, _, term) = client.command("SCD GETATTR MANUFACTURER").await;
        assert_eq!(term, "OK");
        assert_eq!(status, vec!["S MANUFACTURER 0006 Yubico"]);

        // Unavailable read-only attribute -> GPG_ERR_NO_DATA
        let (_, _, term) = client.command("SCD GETATTR DISP-NAME").await;
        assert!(term.starts_with(&err_prefix(GPG_ERR_NO_DATA)));

        // Unsupported attribute -> GPG_ERR_NOT_IMPLEMENTED
        let (_, _, term) = client.command("SCD GETATTR TOTALLY-UNKNOWN").await;
        assert!(term.starts_with(&err_prefix(GPG_ERR_NOT_IMPLEMENTED)));

        let (_, _, term) = client.command("BYE").await;
        assert!(term.starts_with("OK"));
        handle.await.unwrap();

        // Missing SIG-COUNTER -> GPG_ERR_NO_DATA
        let mut status_no_cnt = default_status();
        status_no_cnt.signature_count = None;
        let card2 = MockScdCard::new(status_no_cnt, Vec::new());
        let (mut client2, handle2) = spawn_server(Some(card2)).await;

        let (_, _, term) = client2.command("SCD GETATTR SIG-COUNTER").await;
        assert!(term.starts_with(&err_prefix(GPG_ERR_NO_DATA)));

        let (_, _, term) = client2.command("BYE").await;
        assert!(term.starts_with("OK"));
        handle2.await.unwrap();
    }

    #[tokio::test]
    async fn scd_rejects_mutating_commands_and_allows_nop_restart_bye() {
        let card = MockScdCard::new(default_status(), Vec::new());
        let (mut client, handle) = spawn_server(Some(card)).await;

        for cmd in ["SCD NOP", "SCD RESTART", "SCD BYE"] {
            let (_, _, term) = client.command(cmd).await;
            assert_eq!(term, "OK", "{cmd} should succeed and keep agent alive");
        }

        for cmd in [
            "SCD SETATTR DISP-NAME Foo",
            "SCD GENKEY 1",
            "SCD WRITEKEY OPENPGP.1",
            "SCD PASSWD 1",
            "SCD CHECKPIN D2760001240103040006123456780000",
            "SCD RESET",
        ] {
            let (_, _, term) = client.command(cmd).await;
            assert!(
                term.starts_with(&err_prefix(GPG_ERR_NOT_IMPLEMENTED)),
                "{cmd} should return GPG_ERR_NOT_IMPLEMENTED, got: {term}"
            );
        }

        let (_, _, term) = client.command("SCD BOGUSCMD").await;
        assert!(term.starts_with(&err_prefix(GPG_ERR_UNKNOWN_COMMAND)));

        let (_, _, term) = client.command("BYE").await;
        assert!(term.starts_with("OK"));
        handle.await.unwrap();
    }
}
