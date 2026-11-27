use std::fmt::Write as _;
use std::str::FromStr;

use keyroost_openpgp::{AlgorithmAttributes, Curve, EccKind, KeyCrt};
use keyroost_transport::TransportError;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tracing::{debug, trace, warn};

use crate::{
    assuan::{
        GPG_ERR_BAD_PIN, GPG_ERR_CANCELED, GPG_ERR_INV_DATA, GPG_ERR_NO_DATA, GPG_ERR_NO_SECKEY,
        GPG_ERR_NOT_IMPLEMENTED, GPG_ERR_SOURCE_GPGAGENT, GPG_ERR_UNKNOWN_COMMAND, MAX_LINE_LEN,
        gpg_err_make, hex_value, percent_decode, percent_decode_bytes,
    },
    card::CardOperationOutcome,
    idle::IdleTracker,
    pin_cache::PinCache,
    pinentry::PinentryEnv,
    protocol::gpg::{
        GpgCardBackend,
        cache::{GpgCachedKey, GpgKeyCache},
        keygrip::{Keygrip, compute_keygrip},
        sexp::{
            EncVal, Sexp, encode_decrypt_value, encode_ecdsa_sig, encode_eddsa_sig, encode_rsa_sig,
            parse_enc_val,
        },
    },
};

pub(crate) const GPG_OPENPGP_SLOTS: [KeyCrt; 3] = [KeyCrt::Sign, KeyCrt::Decrypt, KeyCrt::Auth];

/// Reported `gpg-agent` version for `GETINFO version` (`GnuPG` parses `major.minor.micro`).
const AGENT_VERSION: &str = "2.4.0";

/// Maximum encoded bytes per `D ` line (`"D "` + payload + `"\n"` <= `MAX_LINE_LEN`).
const MAX_DATA_LINE_PAYLOAD: usize = MAX_LINE_LEN - 4;

// RFC 8017 §9.2 DER-encoded DigestInfo prefixes (without the digest bytes).
const SHA1_DIGEST_INFO_PREFIX: &[u8] = &[
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
];
const RMD160_DIGEST_INFO_PREFIX: &[u8] = &[
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x24, 0x03, 0x02, 0x01, 0x05, 0x00, 0x04, 0x14,
];
const SHA224_DIGEST_INFO_PREFIX: &[u8] = &[
    0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05,
    0x00, 0x04, 0x1c,
];
const SHA256_DIGEST_INFO_PREFIX: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];
const SHA384_DIGEST_INFO_PREFIX: &[u8] = &[
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30,
];
const SHA512_DIGEST_INFO_PREFIX: &[u8] = &[
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GpgHashAlgo {
    Sha1,
    Rmd160,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl GpgHashAlgo {
    fn from_id(id: u32) -> Option<Self> {
        match id {
            2 => Some(Self::Sha1),
            3 => Some(Self::Rmd160),
            8 => Some(Self::Sha256),
            9 => Some(Self::Sha384),
            10 => Some(Self::Sha512),
            11 => Some(Self::Sha224),
            _ => None,
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "sha1" => Some(Self::Sha1),
            "rmd160" | "ripemd160" => Some(Self::Rmd160),
            "sha224" => Some(Self::Sha224),
            "sha256" => Some(Self::Sha256),
            "sha384" => Some(Self::Sha384),
            "sha512" => Some(Self::Sha512),
            _ => None,
        }
    }

    const fn digest_len(self) -> usize {
        match self {
            Self::Sha1 | Self::Rmd160 => 20,
            Self::Sha224 => 28,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    const fn digest_info_prefix(self) -> &'static [u8] {
        match self {
            Self::Sha1 => SHA1_DIGEST_INFO_PREFIX,
            Self::Rmd160 => RMD160_DIGEST_INFO_PREFIX,
            Self::Sha224 => SHA224_DIGEST_INFO_PREFIX,
            Self::Sha256 => SHA256_DIGEST_INFO_PREFIX,
            Self::Sha384 => SHA384_DIGEST_INFO_PREFIX,
            Self::Sha512 => SHA512_DIGEST_INFO_PREFIX,
        }
    }
}

#[derive(Default)]
struct ConnectionState {
    selected_key: Option<Keygrip>,
    hash: Option<(GpgHashAlgo, Vec<u8>)>,
    key_desc: Option<String>,
    pinentry_env: PinentryEnv,
}

impl ConnectionState {
    fn reset(&mut self) {
        self.selected_key = None;
        self.hash = None;
        self.key_desc = None;
    }

    fn pinentry_env_opt(&self) -> Option<&PinentryEnv> {
        let env = &self.pinentry_env;
        if env.ttyname.is_some()
            || env.ttytype.is_some()
            || env.display.is_some()
            || env.xauthority.is_some()
            || env.lc_ctype.is_some()
            || env.lc_messages.is_some()
        {
            Some(env)
        } else {
            None
        }
    }
}

struct ServerContext<C> {
    card: Option<C>,
    idle_tracker: IdleTracker,
    pin_cache: Option<PinCache>,
    key_cache: GpgKeyCache,
    socket_name: Option<String>,
}

enum LineRead {
    Eof,
    TooLong,
    Line(Vec<u8>),
}

enum InquireOutcome {
    Eof,
    Canceled,
    Data(Vec<u8>),
    Error(u32, &'static str),
}

pub(crate) async fn serve_connection<S, C>(
    stream: S,
    card: Option<C>,
    idle_tracker: IdleTracker,
    pin_cache: Option<PinCache>,
    key_cache: GpgKeyCache,
    socket_name: Option<String>,
) -> Result<(), std::io::Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
    C: GpgCardBackend,
{
    let (read_half, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);

    let ctx = ServerContext {
        card,
        idle_tracker,
        pin_cache,
        key_cache,
        socket_name,
    };
    let mut state = ConnectionState::default();

    write_line(&mut writer, "OK Pleased to meet you").await?;

    loop {
        let raw_line = match read_assuan_line(&mut reader).await? {
            LineRead::Eof => break,
            LineRead::TooLong => {
                ctx.idle_tracker.record_activity();
                send_err(&mut writer, GPG_ERR_INV_DATA, "Line too long").await?;
                continue;
            }
            LineRead::Line(bytes) => bytes,
        };

        let Ok(line) = std::str::from_utf8(&raw_line) else {
            ctx.idle_tracker.record_activity();
            send_err(&mut writer, GPG_ERR_INV_DATA, "Invalid UTF-8 in command").await?;
            continue;
        };

        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        ctx.idle_tracker.record_activity();

        let (cmd_raw, args) = split_command(trimmed);
        let cmd = cmd_raw.to_ascii_uppercase();
        trace!(command = %cmd, "received GPG Assuan command");

        let keep_open = handle_command(&cmd, args, &ctx, &mut state, &mut reader, &mut writer).await?;
        ctx.idle_tracker.record_activity();
        if !keep_open {
            break;
        }
    }

    Ok(())
}

async fn handle_command<R, W, C>(
    cmd: &str,
    args: &str,
    ctx: &ServerContext<C>,
    state: &mut ConnectionState,
    reader: &mut BufReader<R>,
    writer: &mut W,
) -> Result<bool, std::io::Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    C: GpgCardBackend,
{
    match cmd {
        "NOP" => {
            write_line(writer, "OK").await?;
        }
        "RESET" => {
            state.reset();
            write_line(writer, "OK").await?;
        }
        "BYE" => {
            write_line(writer, "OK closing connection").await?;
            return Ok(false);
        }
        "OPTION" => {
            handle_option(args, state, writer).await?;
        }
        "GETINFO" => {
            handle_getinfo(args, ctx, writer).await?;
        }
        "SETKEYDESC" => {
            handle_setkeydesc(args, state, writer).await?;
        }
        "CLEAR_PASSPHRASE" | "RELOADAGENT" => {
            debug!(command = %cmd, "clearing GPG agent caches and disconnecting card");
            if let Some(card) = &ctx.card {
                card.disconnect().await;
            }
            if let Some(pin_cache) = &ctx.pin_cache {
                pin_cache.clear();
            }
            ctx.key_cache.clear();
            write_line(writer, "OK").await?;
        }
        "HAVEKEY" => {
            handle_havekey(args, ctx, writer).await?;
        }
        "KEYINFO" => {
            handle_keyinfo(args, ctx, writer).await?;
        }
        "SIGKEY" | "SETKEY" => {
            handle_setkey(args, state, writer).await?;
        }
        "SETHASH" => {
            handle_sethash(args, state, writer).await?;
        }
        "PKSIGN" => {
            return handle_pksign(args, ctx, state, reader, writer).await;
        }
        "PKDECRYPT" => {
            return handle_pkdecrypt(ctx, state, reader, writer).await;
        }
        _ => {
            send_err(writer, GPG_ERR_UNKNOWN_COMMAND, "Unknown command").await?;
        }
    }
    Ok(true)
}

async fn handle_option<W: AsyncWrite + Unpin>(
    args: &str,
    state: &mut ConnectionState,
    writer: &mut W,
) -> Result<(), std::io::Error> {
    let args = args.trim();
    if args.is_empty() {
        send_err(writer, GPG_ERR_INV_DATA, "Missing option name").await?;
        return Ok(());
    }

    let (name, value) = if let Some((n, v)) = args.split_once('=') {
        (n.trim(), v.trim())
    } else if let Some((n, v)) = args.split_once(char::is_whitespace) {
        (n.trim(), v.trim())
    } else {
        (args, "")
    };

    let opt_val = (!value.is_empty()).then(|| value.to_owned());
    match name.to_ascii_lowercase().as_str() {
        "ttyname" => state.pinentry_env.ttyname = opt_val,
        "ttytype" => state.pinentry_env.ttytype = opt_val,
        "display" => state.pinentry_env.display = opt_val,
        "xauthority" => state.pinentry_env.xauthority = opt_val,
        "lc-ctype" => state.pinentry_env.lc_ctype = opt_val,
        "lc-messages" => state.pinentry_env.lc_messages = opt_val,
        _ => {
            trace!(option = %name, "ignoring unrecognized Assuan OPTION");
        }
    }

    write_line(writer, "OK").await
}

async fn handle_getinfo<W: AsyncWrite + Unpin, C>(
    args: &str,
    ctx: &ServerContext<C>,
    writer: &mut W,
) -> Result<(), std::io::Error> {
    let mut parts = args.split_whitespace();
    let Some(subcmd) = parts.next() else {
        send_err(writer, GPG_ERR_INV_DATA, "Missing GETINFO subcommand").await?;
        return Ok(());
    };

    match subcmd.to_ascii_lowercase().as_str() {
        "version" => {
            send_data_bytes(writer, AGENT_VERSION.as_bytes()).await?;
            write_line(writer, "OK").await
        }
        "pid" => {
            let pid = std::process::id().to_string();
            send_data_bytes(writer, pid.as_bytes()).await?;
            write_line(writer, "OK").await
        }
        "socket_name" => {
            if let Some(socket_name) = &ctx.socket_name {
                send_data_bytes(writer, socket_name.as_bytes()).await?;
                write_line(writer, "OK").await
            } else {
                send_err(writer, GPG_ERR_NO_DATA, "No socket name").await
            }
        }
        "cmd_has_option" => {
            let cmd = parts.next().map(str::to_ascii_uppercase);
            let opt = parts.next().map(str::to_ascii_lowercase);
            let supported = matches!(
                (cmd.as_deref(), opt.as_deref()),
                (Some("KEYINFO"), Some("list" | "data"))
                    | (Some("HAVEKEY"), Some("list"))
                    | (Some("PKSIGN"), Some("hash"))
            );
            if supported {
                write_line(writer, "OK").await
            } else {
                send_err(writer, GPG_ERR_NOT_IMPLEMENTED, "Option not supported").await
            }
        }
        _ => send_err(writer, GPG_ERR_INV_DATA, "Unknown GETINFO subcommand").await,
    }
}

async fn handle_setkeydesc<W: AsyncWrite + Unpin>(
    args: &str,
    state: &mut ConnectionState,
    writer: &mut W,
) -> Result<(), std::io::Error> {
    let encoded = args.trim();
    if encoded.is_empty() {
        state.key_desc = None;
        return write_line(writer, "OK").await;
    }

    // In gpg-agent SETKEYDESC, '+' encodes a space before %XX decoding.
    let plus_decoded = encoded.replace('+', " ");
    let mut bytes = Vec::with_capacity(plus_decoded.len());
    if let Err(msg) = percent_decode(&plus_decoded, &mut bytes) {
        return send_err(writer, GPG_ERR_INV_DATA, msg).await;
    }

    state.key_desc = Some(String::from_utf8_lossy(&bytes).into_owned());
    write_line(writer, "OK").await
}

async fn handle_havekey<W: AsyncWrite + Unpin, C: GpgCardBackend>(
    args: &str,
    ctx: &ServerContext<C>,
    writer: &mut W,
) -> Result<(), std::io::Error> {
    let mut list_mode = false;
    let mut list_limit: Option<usize> = None;
    let mut requested = Vec::new();

    for token in args.split_whitespace() {
        if token == "--list" {
            list_mode = true;
        } else if let Some(limit_str) = token.strip_prefix("--list=") {
            let Ok(limit) = limit_str.parse::<usize>() else {
                return send_err(writer, GPG_ERR_INV_DATA, "Invalid --list limit").await;
            };
            list_mode = true;
            list_limit = Some(limit);
        } else if token.starts_with("--") {
            // Ignore unknown options gracefully.
        } else {
            let Ok(kg) = Keygrip::from_str(token) else {
                return send_err(writer, GPG_ERR_INV_DATA, "Invalid keygrip").await;
            };
            requested.push(kg);
        }
    }

    if list_mode {
        let keys = match scan_keys(ctx).await {
            Ok(keys) => keys,
            Err(err) => {
                let (code, msg) = map_card_error(&err);
                return send_err(writer, code, &msg).await;
            }
        };
        let count = list_limit.map_or(keys.len(), |n| n.min(keys.len()));
        let mut raw = Vec::with_capacity(count * 20);
        for (kg, _) in keys.iter().take(count) {
            raw.extend_from_slice(kg.as_bytes());
        }
        if !raw.is_empty() {
            send_data_bytes(writer, &raw).await?;
        }
        return write_line(writer, "OK").await;
    }

    if requested.is_empty() {
        return send_err(writer, GPG_ERR_INV_DATA, "Missing keygrip").await;
    }

    if requested.iter().any(|kg| ctx.key_cache.get(kg).is_some()) {
        return write_line(writer, "OK").await;
    }

    let keys = match scan_keys(ctx).await {
        Ok(keys) => keys,
        Err(err) => {
            let (code, msg) = map_card_error(&err);
            return send_err(writer, code, &msg).await;
        }
    };

    if requested
        .iter()
        .any(|req| keys.iter().any(|(kg, _)| kg == req))
    {
        write_line(writer, "OK").await
    } else {
        send_err(writer, GPG_ERR_NO_SECKEY, "No secret key").await
    }
}

async fn handle_keyinfo<W: AsyncWrite + Unpin, C: GpgCardBackend>(
    args: &str,
    ctx: &ServerContext<C>,
    writer: &mut W,
) -> Result<(), std::io::Error> {
    let mut list_mode = false;
    let mut use_data = false;
    let mut target: Option<Keygrip> = None;

    for token in args.split_whitespace() {
        match token {
            "--list" => list_mode = true,
            "--data" => use_data = true,
            "--ssh-fpr" | "--with-ssh" | "--ssh-list" => {}
            t if t.starts_with("--") => {}
            other => {
                let Ok(kg) = Keygrip::from_str(other) else {
                    return send_err(writer, GPG_ERR_INV_DATA, "Invalid keygrip").await;
                };
                target = Some(kg);
            }
        }
    }

    if list_mode {
        let keys = match scan_keys(ctx).await {
            Ok(keys) => keys,
            Err(err) => {
                let (code, msg) = map_card_error(&err);
                return send_err(writer, code, &msg).await;
            }
        };
        for (kg, cached) in &keys {
            emit_keyinfo_line(writer, *kg, cached, use_data).await?;
        }
        return write_line(writer, "OK").await;
    }

    let Some(kg) = target else {
        return send_err(writer, GPG_ERR_INV_DATA, "Missing keygrip or --list").await;
    };

    if let Some(cached) = ctx.key_cache.get(&kg) {
        emit_keyinfo_line(writer, kg, &cached, use_data).await?;
        return write_line(writer, "OK").await;
    }

    let keys = match scan_keys(ctx).await {
        Ok(keys) => keys,
        Err(err) => {
            let (code, msg) = map_card_error(&err);
            return send_err(writer, code, &msg).await;
        }
    };

    if let Some((_, cached)) = keys.into_iter().find(|(k, _)| *k == kg) {
        emit_keyinfo_line(writer, kg, &cached, use_data).await?;
        write_line(writer, "OK").await
    } else {
        send_err(writer, GPG_ERR_NO_SECKEY, "No secret key").await
    }
}

async fn emit_keyinfo_line<W: AsyncWrite + Unpin>(
    writer: &mut W,
    keygrip: Keygrip,
    cached: &GpgCachedKey,
    use_data: bool,
) -> Result<(), std::io::Error> {
    let aid_hex = if cached.aid.is_empty() {
        "-".to_owned()
    } else {
        let mut s = String::with_capacity(cached.aid.len() * 2);
        for b in &cached.aid {
            let _ = write!(s, "{b:02X}");
        }
        s
    };

    let idstr = match cached.slot {
        KeyCrt::Sign => "OPENPGP.1",
        KeyCrt::Decrypt => "OPENPGP.2",
        KeyCrt::Auth => "OPENPGP.3",
    };

    let prefix = if use_data { "D" } else { "S" };
    let line = format!("{prefix} KEYINFO {keygrip} T {aid_hex} {idstr} - - - - -");
    write_line(writer, &line).await
}

async fn handle_setkey<W: AsyncWrite + Unpin>(
    args: &str,
    state: &mut ConnectionState,
    writer: &mut W,
) -> Result<(), std::io::Error> {
    let Some(token) = args.split_whitespace().next() else {
        return send_err(writer, GPG_ERR_INV_DATA, "Missing keygrip").await;
    };
    let Ok(kg) = Keygrip::from_str(token) else {
        return send_err(writer, GPG_ERR_INV_DATA, "Invalid keygrip").await;
    };
    state.selected_key = Some(kg);
    write_line(writer, "OK").await
}

async fn handle_sethash<W: AsyncWrite + Unpin>(
    args: &str,
    state: &mut ConnectionState,
    writer: &mut W,
) -> Result<(), std::io::Error> {
    let mut parts = args.split_whitespace();
    let Some(algo_tok) = parts.next() else {
        return send_err(writer, GPG_ERR_INV_DATA, "Missing hash algorithm").await;
    };
    let Some(hex_tok) = parts.next() else {
        return send_err(writer, GPG_ERR_INV_DATA, "Missing hash digest").await;
    };

    let algo = if let Some(name) = algo_tok.strip_prefix("--hash=") {
        GpgHashAlgo::from_name(name)
    } else if let Ok(id) = algo_tok.parse::<u32>() {
        GpgHashAlgo::from_id(id)
    } else {
        None
    };

    let Some(algo) = algo else {
        return send_err(writer, GPG_ERR_INV_DATA, "Unsupported hash algorithm").await;
    };

    let Ok(digest) = decode_hex(hex_tok) else {
        return send_err(writer, GPG_ERR_INV_DATA, "Invalid hex digest").await;
    };

    if digest.len() != algo.digest_len() {
        return send_err(writer, GPG_ERR_INV_DATA, "Digest length mismatch").await;
    }

    state.hash = Some((algo, digest));
    write_line(writer, "OK").await
}

async fn handle_pksign<R, W, C>(
    args: &str,
    ctx: &ServerContext<C>,
    state: &mut ConnectionState,
    reader: &mut BufReader<R>,
    writer: &mut W,
) -> Result<bool, std::io::Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    C: GpgCardBackend,
{
    let Some(keygrip) = state.selected_key else {
        send_err(writer, GPG_ERR_NO_SECKEY, "No key selected").await?;
        return Ok(true);
    };

    let mut arg_hash: Option<GpgHashAlgo> = None;
    for token in args.split_whitespace() {
        if let Some(name) = token.strip_prefix("--hash=") {
            let Some(algo) = GpgHashAlgo::from_name(name) else {
                send_err(writer, GPG_ERR_INV_DATA, "Unsupported hash algorithm").await?;
                return Ok(true);
            };
            arg_hash = Some(algo);
        }
    }

    let (hash_algo, digest) = if let Some((algo, digest)) = state.hash.take() {
        (Some(algo), digest)
    } else {
        match inquire_data(reader, writer, "DATA").await? {
            InquireOutcome::Eof => return Ok(false),
            InquireOutcome::Canceled => {
                send_err(writer, GPG_ERR_CANCELED, "Operation cancelled").await?;
                return Ok(true);
            }
            InquireOutcome::Error(code, msg) => {
                send_err(writer, code, msg).await?;
                return Ok(true);
            }
            InquireOutcome::Data(data) => (arg_hash, data),
        }
    };

    let Some(card) = &ctx.card else {
        send_err(writer, GPG_ERR_NO_SECKEY, "No secret key").await?;
        return Ok(true);
    };

    let (cached, from_cache) = match lookup_or_scan_key(ctx, keygrip).await {
        Ok(Some(found)) => found,
        Ok(None) => {
            send_err(writer, GPG_ERR_NO_SECKEY, "No secret key").await?;
            return Ok(true);
        }
        Err(err) => {
            let (code, msg) = map_card_error(&err);
            send_err(writer, code, &msg).await?;
            return Ok(true);
        }
    };

    let prompt_desc = state.key_desc.as_deref();
    let prompt_env = state.pinentry_env_opt();

    let (attrs, outcome) = match execute_sign(
        card,
        ctx,
        keygrip,
        &cached,
        from_cache,
        hash_algo,
        &digest,
        prompt_desc,
        prompt_env,
    )
    .await
    {
        Ok(res) => res,
        Err((code, msg)) => {
            send_err(writer, code, &msg).await?;
            return Ok(true);
        }
    };

    match outcome {
        CardOperationOutcome::Completed(raw_sig) => match encode_gpg_signature(attrs, &raw_sig) {
            Ok(sexp_bytes) => {
                send_data_bytes(writer, &sexp_bytes).await?;
                write_line(writer, "OK").await?;
            }
            Err(msg) => {
                send_err(writer, GPG_ERR_INV_DATA, msg).await?;
            }
        },
        CardOperationOutcome::UserCancelled => {
            send_err(writer, GPG_ERR_CANCELED, "Operation cancelled").await?;
        }
        CardOperationOutcome::NotFound => {
            send_err(writer, GPG_ERR_NO_SECKEY, "No secret key").await?;
        }
    }

    Ok(true)
}

#[expect(clippy::too_many_arguments)]
async fn execute_sign<C: GpgCardBackend>(
    card: &C,
    ctx: &ServerContext<C>,
    keygrip: Keygrip,
    cached: &GpgCachedKey,
    from_cache: bool,
    hash_algo: Option<GpgHashAlgo>,
    digest: &[u8],
    prompt_desc: Option<&str>,
    prompt_env: Option<&PinentryEnv>,
) -> Result<(AlgorithmAttributes, CardOperationOutcome<Vec<u8>>), (u32, String)> {
    let prepared = prepare_sign_input(cached.attrs, hash_algo, digest)?;
    let expected_serial = if from_cache { cached.serial } else { None };

    let first_attempt = card
        .sign_raw(cached.slot, expected_serial, &prepared, prompt_desc, prompt_env)
        .await;

    let should_rescan = from_cache
        && (matches!(&first_attempt, Ok(CardOperationOutcome::NotFound))
            || first_attempt
                .as_ref()
                .err()
                .is_some_and(crate::Error::is_transport_error));

    if !should_rescan {
        let outcome = first_attempt.map_err(|err| map_card_error(&err))?;
        return Ok((cached.attrs, outcome));
    }

    debug!(slot = ?cached.slot, "cached GPG key sign reported stale card/slot; re-scanning");
    let keys = scan_keys(ctx).await.map_err(|err| map_card_error(&err))?;
    let Some((_, fresh)) = keys.into_iter().find(|(kg, _)| *kg == keygrip) else {
        return Ok((cached.attrs, CardOperationOutcome::NotFound));
    };

    let fresh_prepared = prepare_sign_input(fresh.attrs, hash_algo, digest)?;
    let outcome = card
        .sign_raw(fresh.slot, None, &fresh_prepared, prompt_desc, prompt_env)
        .await
        .map_err(|err| map_card_error(&err))?;
    Ok((fresh.attrs, outcome))
}

fn prepare_sign_input(
    attrs: AlgorithmAttributes,
    hash_algo: Option<GpgHashAlgo>,
    digest: &[u8],
) -> Result<Vec<u8>, (u32, String)> {
    match attrs {
        AlgorithmAttributes::Rsa(_) => {
            let Some(algo) = hash_algo else {
                return Err((
                    GPG_ERR_INV_DATA,
                    "Missing hash algorithm for RSA signing".to_owned(),
                ));
            };
            let prefix = algo.digest_info_prefix();
            let mut out = Vec::with_capacity(prefix.len() + digest.len());
            out.extend_from_slice(prefix);
            out.extend_from_slice(digest);
            Ok(out)
        }
        AlgorithmAttributes::Ecc {
            kind: EccKind::Ecdsa,
            ..
        }
        | AlgorithmAttributes::Ecc {
            kind: EccKind::EdDsa,
            curve: Curve::Ed25519,
            ..
        } => Ok(digest.to_vec()),
        AlgorithmAttributes::Ecc { .. } => Err((
            GPG_ERR_INV_DATA,
            "Key algorithm does not support signing".to_owned(),
        )),
    }
}

fn encode_gpg_signature(attrs: AlgorithmAttributes, raw_sig: &[u8]) -> Result<Vec<u8>, &'static str> {
    match attrs {
        AlgorithmAttributes::Rsa(_) => Ok(encode_rsa_sig(raw_sig)),
        AlgorithmAttributes::Ecc {
            kind: EccKind::Ecdsa,
            ..
        } => {
            if raw_sig.len() < 2 || !raw_sig.len().is_multiple_of(2) {
                return Err("Invalid ECDSA signature length from card");
            }
            let (r, s) = raw_sig.split_at(raw_sig.len() / 2);
            Ok(encode_ecdsa_sig(r, s))
        }
        AlgorithmAttributes::Ecc {
            kind: EccKind::EdDsa,
            curve: Curve::Ed25519,
            ..
        } => {
            if raw_sig.len() != 64 {
                return Err("Invalid Ed25519 signature length from card");
            }
            let (r, s) = raw_sig.split_at(32);
            Ok(encode_eddsa_sig(r, s))
        }
        AlgorithmAttributes::Ecc { .. } => Err("Unsupported signature algorithm"),
    }
}

async fn handle_pkdecrypt<R, W, C>(
    ctx: &ServerContext<C>,
    state: &mut ConnectionState,
    reader: &mut BufReader<R>,
    writer: &mut W,
) -> Result<bool, std::io::Error>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    C: GpgCardBackend,
{
    let Some(keygrip) = state.selected_key else {
        send_err(writer, GPG_ERR_NO_SECKEY, "No key selected").await?;
        return Ok(true);
    };

    let raw_ciphertext = match inquire_data(reader, writer, "CIPHERTEXT").await? {
        InquireOutcome::Eof => return Ok(false),
        InquireOutcome::Canceled => {
            send_err(writer, GPG_ERR_CANCELED, "Operation cancelled").await?;
            return Ok(true);
        }
        InquireOutcome::Error(code, msg) => {
            send_err(writer, code, msg).await?;
            return Ok(true);
        }
        InquireOutcome::Data(data) => data,
    };

    let sexp = match Sexp::parse(&raw_ciphertext) {
        Ok(sexp) => sexp,
        Err(err) => {
            send_err(writer, GPG_ERR_INV_DATA, &err.to_string()).await?;
            return Ok(true);
        }
    };

    let enc_val = match parse_enc_val(&sexp) {
        Ok(val) => val,
        Err(err) => {
            send_err(writer, GPG_ERR_INV_DATA, &err.to_string()).await?;
            return Ok(true);
        }
    };

    let Some(card) = &ctx.card else {
        send_err(writer, GPG_ERR_NO_SECKEY, "No secret key").await?;
        return Ok(true);
    };

    let (cached, from_cache) = match lookup_or_scan_key(ctx, keygrip).await {
        Ok(Some(found)) => found,
        Ok(None) => {
            send_err(writer, GPG_ERR_NO_SECKEY, "No secret key").await?;
            return Ok(true);
        }
        Err(err) => {
            let (code, msg) = map_card_error(&err);
            send_err(writer, code, &msg).await?;
            return Ok(true);
        }
    };

    let prompt_desc = state.key_desc.as_deref();
    let prompt_env = state.pinentry_env_opt();

    let (attrs, outcome) = match execute_decrypt(
        card,
        ctx,
        keygrip,
        &cached,
        from_cache,
        &enc_val,
        prompt_desc,
        prompt_env,
    )
    .await
    {
        Ok(res) => res,
        Err((code, msg)) => {
            send_err(writer, code, &msg).await?;
            return Ok(true);
        }
    };

    match outcome {
        CardOperationOutcome::Completed(mut plaintext) => {
            if matches!(enc_val, EncVal::Ecdh { .. })
                && matches!(
                    attrs,
                    AlgorithmAttributes::Ecc {
                        curve: Curve::X25519,
                        ..
                    }
                )
                && plaintext.len() == 32
            {
                let mut prefixed = Vec::with_capacity(33);
                prefixed.push(0x40);
                prefixed.extend_from_slice(&plaintext);
                plaintext = prefixed;
            }
            write_line(writer, "S PADDING 0").await?;
            let encoded = encode_decrypt_value(&plaintext);
            send_data_bytes(writer, &encoded).await?;
            write_line(writer, "OK").await?;
        }
        CardOperationOutcome::UserCancelled => {
            send_err(writer, GPG_ERR_CANCELED, "Operation cancelled").await?;
        }
        CardOperationOutcome::NotFound => {
            send_err(writer, GPG_ERR_NO_SECKEY, "No secret key").await?;
        }
    }

    Ok(true)
}

#[expect(clippy::too_many_arguments)]
async fn execute_decrypt<C: GpgCardBackend>(
    card: &C,
    ctx: &ServerContext<C>,
    keygrip: Keygrip,
    cached: &GpgCachedKey,
    from_cache: bool,
    enc_val: &EncVal,
    prompt_desc: Option<&str>,
    prompt_env: Option<&PinentryEnv>,
) -> Result<(AlgorithmAttributes, CardOperationOutcome<Vec<u8>>), (u32, String)> {
    let expected_serial = if from_cache { cached.serial } else { None };
    let first_attempt =
        run_decrypt_op(card, cached.attrs, expected_serial, enc_val, prompt_desc, prompt_env)
            .await;

    let should_rescan = from_cache
        && (matches!(&first_attempt, Ok(CardOperationOutcome::NotFound))
            || first_attempt
                .as_ref()
                .err()
                .is_some_and(|err| matches!(err, DecryptOpError::Card(e) if e.is_transport_error())));

    if !should_rescan {
        let outcome = first_attempt.map_err(DecryptOpError::into_assuan)?;
        return Ok((cached.attrs, outcome));
    }

    debug!(slot = ?cached.slot, "cached GPG key decrypt reported stale card/slot; re-scanning");
    let keys = scan_keys(ctx).await.map_err(|err| map_card_error(&err))?;
    let Some((_, fresh)) = keys.into_iter().find(|(kg, _)| *kg == keygrip) else {
        return Ok((cached.attrs, CardOperationOutcome::NotFound));
    };

    let outcome = run_decrypt_op(card, fresh.attrs, None, enc_val, prompt_desc, prompt_env)
        .await
        .map_err(DecryptOpError::into_assuan)?;
    Ok((fresh.attrs, outcome))
}

enum DecryptOpError {
    InvalidData(&'static str),
    Card(crate::Error),
}

impl DecryptOpError {
    fn into_assuan(self) -> (u32, String) {
        match self {
            Self::InvalidData(msg) => (GPG_ERR_INV_DATA, msg.to_owned()),
            Self::Card(err) => map_card_error(&err),
        }
    }
}

async fn run_decrypt_op<C: GpgCardBackend>(
    card: &C,
    attrs: AlgorithmAttributes,
    expected_serial: Option<u128>,
    enc_val: &EncVal,
    prompt_desc: Option<&str>,
    prompt_env: Option<&PinentryEnv>,
) -> Result<CardOperationOutcome<Vec<u8>>, DecryptOpError> {
    match (enc_val, attrs) {
        (EncVal::Rsa { a }, AlgorithmAttributes::Rsa(_)) => card
            .decrypt_rsa(expected_serial, a, prompt_desc, prompt_env)
            .await
            .map_err(DecryptOpError::Card),
        (
            EncVal::Ecdh { e },
            AlgorithmAttributes::Ecc {
                kind: EccKind::Ecdh,
                curve,
                ..
            },
        ) => {
            // GnuPG encodes Curve25519 ephemeral points with a leading 0x40 prefix
            // (33 bytes); OpenPGP Card PSO:DECIPHER expects the raw 32-byte coordinate.
            let point = if curve == Curve::X25519 && e.len() == 33 && e[0] == 0x40 {
                &e[1..]
            } else {
                e.as_slice()
            };
            card.decrypt_ecdh(expected_serial, point, prompt_desc, prompt_env)
                .await
                .map_err(DecryptOpError::Card)
        }
        _ => Err(DecryptOpError::InvalidData(
            "Ciphertext algorithm does not match selected key",
        )),
    }
}

async fn lookup_or_scan_key<C: GpgCardBackend>(
    ctx: &ServerContext<C>,
    keygrip: Keygrip,
) -> Result<Option<(GpgCachedKey, bool)>, crate::Error> {
    if let Some(cached) = ctx.key_cache.get(&keygrip) {
        return Ok(Some((cached, true)));
    }

    let keys = scan_keys(ctx).await?;
    Ok(keys
        .into_iter()
        .find(|(kg, _)| *kg == keygrip)
        .map(|(_, cached)| (cached, false)))
}

async fn scan_keys<C: GpgCardBackend>(
    ctx: &ServerContext<C>,
) -> Result<Vec<(Keygrip, GpgCachedKey)>, crate::Error> {
    let Some(card) = &ctx.card else {
        ctx.key_cache.clear();
        return Ok(Vec::new());
    };

    let raw_keys = card.list_keys(&GPG_OPENPGP_SLOTS).await?;
    let mut entries = Vec::with_capacity(raw_keys.len());
    for info in raw_keys {
        match compute_keygrip(info.attrs, &info.public_key) {
            Ok(kg) => {
                entries.push((
                    kg,
                    GpgCachedKey {
                        slot: info.slot,
                        attrs: info.attrs,
                        aid: info.aid,
                        serial: info.full_serial,
                    },
                ));
            }
            Err(err) => {
                warn!(slot = ?info.slot, "skipping OpenPGP slot with invalid keygrip: {err}");
            }
        }
    }

    ctx.key_cache.replace(entries.clone());
    Ok(entries)
}

async fn inquire_data<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut BufReader<R>,
    writer: &mut W,
    keyword: &str,
) -> Result<InquireOutcome, std::io::Error> {
    write_line(writer, &format!("INQUIRE {keyword}")).await?;

    let mut collected = Vec::new();
    loop {
        let raw_line = match read_assuan_line(reader).await? {
            LineRead::Eof => return Ok(InquireOutcome::Eof),
            LineRead::TooLong => {
                return Ok(InquireOutcome::Error(GPG_ERR_INV_DATA, "Line too long"));
            }
            LineRead::Line(bytes) => bytes,
        };

        if raw_line.is_empty() || raw_line.starts_with(b"#") {
            continue;
        }

        if raw_line.eq_ignore_ascii_case(b"END") {
            return Ok(InquireOutcome::Data(collected));
        }

        if raw_line.eq_ignore_ascii_case(b"CAN") {
            return Ok(InquireOutcome::Canceled);
        }

        if let Some(payload) = raw_line
            .strip_prefix(b"D ")
            .or_else(|| raw_line.strip_prefix(b"d "))
        {
            if let Err(msg) = percent_decode_bytes(payload, &mut collected) {
                return Ok(InquireOutcome::Error(GPG_ERR_INV_DATA, msg));
            }
        } else {
            return Ok(InquireOutcome::Error(
                GPG_ERR_INV_DATA,
                "Unexpected line during INQUIRE",
            ));
        }
    }
}

async fn read_assuan_line<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
) -> Result<LineRead, std::io::Error> {
    let mut buf = Vec::new();
    let max_read = (MAX_LINE_LEN + 1) as u64;
    let n = reader.take(max_read).read_until(b'\n', &mut buf).await?;
    if n == 0 {
        return Ok(LineRead::Eof);
    }

    let ended_with_lf = buf.last() == Some(&b'\n');
    if buf.len() > MAX_LINE_LEN || (buf.len() == MAX_LINE_LEN && !ended_with_lf) {
        if !ended_with_lf {
            drain_until_lf(reader).await?;
        }
        return Ok(LineRead::TooLong);
    }

    if buf.last() == Some(&b'\n') {
        buf.pop();
    }
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }

    Ok(LineRead::Line(buf))
}

async fn drain_until_lf<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
) -> Result<(), std::io::Error> {
    let mut discard = Vec::new();
    loop {
        discard.clear();
        let n = reader.take(1024).read_until(b'\n', &mut discard).await?;
        if n == 0 || discard.last() == Some(&b'\n') {
            return Ok(());
        }
    }
}

fn split_command(line: &str) -> (&str, &str) {
    match line.find([' ', '\t']) {
        Some(idx) => (&line[..idx], line[idx..].trim_start_matches([' ', '\t'])),
        None => (line, ""),
    }
}

fn decode_hex(s: &str) -> Result<Vec<u8>, ()> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(());
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let (pairs, _) = bytes.as_chunks::<2>();
    for pair in pairs {
        let hi = hex_value(pair[0]).ok_or(())?;
        let lo = hex_value(pair[1]).ok_or(())?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

async fn write_line<W: AsyncWrite + Unpin>(
    writer: &mut W,
    line: &str,
) -> Result<(), std::io::Error> {
    writer.write_all(line.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await
}

async fn send_err<W: AsyncWrite + Unpin>(
    writer: &mut W,
    code: u32,
    description: &str,
) -> Result<(), std::io::Error> {
    let full_code = gpg_err_make(GPG_ERR_SOURCE_GPGAGENT, code);
    let prefix = format!("ERR {full_code} ");
    let max_desc = MAX_LINE_LEN.saturating_sub(prefix.len() + 1);
    let mut clean = String::with_capacity(description.len().min(max_desc));
    for ch in description.chars() {
        let mapped = if ch == '\r' || ch == '\n' { ' ' } else { ch };
        if clean.len() + mapped.len_utf8() > max_desc {
            break;
        }
        clean.push(mapped);
    }
    write_line(writer, &format!("{prefix}{clean}")).await
}

async fn send_data_bytes<W: AsyncWrite + Unpin>(
    writer: &mut W,
    data: &[u8],
) -> Result<(), std::io::Error> {
    let mut line = String::with_capacity(MAX_DATA_LINE_PAYLOAD + 3);
    line.push_str("D ");

    for &b in data {
        let needs_escape = b == b'%' || !(0x20..0x7F).contains(&b);
        let needed = if needs_escape { 3 } else { 1 };
        if (line.len() - 2) + needed > MAX_DATA_LINE_PAYLOAD {
            line.push('\n');
            writer.write_all(line.as_bytes()).await?;
            line.clear();
            line.push_str("D ");
        }

        if needs_escape {
            let _ = write!(line, "%{b:02X}");
        } else {
            line.push(char::from(b));
        }
    }

    if line.len() > 2 {
        line.push('\n');
        writer.write_all(line.as_bytes()).await?;
        writer.flush().await?;
    }

    Ok(())
}

fn map_card_error(err: &crate::Error) -> (u32, String) {
    if let crate::Error::Other(inner) = err
        && let Some(transport_err) = inner.downcast_ref::<TransportError>()
    {
        match transport_err {
            TransportError::OpenPgpPinRejected { .. }
            | TransportError::PivPinRejected { .. }
            | TransportError::PivBadPinLength
            | TransportError::PivSecurityNotSatisfied
            | TransportError::Apdu {
                sw1: 0x69,
                sw2: 0x82 | 0x83,
                ..
            } => return (GPG_ERR_BAD_PIN, err.to_string()),
            _ => {}
        }
    }
    (GPG_ERR_INV_DATA, err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::card::openpgp::OpenPgpKeyInfo;
    use crate::pinentry::Applet;
    use keyroost_openpgp::{PublicKey, RsaAttributes, RsaImportFormat};
    use ssh_agent_lib::secrecy::SecretBox;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    #[derive(Clone)]
    struct MockCallRecord {
        slot: Option<KeyCrt>,
        expected_serial: Option<u128>,
        input: Vec<u8>,
        prompt_desc: Option<String>,
        prompt_env: Option<PinentryEnv>,
    }

    struct MockCardState {
        keys: Vec<OpenPgpKeyInfo>,
        list_calls: usize,
        disconnect_calls: usize,
        sign_responses: std::collections::VecDeque<Result<CardOperationOutcome<Vec<u8>>, crate::Error>>,
        rsa_decrypt_responses:
            std::collections::VecDeque<Result<CardOperationOutcome<Vec<u8>>, crate::Error>>,
        ecdh_decrypt_responses:
            std::collections::VecDeque<Result<CardOperationOutcome<Vec<u8>>, crate::Error>>,
        sign_calls: Vec<MockCallRecord>,
        rsa_decrypt_calls: Vec<MockCallRecord>,
        ecdh_decrypt_calls: Vec<MockCallRecord>,
    }

    #[derive(Clone)]
    struct MockCard {
        state: Arc<Mutex<MockCardState>>,
    }

    impl MockCard {
        fn new(keys: Vec<OpenPgpKeyInfo>) -> Self {
            Self {
                state: Arc::new(Mutex::new(MockCardState {
                    keys,
                    list_calls: 0,
                    disconnect_calls: 0,
                    sign_responses: std::collections::VecDeque::new(),
                    rsa_decrypt_responses: std::collections::VecDeque::new(),
                    ecdh_decrypt_responses: std::collections::VecDeque::new(),
                    sign_calls: Vec::new(),
                    rsa_decrypt_calls: Vec::new(),
                    ecdh_decrypt_calls: Vec::new(),
                })),
            }
        }

        fn push_sign(&self, resp: Result<CardOperationOutcome<Vec<u8>>, crate::Error>) {
            self.state.lock().unwrap().sign_responses.push_back(resp);
        }

        fn push_rsa_decrypt(&self, resp: Result<CardOperationOutcome<Vec<u8>>, crate::Error>) {
            self.state
                .lock()
                .unwrap()
                .rsa_decrypt_responses
                .push_back(resp);
        }

        fn push_ecdh_decrypt(&self, resp: Result<CardOperationOutcome<Vec<u8>>, crate::Error>) {
            self.state
                .lock()
                .unwrap()
                .ecdh_decrypt_responses
                .push_back(resp);
        }

        fn set_keys(&self, keys: Vec<OpenPgpKeyInfo>) {
            self.state.lock().unwrap().keys = keys;
        }

        fn list_calls(&self) -> usize {
            self.state.lock().unwrap().list_calls
        }

        fn disconnect_calls(&self) -> usize {
            self.state.lock().unwrap().disconnect_calls
        }

        fn sign_calls(&self) -> Vec<MockCallRecord> {
            self.state.lock().unwrap().sign_calls.clone()
        }

        fn rsa_decrypt_calls(&self) -> Vec<MockCallRecord> {
            self.state.lock().unwrap().rsa_decrypt_calls.clone()
        }

        fn ecdh_decrypt_calls(&self) -> Vec<MockCallRecord> {
            self.state.lock().unwrap().ecdh_decrypt_calls.clone()
        }
    }

    impl GpgCardBackend for MockCard {
        fn list_keys(
            &self,
            _slots: &[KeyCrt],
        ) -> impl std::future::Future<Output = Result<Vec<OpenPgpKeyInfo>, crate::Error>> + Send {
            let mut st = self.state.lock().unwrap();
            st.list_calls += 1;
            std::future::ready(Ok(st.keys.clone()))
        }

        fn sign_raw(
            &self,
            slot: KeyCrt,
            expected_serial: Option<u128>,
            data: &[u8],
            prompt_desc: Option<&str>,
            prompt_env: Option<&PinentryEnv>,
        ) -> impl std::future::Future<
            Output = Result<CardOperationOutcome<Vec<u8>>, crate::Error>,
        > + Send {
            let mut st = self.state.lock().unwrap();
            st.sign_calls.push(MockCallRecord {
                slot: Some(slot),
                expected_serial,
                input: data.to_vec(),
                prompt_desc: prompt_desc.map(ToOwned::to_owned),
                prompt_env: prompt_env.cloned(),
            });
            std::future::ready(
                st.sign_responses
                    .pop_front()
                    .unwrap_or_else(|| Ok(CardOperationOutcome::NotFound)),
            )
        }

        fn decrypt_rsa(
            &self,
            expected_serial: Option<u128>,
            cryptogram: &[u8],
            prompt_desc: Option<&str>,
            prompt_env: Option<&PinentryEnv>,
        ) -> impl std::future::Future<
            Output = Result<CardOperationOutcome<Vec<u8>>, crate::Error>,
        > + Send {
            let mut st = self.state.lock().unwrap();
            st.rsa_decrypt_calls.push(MockCallRecord {
                slot: None,
                expected_serial,
                input: cryptogram.to_vec(),
                prompt_desc: prompt_desc.map(ToOwned::to_owned),
                prompt_env: prompt_env.cloned(),
            });
            std::future::ready(
                st.rsa_decrypt_responses
                    .pop_front()
                    .unwrap_or_else(|| Ok(CardOperationOutcome::NotFound)),
            )
        }

        fn decrypt_ecdh(
            &self,
            expected_serial: Option<u128>,
            ephemeral_point: &[u8],
            prompt_desc: Option<&str>,
            prompt_env: Option<&PinentryEnv>,
        ) -> impl std::future::Future<
            Output = Result<CardOperationOutcome<Vec<u8>>, crate::Error>,
        > + Send {
            let mut st = self.state.lock().unwrap();
            st.ecdh_decrypt_calls.push(MockCallRecord {
                slot: None,
                expected_serial,
                input: ephemeral_point.to_vec(),
                prompt_desc: prompt_desc.map(ToOwned::to_owned),
                prompt_env: prompt_env.cloned(),
            });
            std::future::ready(
                st.ecdh_decrypt_responses
                    .pop_front()
                    .unwrap_or_else(|| Ok(CardOperationOutcome::NotFound)),
            )
        }

        fn disconnect(&self) -> impl std::future::Future<Output = ()> + Send {
            self.state.lock().unwrap().disconnect_calls += 1;
            std::future::ready(())
        }
    }

    fn test_aid() -> Vec<u8> {
        vec![0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x03, 0x04]
    }

    fn rsa_key_info(slot: KeyCrt, serial: u128) -> (OpenPgpKeyInfo, Keygrip) {
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
            aid: test_aid(),
            serial: Some(u32::try_from(serial).unwrap_or(0)),
            full_serial: Some(serial),
        };
        (info, kg)
    }

    fn ecdsa_p256_key_info(slot: KeyCrt, serial: u128) -> (OpenPgpKeyInfo, Keygrip) {
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
            aid: test_aid(),
            serial: Some(u32::try_from(serial).unwrap_or(0)),
            full_serial: Some(serial),
        };
        (info, kg)
    }

    fn ed25519_key_info(slot: KeyCrt, serial: u128) -> (OpenPgpKeyInfo, Keygrip) {
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
            aid: test_aid(),
            serial: Some(u32::try_from(serial).unwrap_or(0)),
            full_serial: Some(serial),
        };
        (info, kg)
    }

    fn x25519_key_info(slot: KeyCrt, serial: u128) -> (OpenPgpKeyInfo, Keygrip) {
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
            aid: test_aid(),
            serial: Some(u32::try_from(serial).unwrap_or(0)),
            full_serial: Some(serial),
        };
        (info, kg)
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

        /// Send a command and read lines until `OK...`, `ERR...`, or `INQUIRE...`.
        async fn command(&mut self, cmd: &str) -> (Vec<String>, Vec<u8>, String) {
            self.send_line(cmd).await;
            self.read_until_terminal().await
        }

        async fn read_until_terminal(&mut self) -> (Vec<String>, Vec<u8>, String) {
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
        card: Option<MockCard>,
        idle_tracker: IdleTracker,
        pin_cache: Option<PinCache>,
        key_cache: GpgKeyCache,
        socket_name: Option<String>,
    ) -> (TestClient, tokio::task::JoinHandle<()>) {
        let (client_stream, server_stream) = tokio::io::duplex(16 * 1024);
        let handle = tokio::spawn(async move {
            let _ = serve_connection(
                server_stream,
                card,
                idle_tracker,
                pin_cache,
                key_cache,
                socket_name,
            )
            .await;
        });
        let (r, w) = tokio::io::split(client_stream);
        let mut client = TestClient {
            reader: BufReader::new(r),
            writer: w,
        };
        let greeting = client.read_line().await;
        assert_eq!(greeting, "OK Pleased to meet you");
        (client, handle)
    }

    #[tokio::test]
    async fn session_commands_getinfo_option_and_comments() {
        let (mut client, handle) = spawn_server(
            None,
            IdleTracker::new(),
            None,
            GpgKeyCache::new(),
            Some("/run/user/1000/S.gpg-agent".to_owned()),
        )
        .await;

        // Comments and blank lines produce no response.
        client.send_line("# comment line").await;
        client.send_line("   ").await;

        let (_, _, term) = client.command("nop").await;
        assert_eq!(term, "OK");

        let (_, data, term) = client.command("GETINFO version").await;
        assert_eq!(term, "OK");
        assert_eq!(data, b"2.4.0");

        let (_, data, term) = client.command("GETINFO pid").await;
        assert_eq!(term, "OK");
        assert_eq!(
            String::from_utf8(data).unwrap(),
            std::process::id().to_string()
        );

        let (_, data, term) = client.command("GETINFO socket_name").await;
        assert_eq!(term, "OK");
        assert_eq!(data, b"/run/user/1000/S.gpg-agent");

        for supported in [
            "GETINFO cmd_has_option KEYINFO list",
            "GETINFO cmd_has_option KEYINFO data",
            "GETINFO cmd_has_option HAVEKEY list",
            "GETINFO cmd_has_option PKSIGN hash",
        ] {
            let (_, _, term) = client.command(supported).await;
            assert_eq!(term, "OK", "expected OK for {supported}");
        }

        let (_, _, term) = client.command("GETINFO cmd_has_option PKSIGN bogus").await;
        assert!(term.starts_with(&format!(
            "ERR {} ",
            gpg_err_make(GPG_ERR_SOURCE_GPGAGENT, GPG_ERR_NOT_IMPLEMENTED)
        )));

        let (_, _, term) = client.command("UNKNOWNCMD").await;
        assert!(term.starts_with(&format!(
            "ERR {} ",
            gpg_err_make(GPG_ERR_SOURCE_GPGAGENT, GPG_ERR_UNKNOWN_COMMAND)
        )));

        let (_, _, term) = client.command("BYE").await;
        assert_eq!(term, "OK closing connection");
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn havekey_match_miss_and_list() {
        let (sig_info, sig_kg) = ed25519_key_info(KeyCrt::Sign, 42);
        let (dec_info, dec_kg) = x25519_key_info(KeyCrt::Decrypt, 42);
        let card = MockCard::new(vec![sig_info, dec_info]);

        let (mut client, handle) = spawn_server(
            Some(card),
            IdleTracker::new(),
            None,
            GpgKeyCache::new(),
            None,
        )
        .await;

        // --list returns concatenated raw 20-byte keygrips
        let (_, data, term) = client.command("HAVEKEY --list").await;
        assert_eq!(term, "OK");
        let mut expected = Vec::new();
        expected.extend_from_slice(sig_kg.as_bytes());
        expected.extend_from_slice(dec_kg.as_bytes());
        assert_eq!(data, expected);

        // --list=1 truncates to 1 keygrip
        let (_, data, term) = client.command("HAVEKEY --list=1").await;
        assert_eq!(term, "OK");
        assert_eq!(data, sig_kg.as_bytes());

        // Match existing keygrip
        let (_, _, term) = client.command(&format!("HAVEKEY {sig_kg}")).await;
        assert_eq!(term, "OK");

        // Match when at least one of multiple keygrips exists
        let missing = "00".repeat(20);
        let (_, _, term) = client.command(&format!("HAVEKEY {missing} {dec_kg}")).await;
        assert_eq!(term, "OK");

        // Miss returns GPG_ERR_NO_SECKEY (67108881)
        let (_, _, term) = client.command(&format!("HAVEKEY {missing}")).await;
        assert!(term.starts_with("ERR 67108881 "));

        client.command("BYE").await;
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn keyinfo_single_list_and_data_modes() {
        let (sig_info, sig_kg) = ed25519_key_info(KeyCrt::Sign, 42);
        let (dec_info, dec_kg) = x25519_key_info(KeyCrt::Decrypt, 42);
        let (auth_info, auth_kg) = ecdsa_p256_key_info(KeyCrt::Auth, 42);
        let card = MockCard::new(vec![sig_info, dec_info, auth_info]);

        let (mut client, handle) = spawn_server(
            Some(card),
            IdleTracker::new(),
            None,
            GpgKeyCache::new(),
            None,
        )
        .await;

        // --list emits S KEYINFO lines
        let (status, _, term) = client.command("KEYINFO --list").await;
        assert_eq!(term, "OK");
        assert_eq!(
            status,
            vec![
                format!("S KEYINFO {sig_kg} T D276000124010304 OPENPGP.1 - - - - -"),
                format!("S KEYINFO {dec_kg} T D276000124010304 OPENPGP.2 - - - - -"),
                format!("S KEYINFO {auth_kg} T D276000124010304 OPENPGP.3 - - - - -"),
            ]
        );

        // Single keygrip lookup
        let (status, _, term) = client.command(&format!("KEYINFO {dec_kg}")).await;
        assert_eq!(term, "OK");
        assert_eq!(
            status,
            vec![format!(
                "S KEYINFO {dec_kg} T D276000124010304 OPENPGP.2 - - - - -"
            )]
        );

        // --data emits D KEYINFO ...
        let (status, data, term) = client.command(&format!("KEYINFO --data {sig_kg}")).await;
        assert_eq!(term, "OK");
        assert_eq!(status, Vec::<String>::new());
        assert_eq!(
            String::from_utf8(data).unwrap(),
            format!("KEYINFO {sig_kg} T D276000124010304 OPENPGP.1 - - - - -")
        );

        // Missing keygrip returns NO_SECKEY
        let missing = "FF".repeat(20);
        let (_, _, term) = client.command(&format!("KEYINFO {missing}")).await;
        assert!(term.starts_with("ERR 67108881 "));

        client.command("BYE").await;
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn pksign_rsa_ecdsa_ed25519_and_inquire_data() {
        let (rsa_info, rsa_kg) = rsa_key_info(KeyCrt::Sign, 100);
        let (ecdsa_info, ecdsa_kg) = ecdsa_p256_key_info(KeyCrt::Auth, 100);
        let (ed_info, ed_kg) = ed25519_key_info(KeyCrt::Decrypt, 100);
        let card = MockCard::new(vec![rsa_info, ecdsa_info, ed_info]);

        card.push_sign(Ok(CardOperationOutcome::Completed(vec![0xAA; 256])));
        let mut ecdsa_raw = vec![0x11; 32];
        ecdsa_raw.extend_from_slice(&[0x22; 32]);
        card.push_sign(Ok(CardOperationOutcome::Completed(ecdsa_raw)));
        let mut ed_raw = vec![0x33; 32];
        ed_raw.extend_from_slice(&[0x44; 32]);
        card.push_sign(Ok(CardOperationOutcome::Completed(ed_raw)));

        let (mut client, handle) = spawn_server(
            Some(card.clone()),
            IdleTracker::new(),
            None,
            GpgKeyCache::new(),
            None,
        )
        .await;

        // Configure pinentry OPTIONs and SETKEYDESC (+ as space and %2B as '+')
        assert_eq!(client.command("OPTION ttyname=/dev/pts/7").await.2, "OK");
        assert_eq!(client.command("OPTION display=:0").await.2, "OK");
        assert_eq!(
            client
                .command("SETKEYDESC Sign+commit%0A100%25+ok%2Bmore")
                .await
                .2,
            "OK"
        );

        // 1. RSA signing with SETHASH 8 (SHA-256)
        assert_eq!(client.command(&format!("SIGKEY {rsa_kg}")).await.2, "OK");
        let sha256_hex = "ab".repeat(32);
        assert_eq!(
            client.command(&format!("SETHASH 8 {sha256_hex}")).await.2,
            "OK"
        );
        let (_, data, term) = client.command("PKSIGN").await;
        assert_eq!(term, "OK");
        assert_eq!(data, encode_rsa_sig(&[0xAA; 256]));

        // 2. ECDSA signing with SETHASH --hash=sha256
        assert_eq!(client.command(&format!("SIGKEY {ecdsa_kg}")).await.2, "OK");
        let ecdsa_hex = "cd".repeat(32);
        assert_eq!(
            client
                .command(&format!("SETHASH --hash=sha256 {ecdsa_hex}"))
                .await
                .2,
            "OK"
        );
        let (_, data, term) = client.command("PKSIGN").await;
        assert_eq!(term, "OK");
        assert_eq!(data, encode_ecdsa_sig(&[0x11; 32], &[0x22; 32]));

        // 3. Ed25519 signing via INQUIRE DATA (no SETHASH)
        assert_eq!(client.command(&format!("SETKEY {ed_kg}")).await.2, "OK");
        let (_, _, term) = client.command("PKSIGN --hash=sha512").await;
        assert_eq!(term, "INQUIRE DATA");
        client.send_line("D hello%20world").await;
        client.send_line("END").await;
        let (_, data, term) = client.read_until_terminal().await;
        assert_eq!(term, "OK");
        assert_eq!(data, encode_eddsa_sig(&[0x33; 32], &[0x44; 32]));

        // Verify card received DigestInfo-prefixed RSA input, raw ECDSA digest, raw Ed25519 data,
        // and the decoded SETKEYDESC + PinentryEnv.
        let calls = card.sign_calls();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].slot, Some(KeyCrt::Sign));
        assert_eq!(calls[1].slot, Some(KeyCrt::Auth));
        assert_eq!(calls[2].slot, Some(KeyCrt::Decrypt));

        let mut expected_rsa_in = SHA256_DIGEST_INFO_PREFIX.to_vec();
        expected_rsa_in.extend_from_slice(&[0xAB; 32]);
        assert_eq!(calls[0].input, expected_rsa_in);
        assert_eq!(
            calls[0].prompt_desc.as_deref(),
            Some("Sign commit\n100% ok+more")
        );
        assert_eq!(
            calls[0].prompt_env,
            Some(PinentryEnv {
                ttyname: Some("/dev/pts/7".to_owned()),
                display: Some(":0".to_owned()),
                ..Default::default()
            })
        );

        assert_eq!(calls[1].input, vec![0xCD; 32]);
        assert_eq!(calls[2].input, b"hello world");

        client.command("BYE").await;
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn pkdecrypt_rsa_x25519_and_inquire_cancel() {
        let (rsa_info, rsa_kg) = rsa_key_info(KeyCrt::Decrypt, 7);
        let (x25519_info, x25519_kg) = x25519_key_info(KeyCrt::Auth, 7);
        let card = MockCard::new(vec![rsa_info, x25519_info]);

        card.push_rsa_decrypt(Ok(CardOperationOutcome::Completed(b"rsa-session-key".to_vec())));
        card.push_ecdh_decrypt(Ok(CardOperationOutcome::Completed(vec![0x77; 32])));

        let (mut client, handle) = spawn_server(
            Some(card.clone()),
            IdleTracker::new(),
            None,
            GpgKeyCache::new(),
            None,
        )
        .await;

        // 1. RSA decryption
        assert_eq!(client.command(&format!("SETKEY {rsa_kg}")).await.2, "OK");
        let (_, _, term) = client.command("PKDECRYPT").await;
        assert_eq!(term, "INQUIRE CIPHERTEXT");
        client.send_line("D (7:enc-val(3:rsa(1:a4:ABCD)))").await;
        client.send_line("END").await;
        let (status, data, term) = client.read_until_terminal().await;
        assert_eq!(term, "OK");
        assert_eq!(status, vec!["S PADDING 0"]);
        assert_eq!(data, encode_decrypt_value(b"rsa-session-key"));

        // 2. X25519 ECDH decryption prepends 0x40 to 32-byte shared secret
        assert_eq!(client.command(&format!("SETKEY {x25519_kg}")).await.2, "OK");
        let (_, _, term) = client.command("PKDECRYPT").await;
        assert_eq!(term, "INQUIRE CIPHERTEXT");
        client.send_line("D (7:enc-val(4:ecdh(1:e4:WXYZ)))").await;
        client.send_line("END").await;
        let (status, data, term) = client.read_until_terminal().await;
        assert_eq!(term, "OK");
        assert_eq!(status, vec!["S PADDING 0"]);
        let mut expected_shared = vec![0x40];
        expected_shared.extend_from_slice(&[0x77; 32]);
        assert_eq!(data, encode_decrypt_value(&expected_shared));

        // 3. Client sends CAN during INQUIRE CIPHERTEXT
        let (_, _, term) = client.command("PKDECRYPT").await;
        assert_eq!(term, "INQUIRE CIPHERTEXT");
        client.send_line("CAN").await;
        let (_, _, term) = client.read_until_terminal().await;
        assert!(term.starts_with(&format!(
            "ERR {} ",
            gpg_err_make(GPG_ERR_SOURCE_GPGAGENT, GPG_ERR_CANCELED)
        )));

        assert_eq!(card.rsa_decrypt_calls()[0].input, b"ABCD");
        assert_eq!(card.ecdh_decrypt_calls()[0].input, b"WXYZ");

        client.command("BYE").await;
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn pkdecrypt_handles_binary_inquire_and_strips_x25519_prefix() {
        let (x25519_info, x25519_kg) = x25519_key_info(KeyCrt::Decrypt, 7);
        let card = MockCard::new(vec![x25519_info]);
        card.push_ecdh_decrypt(Ok(CardOperationOutcome::Completed(vec![0xAB; 32])));

        let (mut client, handle) = spawn_server(
            Some(card.clone()),
            IdleTracker::new(),
            None,
            GpgKeyCache::new(),
            None,
        )
        .await;

        assert_eq!(client.command(&format!("SETKEY {x25519_kg}")).await.2, "OK");
        let (_, _, term) = client.command("PKDECRYPT").await;
        assert_eq!(term, "INQUIRE CIPHERTEXT");

        // Build a 33-byte Cv25519 ephemeral point with 0x40 prefix and non-UTF-8 bytes.
        let mut raw_u = [0u8; 32];
        for (i, b) in raw_u.iter_mut().enumerate() {
            *b = 0x80u8.wrapping_add(u8::try_from(i).unwrap());
        }
        let mut line = Vec::from(&b"D (7:enc-val(4:ecdh(1:e33:\x40"[..]);
        line.extend_from_slice(&raw_u);
        line.extend_from_slice(b")))\n");
        client.writer.write_all(&line).await.unwrap();
        client.writer.flush().await.unwrap();
        client.send_line("END").await;

        let (status, data, term) = client.read_until_terminal().await;
        assert_eq!(term, "OK");
        assert_eq!(status, vec!["S PADDING 0"]);
        let mut expected_shared = vec![0x40];
        expected_shared.extend_from_slice(&[0xAB; 32]);
        assert_eq!(data, encode_decrypt_value(&expected_shared));

        // Card must receive the raw 32-byte coordinate without the 0x40 prefix.
        assert_eq!(card.ecdh_decrypt_calls()[0].input, raw_u);

        client.command("BYE").await;
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn clear_passphrase_and_reloadagent_clear_caches_and_disconnect() {
        let (sig_info, sig_kg) = ed25519_key_info(KeyCrt::Sign, 1);
        let card = MockCard::new(vec![sig_info]);
        let pin_cache = PinCache::new(Duration::from_secs(60), None);
        let key_cache = GpgKeyCache::new();

        pin_cache.insert(
            Applet::OpenPgp,
            Some(1),
            SecretBox::from(Box::<str>::from("123456")),
        );

        let (mut client, handle) = spawn_server(
            Some(card.clone()),
            IdleTracker::new(),
            Some(pin_cache.clone()),
            key_cache.clone(),
            None,
        )
        .await;

        // Populate key_cache via HAVEKEY
        assert_eq!(client.command(&format!("HAVEKEY {sig_kg}")).await.2, "OK");
        assert!(key_cache.get(&sig_kg).is_some());

        // CLEAR_PASSPHRASE clears caches & disconnects
        assert_eq!(
            client.command("CLEAR_PASSPHRASE --mode=normal foo").await.2,
            "OK"
        );
        assert!(pin_cache.get(Applet::OpenPgp, Some(1)).is_none());
        assert!(key_cache.get(&sig_kg).is_none());
        assert_eq!(card.disconnect_calls(), 1);

        // Re-populate and test RELOADAGENT
        pin_cache.insert(
            Applet::OpenPgp,
            Some(1),
            SecretBox::from(Box::<str>::from("654321")),
        );
        assert_eq!(client.command(&format!("HAVEKEY {sig_kg}")).await.2, "OK");
        assert!(key_cache.get(&sig_kg).is_some());

        assert_eq!(client.command("RELOADAGENT").await.2, "OK");
        assert!(pin_cache.get(Applet::OpenPgp, Some(1)).is_none());
        assert!(key_cache.get(&sig_kg).is_none());
        assert_eq!(card.disconnect_calls(), 2);

        client.command("BYE").await;
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn user_cancel_and_wrong_pin_map_to_gpg_error_codes() {
        let (ed_info, ed_kg) = ed25519_key_info(KeyCrt::Sign, 5);
        let card = MockCard::new(vec![ed_info]);
        card.push_sign(Ok(CardOperationOutcome::UserCancelled));
        card.push_sign(Err(crate::Error::from(
            TransportError::OpenPgpPinRejected {
                tries_remaining: Some(2),
            },
        )));

        let (mut client, handle) = spawn_server(
            Some(card),
            IdleTracker::new(),
            None,
            GpgKeyCache::new(),
            None,
        )
        .await;

        assert_eq!(client.command(&format!("SIGKEY {ed_kg}")).await.2, "OK");
        let digest = "11".repeat(32);

        // User cancel -> GPG_ERR_CANCELED
        assert_eq!(client.command(&format!("SETHASH 8 {digest}")).await.2, "OK");
        let (_, _, term) = client.command("PKSIGN").await;
        assert!(term.starts_with(&format!(
            "ERR {} ",
            gpg_err_make(GPG_ERR_SOURCE_GPGAGENT, GPG_ERR_CANCELED)
        )));

        // Wrong PIN -> GPG_ERR_BAD_PIN
        assert_eq!(client.command(&format!("SETHASH 8 {digest}")).await.2, "OK");
        let (_, _, term) = client.command("PKSIGN").await;
        assert!(term.starts_with(&format!(
            "ERR {} ",
            gpg_err_make(GPG_ERR_SOURCE_GPGAGENT, GPG_ERR_BAD_PIN)
        )));

        client.command("BYE").await;
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn cache_miss_and_stale_card_rescan_on_sign() {
        let (ed_info_old, ed_kg) = ed25519_key_info(KeyCrt::Sign, 10);
        let (ed_info_new, _) = ed25519_key_info(KeyCrt::Sign, 20);
        let card = MockCard::new(vec![ed_info_old]);
        let key_cache = GpgKeyCache::new();

        // Pre-seed cache with serial 10
        key_cache.replace([(
            ed_kg,
            GpgCachedKey {
                slot: KeyCrt::Sign,
                attrs: AlgorithmAttributes::Ecc {
                    kind: EccKind::EdDsa,
                    curve: Curve::Ed25519,
                    import_with_public_key: false,
                },
                aid: test_aid(),
                serial: Some(10),
            },
        )]);

        // Card now holds serial 20; first sign returns NotFound, retry after rescan succeeds.
        card.set_keys(vec![ed_info_new]);
        card.push_sign(Ok(CardOperationOutcome::NotFound));
        card.push_sign(Ok(CardOperationOutcome::Completed(vec![0x99; 64])));

        let (mut client, handle) = spawn_server(
            Some(card.clone()),
            IdleTracker::new(),
            None,
            key_cache.clone(),
            None,
        )
        .await;

        assert_eq!(client.command(&format!("SIGKEY {ed_kg}")).await.2, "OK");
        let digest = "22".repeat(32);
        assert_eq!(client.command(&format!("SETHASH 8 {digest}")).await.2, "OK");
        let (_, data, term) = client.command("PKSIGN").await;
        assert_eq!(term, "OK");
        assert_eq!(data, encode_eddsa_sig(&[0x99; 32], &[0x99; 32]));

        // Exactly one rescan happened, and cache now holds serial 20.
        assert_eq!(card.list_calls(), 1);
        assert_eq!(key_cache.get(&ed_kg).unwrap().serial, Some(20));

        let calls = card.sign_calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].expected_serial, Some(10));
        assert_eq!(calls[1].expected_serial, None);

        client.command("BYE").await;
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn idle_tracker_records_activity_on_commands() {
        let tracker = IdleTracker::new();
        let activity_count = Arc::new(AtomicUsize::new(0));
        let counter_clone = Arc::clone(&activity_count);
        let watch_tracker = tracker.clone();

        let watcher = tokio::spawn(async move {
            loop {
                watch_tracker.wait_for_activity().await;
                counter_clone.fetch_add(1, Ordering::SeqCst);
            }
        });

        let (mut client, handle) =
            spawn_server(None, tracker, None, GpgKeyCache::new(), None).await;

        // Yield to ensure watcher is waiting
        tokio::task::yield_now().await;
        assert_eq!(client.command("NOP").await.2, "OK");
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            activity_count.load(Ordering::SeqCst) >= 1,
            "expected IdleTracker activity on GPG command"
        );

        client.command("BYE").await;
        handle.await.unwrap();
        watcher.abort();
    }

    #[tokio::test]
    async fn reset_clears_key_hash_desc_and_overlong_line_is_rejected() {
        let (ed_info, ed_kg) = ed25519_key_info(KeyCrt::Sign, 3);
        let card = MockCard::new(vec![ed_info]);
        card.push_sign(Ok(CardOperationOutcome::Completed(vec![0x55; 64])));

        let (mut client, handle) = spawn_server(
            Some(card.clone()),
            IdleTracker::new(),
            None,
            GpgKeyCache::new(),
            None,
        )
        .await;

        assert_eq!(client.command("OPTION ttyname=/dev/pts/9").await.2, "OK");
        assert_eq!(client.command(&format!("SIGKEY {ed_kg}")).await.2, "OK");
        assert_eq!(client.command("SETKEYDESC Old+desc").await.2, "OK");
        assert_eq!(
            client
                .command(&format!("SETHASH 8 {}", "aa".repeat(32)))
                .await
                .2,
            "OK"
        );

        // RESET clears key, hash, and key_desc, but preserves OPTION ttyname
        assert_eq!(client.command("RESET").await.2, "OK");
        let (_, _, term) = client.command("PKSIGN").await;
        assert!(term.starts_with(&format!(
            "ERR {} ",
            gpg_err_make(GPG_ERR_SOURCE_GPGAGENT, GPG_ERR_NO_SECKEY)
        )));

        // Re-select key and sign: key_desc is None, PinentryEnv still has ttyname
        assert_eq!(client.command(&format!("SIGKEY {ed_kg}")).await.2, "OK");
        assert_eq!(
            client
                .command(&format!("SETHASH 8 {}", "bb".repeat(32)))
                .await
                .2,
            "OK"
        );
        assert_eq!(client.command("PKSIGN").await.2, "OK");
        let calls = card.sign_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].prompt_desc, None);
        assert_eq!(
            calls[0].prompt_env,
            Some(PinentryEnv {
                ttyname: Some("/dev/pts/9".to_owned()),
                ..Default::default()
            })
        );

        // Line exceeding MAX_LINE_LEN returns INV_DATA without breaking the connection
        let overlong = format!("NOP {}", "x".repeat(MAX_LINE_LEN + 50));
        let (_, _, term) = client.command(&overlong).await;
        assert!(term.starts_with(&format!(
            "ERR {} ",
            gpg_err_make(GPG_ERR_SOURCE_GPGAGENT, GPG_ERR_INV_DATA)
        )));
        assert_eq!(client.command("NOP").await.2, "OK");

        client.command("BYE").await;
        handle.await.unwrap();
    }
}
