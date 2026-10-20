//! VSmartCard front end: presents [`PivApplet`] as a PC/SC card.
//!
//! This binary is the `vpicc` (virtual ICC) side of the VSmartCard
//! architecture: it listens on a TCP port; the `vpcd` PC/SC reader driver
//! (shipped by `pkgs.vsmartcard-vpcd`, registered with `pcscd` by the
//! `services.vsmartcard-vpcd` NixOS module, and pointed at this host with
//! that module's `hostname` option) connects to it, and it answers as a
//! card for every PC/SC client that reaches the reader.
//!
//! # Wire protocol
//!
//! VSmartCard is a length-prefixed TCP protocol in both directions: a
//! big-endian `u16` count, then exactly that many payload bytes.
//!
//! * The driver sends a one-byte control message: `0x00` (power off),
//!   `0x01` (power on) or `0x02` (reset) — none of the three is
//!   answered — or `0x04` (get ATR), answered with the ATR bytes. An
//!   empty answer would mean "card absent"; this front end is always
//!   present.
//! * Every other message is a command APDU. The answer is the response
//!   APDU: the response data, followed by the two-byte status word.
//!
//! The card is the applet instance created on power on / reset. While the
//! applet is wiring only, unimplemented APDUs are answered with a
//! not-supported status word instead of panicking.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::ExitCode;

use clap::Parser;
use tracing::{info, trace, warn};
use tracing_subscriber::EnvFilter;

use keyroost_piv_applet::{PivApplet, Response};

/// The ATR of a YubiKey 4, so card drivers that match on the ATR (OpenSC's
/// PIV support, GnuPG) bind to the virtual card.
const DEFAULT_ATR: &str = "3BFD1300008131FE158073C021C057597562694B657940";

// VSmartCard control commands (driver → card, one-byte payload).
const CTRL_POWER_OFF: u8 = 0x00;
const CTRL_POWER_ON: u8 = 0x01;
const CTRL_RESET: u8 = 0x02;
const CTRL_GET_ATR: u8 = 0x04;

// ISO 7816-4 status words for malformed input.
const SW_WRONG_LENGTH: u16 = 0x6700;
const SW_NOT_INITIALIZED: u16 = 0x6985;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "piv-vsmartcard",
    version,
    about = "Present the keyroost PIV applet as a PC/SC card via VSmartCard"
)]
struct Args {
    /// Host to bind the listener on.
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// Port to listen on.
    #[arg(long, default_value_t = 35963u16)]
    port: u16,

    /// ATR presented to PC/SC clients, as a hex string.
    #[arg(long, default_value = DEFAULT_ATR)]
    atr: String,
}

fn main() -> ExitCode {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let atr = match hex_decode(&args.atr) {
        Ok(atr) => atr,
        Err(e) => {
            tracing::error!("invalid --atr: {e}");
            return ExitCode::FAILURE;
        }
    };

    // We are the vpicc listener: vpcd is configured in connect mode and
    // dials us. The port is ours, so bind once — a failure here is a real
    // error rather than something to retry.
    let listener = match TcpListener::bind((args.host.as_str(), args.port)) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(host = %args.host, port = args.port, "cannot bind: {e}");
            return ExitCode::FAILURE;
        }
    };
    info!(host = %args.host, port = args.port, "listening for vpcd");

    loop {
        match listener.accept() {
            Ok((stream, addr)) => {
                info!(%addr, "vpcd connected");
                if let Err(e) = serve_connection(stream, &atr) {
                    warn!("connection with {addr} failed: {e}");
                }
            }
            Err(e) => warn!("accept failed: {e}"),
        }
    }
}

/// Serve one vpcd connection until it drops.
fn serve_connection(mut stream: TcpStream, atr: &[u8]) -> io::Result<()> {
    // The card: the applet instance
    let mut applet = PivApplet::new();
    let mut power_on = false;

    loop {
        let Some(msg) = read_msg(&mut stream)? else {
            info!("vpcd disconnected");
            return Ok(());
        };

        if msg.len() == 1 {
            // A control command: answered, at most, with an ATR.
            match msg[0] {
                CTRL_POWER_OFF => {
                    power_on = false;
                    trace!("power off");
                }
                CTRL_POWER_ON | CTRL_RESET => {
                    power_on = true;
                    trace!("power on (fresh applet)");
                }
                CTRL_GET_ATR => write_msg(&mut stream, atr)?,
                other => warn!("unknown control command 0x{other:02x}"),
            }
            continue;
        }
        // A command APDU.

        let response = if !power_on {
            warn!("command APDU while powered off");
            Response::sw(SW_NOT_INITIALIZED)
        } else if msg.len() < 4 {
            warn!(
                "command APDU shorter than the 4-byte header ({} byte(s))",
                msg.len()
            );
            Response::sw(SW_WRONG_LENGTH)
        } else {
            applet.process(&msg)
        };

        trace!(
            apdu = hex(&msg),
            sw = format!("{:04X}", response.sw),
            "command APDU"
        );
        let mut out = response.data;
        out.extend_from_slice(&response.sw.to_be_bytes());
        write_msg(&mut stream, &out)?;
    }
}

/// Read one length-prefixed message; `None` on a clean close.
fn read_msg(r: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 2];
    match r.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let n = u16::from_be_bytes(len) as usize;
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)?;
    Ok(Some(buf))
}

/// Write one length-prefixed message.
fn write_msg(w: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    let len = u16::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "message exceeds 65535 bytes"))?;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(payload)?;
    w.flush()
}

/// Decode an even-length hex string.
fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(format!("hex string has odd length ({})", bytes.len()));
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for i in (0..bytes.len()).step_by(2) {
        let pair = &s[i..i + 2];
        out.push(u8::from_str_radix(pair, 16).map_err(|_| format!("invalid hex pair {pair:?}"))?);
    }
    Ok(out)
}

/// Encode bytes as lowercase hex, for tracing.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}
