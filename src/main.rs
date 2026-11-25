use std::os::unix::io::FromRawFd;
use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
struct Cli {
    #[command(flatten)]
    verbosity: clap_verbosity_flag::Verbosity,

    /// Bind the agent to the specified Unix-domain socket.
    #[arg(short = 's', long)]
    socket: Option<PathBuf>,

    /// Smart-card reader whose name contains this text (case-insensitive)
    #[arg(short = 'r', long)]
    reader: Option<String>,

    /// Path or name of the pinentry binary to use for PIN prompts
    #[arg(short = 'p', long)]
    pinentry: Option<String>,
}

fn systemd_listener() -> Result<Option<tokio::net::UnixListener>, Box<dyn std::error::Error>> {
    let Ok(fds) = std::env::var("LISTEN_FDS") else {
        return Ok(None);
    };
    let fds: usize = fds.parse()?;
    if fds == 0 {
        return Ok(None);
    }
    if let Ok(pid) = std::env::var("LISTEN_PID") {
        let pid: u32 = pid.parse()?;
        if pid != std::process::id() {
            return Ok(None);
        }
    }
    if fds > 1 {
        return Err(format!("Expected 1 systemd socket fd, got {fds}").into());
    }

    // SAFETY: systemd passes the first socket-activated file descriptor as fd 3.
    let std_listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(3) };
    std_listener.set_nonblocking(true)?;
    Ok(Some(tokio::net::UnixListener::from_std(std_listener)?))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opts = Cli::parse();

    tracing_subscriber::fmt()
        .with_max_level(opts.verbosity)
        .init();

    let mut readers = keyroost_transport::probe_readers()?
        .into_iter()
        .filter(|reader| reader.has_piv || reader.has_openpgp);
    let reader = match opts.reader {
        Some(name) => readers.find(|probed| {
            probed
                .reader_name
                .to_lowercase()
                .contains(&name.to_lowercase())
        }),
        None => readers.next(),
    };

    let Some(reader) = reader else {
        return Err("No PC/SC reader found.".into());
    };

    let piv_reader = reader.has_piv.then(|| reader.reader_name.clone());
    let openpgp_reader = reader.has_openpgp.then(|| reader.reader_name.clone());

    if let Some(socket) = opts.socket {
        keyroost_agent::run(&socket, piv_reader, openpgp_reader, opts.pinentry).await?;
    } else if let Some(listener) = systemd_listener()? {
        keyroost_agent::run_with_listener(listener, piv_reader, openpgp_reader, opts.pinentry).await?;
    } else {
        return Err("Either --socket or systemd socket activation (LISTEN_FDS) is required.".into());
    }

    Ok(())
}
