use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
struct Cli {
    #[command(flatten)]
    verbosity: clap_verbosity_flag::Verbosity,

    /// Bind the agent to the specified Unix-domain socket.
    #[arg(short = 's', long)]
    socket: PathBuf,

    /// Smart-card reader whose name contains this text (case-insensitive)
    #[arg(short = 'r', long)]
    reader: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opts = Cli::parse();

    tracing_subscriber::fmt()
        .with_max_level(opts.verbosity)
        .init();

    let mut readers = keyroost_transport::probe_readers()?
        .into_iter()
        .filter(|reader| reader.has_piv);
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

    keyroost_agent::run(&opts.socket, reader.reader_name.clone(), None).await?;

    Ok(())
}
