use std::os::unix::io::FromRawFd;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, ValueEnum};
use keyroost_agent::ConnectionMode;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
enum AppletSelection {
    #[default]
    Auto,
    Piv,
    #[value(name = "openpgp")]
    OpenPgp,
    Both,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
enum ConnectionSelection {
    #[default]
    Auto,
    Persistent,
    Ephemeral,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ResolvedConfig {
    use_piv: bool,
    use_openpgp: bool,
    connection_mode: ConnectionMode,
}

#[expect(clippy::fn_params_excessive_bools)]
fn resolve_config(
    applet: AppletSelection,
    connection: ConnectionSelection,
    has_piv: bool,
    has_openpgp: bool,
    piv_has_identities: bool,
    openpgp_has_identities: bool,
) -> Result<ResolvedConfig, String> {
    let (use_piv, use_openpgp) = match applet {
        AppletSelection::Piv => {
            if !has_piv {
                return Err(
                    "PIV applet requested (--applet=piv), but no PIV applet was found on the reader."
                        .to_owned(),
                );
            }
            (true, false)
        }
        AppletSelection::OpenPgp => {
            if !has_openpgp {
                return Err(
                    "OpenPGP applet requested (--applet=openpgp), but no OpenPGP applet was found on the reader."
                        .to_owned(),
                );
            }
            (false, true)
        }
        AppletSelection::Both => match (has_piv, has_openpgp) {
            (true, true) => (true, true),
            (false, false) => {
                return Err(
                    "Both applets requested (--applet=both), but neither PIV nor OpenPGP applet was found on the reader."
                        .to_owned(),
                );
            }
            (false, true) => {
                return Err(
                    "Both applets requested (--applet=both), but no PIV applet was found on the reader."
                        .to_owned(),
                );
            }
            (true, false) => {
                return Err(
                    "Both applets requested (--applet=both), but no OpenPGP applet was found on the reader."
                        .to_owned(),
                );
            }
        },
        AppletSelection::Auto => {
            if !has_piv && !has_openpgp {
                return Err("No PIV or OpenPGP applet found on the reader.".to_owned());
            }
            match (
                has_piv && piv_has_identities,
                has_openpgp && openpgp_has_identities,
            ) {
                (true, false) => (true, false),
                (false, true) => (false, true),
                (true, true) => (true, true),
                (false, false) => (has_piv, has_openpgp),
            }
        }
    };

    let both_active = use_piv && use_openpgp;
    let connection_mode = match connection {
        ConnectionSelection::Auto => {
            if both_active {
                ConnectionMode::Ephemeral
            } else {
                ConnectionMode::Persistent
            }
        }
        ConnectionSelection::Persistent => {
            if both_active {
                return Err(
                    "Persistent connection (--connection=persistent) cannot be used when both PIV and OpenPGP applets are active because switching between applets resets on-card PIN verification. Use --applet=piv, --applet=openpgp, or --connection=ephemeral."
                        .to_owned(),
                );
            }
            ConnectionMode::Persistent
        }
        ConnectionSelection::Ephemeral => ConnectionMode::Ephemeral,
    };

    Ok(ResolvedConfig {
        use_piv,
        use_openpgp,
        connection_mode,
    })
}

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

    /// Smart-card applet to expose
    #[arg(long, value_enum, default_value_t = AppletSelection::Auto)]
    applet: AppletSelection,

    /// Smart-card connection mode
    #[arg(long, value_enum, default_value_t = ConnectionSelection::Auto)]
    connection: ConnectionSelection,

    /// Idle timeout after which persistent smart-card sessions are released (0 disables; e.g. 30s, 30m, 1h)
    #[arg(
        long,
        value_name = "DURATION",
        default_value = "30m",
        value_parser = keyroost_agent::parse_duration
    )]
    idle_timeout: Duration,
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

    let piv_has_identities = reader.has_piv
        && opts.applet != AppletSelection::OpenPgp
        && keyroost_agent::probe_piv_identities(&reader.reader_name).unwrap_or_else(|err| {
            tracing::warn!("failed to probe PIV identities: {err}");
            false
        });

    let openpgp_has_identities = reader.has_openpgp
        && opts.applet != AppletSelection::Piv
        && keyroost_agent::probe_openpgp_identities(&reader.reader_name).unwrap_or_else(|err| {
            tracing::warn!("failed to probe OpenPGP identities: {err}");
            false
        });

    if opts.applet == AppletSelection::Auto && !piv_has_identities && !openpgp_has_identities {
        tracing::warn!(
            "no usable SSH identities found on reader '{}'; keeping available applets",
            reader.reader_name
        );
    }

    let resolved = resolve_config(
        opts.applet,
        opts.connection,
        reader.has_piv,
        reader.has_openpgp,
        piv_has_identities,
        openpgp_has_identities,
    )?;

    tracing::info!(
        reader = %reader.reader_name,
        piv = resolved.use_piv,
        openpgp = resolved.use_openpgp,
        connection = ?resolved.connection_mode,
        "resolved agent configuration"
    );

    let piv_reader = resolved.use_piv.then(|| reader.reader_name.clone());
    let openpgp_reader = resolved.use_openpgp.then(|| reader.reader_name.clone());
    let idle_timeout = (!opts.idle_timeout.is_zero()).then_some(opts.idle_timeout);

    if let Some(socket) = opts.socket {
        keyroost_agent::run(
            &socket,
            piv_reader,
            openpgp_reader,
            opts.pinentry,
            resolved.connection_mode,
            idle_timeout,
            false,
        )
        .await?;
    } else if let Some(listener) = systemd_listener()? {
        keyroost_agent::run_with_listener(
            listener,
            piv_reader,
            openpgp_reader,
            opts.pinentry,
            resolved.connection_mode,
            idle_timeout,
            true,
        )
        .await?;
    } else {
        return Err("Either --socket or systemd socket activation (LISTEN_FDS) is required.".into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{AppletSelection, Cli, ConnectionSelection, ResolvedConfig, resolve_config};
    use clap::Parser;
    use keyroost_agent::ConnectionMode;
    use std::time::Duration;

    #[test]
    fn cli_defaults_applet_and_connection_to_auto() {
        let cli = Cli::try_parse_from(["keyroost-agent"]).unwrap();
        assert_eq!(cli.applet, AppletSelection::Auto);
        assert_eq!(cli.connection, ConnectionSelection::Auto);
        assert_eq!(cli.idle_timeout, Duration::from_mins(30));
    }

    #[test]
    fn cli_parses_idle_timeout_options() {
        let default_cli = Cli::try_parse_from(["keyroost-agent"]).unwrap();
        assert_eq!(default_cli.idle_timeout, Duration::from_mins(30));

        let five_min = Cli::try_parse_from(["keyroost-agent", "--idle-timeout", "5m"]).unwrap();
        assert_eq!(five_min.idle_timeout, Duration::from_secs(300));

        let disabled = Cli::try_parse_from(["keyroost-agent", "--idle-timeout", "0"]).unwrap();
        assert!(disabled.idle_timeout.is_zero());
        assert_eq!(
            (!disabled.idle_timeout.is_zero()).then_some(disabled.idle_timeout),
            None
        );

        let bare_secs = Cli::try_parse_from(["keyroost-agent", "--idle-timeout", "45"]).unwrap();
        assert_eq!(bare_secs.idle_timeout, Duration::from_secs(45));

        let one_hour = Cli::try_parse_from(["keyroost-agent", "--idle-timeout", "1h"]).unwrap();
        assert_eq!(one_hour.idle_timeout, Duration::from_secs(3600));

        assert!(Cli::try_parse_from(["keyroost-agent", "--idle-timeout", "bogus"]).is_err());
    }

    #[test]
    fn cli_parses_all_applet_and_connection_variants() {
        for (applet_arg, expected_applet) in [
            ("auto", AppletSelection::Auto),
            ("piv", AppletSelection::Piv),
            ("openpgp", AppletSelection::OpenPgp),
            ("both", AppletSelection::Both),
        ] {
            for (conn_arg, expected_conn) in [
                ("auto", ConnectionSelection::Auto),
                ("persistent", ConnectionSelection::Persistent),
                ("ephemeral", ConnectionSelection::Ephemeral),
            ] {
                let cli = Cli::try_parse_from([
                    "keyroost-agent",
                    "--applet",
                    applet_arg,
                    "--connection",
                    conn_arg,
                ])
                .unwrap();
                assert_eq!(cli.applet, expected_applet);
                assert_eq!(cli.connection, expected_conn);
            }
        }
    }

    #[test]
    fn explicit_piv_selection() {
        assert_eq!(
            resolve_config(
                AppletSelection::Piv,
                ConnectionSelection::Auto,
                true,
                true,
                false,
                true,
            ),
            Ok(ResolvedConfig {
                use_piv: true,
                use_openpgp: false,
                connection_mode: ConnectionMode::Persistent,
            })
        );
        assert_eq!(
            resolve_config(
                AppletSelection::Piv,
                ConnectionSelection::Persistent,
                true,
                false,
                false,
                false,
            ),
            Ok(ResolvedConfig {
                use_piv: true,
                use_openpgp: false,
                connection_mode: ConnectionMode::Persistent,
            })
        );
        assert_eq!(
            resolve_config(
                AppletSelection::Piv,
                ConnectionSelection::Ephemeral,
                true,
                true,
                true,
                true,
            ),
            Ok(ResolvedConfig {
                use_piv: true,
                use_openpgp: false,
                connection_mode: ConnectionMode::Ephemeral,
            })
        );

        let err = resolve_config(
            AppletSelection::Piv,
            ConnectionSelection::Auto,
            false,
            true,
            false,
            true,
        )
        .unwrap_err();
        assert!(err.contains("--applet=piv"));
    }

    #[test]
    fn explicit_openpgp_selection() {
        assert_eq!(
            resolve_config(
                AppletSelection::OpenPgp,
                ConnectionSelection::Auto,
                true,
                true,
                true,
                false,
            ),
            Ok(ResolvedConfig {
                use_piv: false,
                use_openpgp: true,
                connection_mode: ConnectionMode::Persistent,
            })
        );
        assert_eq!(
            resolve_config(
                AppletSelection::OpenPgp,
                ConnectionSelection::Persistent,
                false,
                true,
                false,
                true,
            ),
            Ok(ResolvedConfig {
                use_piv: false,
                use_openpgp: true,
                connection_mode: ConnectionMode::Persistent,
            })
        );
        assert_eq!(
            resolve_config(
                AppletSelection::OpenPgp,
                ConnectionSelection::Ephemeral,
                true,
                true,
                true,
                true,
            ),
            Ok(ResolvedConfig {
                use_piv: false,
                use_openpgp: true,
                connection_mode: ConnectionMode::Ephemeral,
            })
        );

        let err = resolve_config(
            AppletSelection::OpenPgp,
            ConnectionSelection::Auto,
            true,
            false,
            true,
            false,
        )
        .unwrap_err();
        assert!(err.contains("--applet=openpgp"));
    }

    #[test]
    fn explicit_both_selection() {
        assert_eq!(
            resolve_config(
                AppletSelection::Both,
                ConnectionSelection::Auto,
                true,
                true,
                true,
                false,
            ),
            Ok(ResolvedConfig {
                use_piv: true,
                use_openpgp: true,
                connection_mode: ConnectionMode::Ephemeral,
            })
        );
        assert_eq!(
            resolve_config(
                AppletSelection::Both,
                ConnectionSelection::Ephemeral,
                true,
                true,
                false,
                false,
            ),
            Ok(ResolvedConfig {
                use_piv: true,
                use_openpgp: true,
                connection_mode: ConnectionMode::Ephemeral,
            })
        );

        let persistent_err = resolve_config(
            AppletSelection::Both,
            ConnectionSelection::Persistent,
            true,
            true,
            true,
            true,
        )
        .unwrap_err();
        assert!(persistent_err.contains("PIN verification"));
        assert!(persistent_err.contains("--applet=piv"));
        assert!(persistent_err.contains("--applet=openpgp"));
        assert!(persistent_err.contains("--connection=ephemeral"));

        for (has_piv, has_openpgp) in [(false, true), (true, false), (false, false)] {
            let err = resolve_config(
                AppletSelection::Both,
                ConnectionSelection::Auto,
                has_piv,
                has_openpgp,
                has_piv,
                has_openpgp,
            )
            .unwrap_err();
            assert!(err.contains("--applet=both"));
        }
    }

    #[test]
    fn auto_applet_selects_only_piv_when_only_piv_has_identities() {
        assert_eq!(
            resolve_config(
                AppletSelection::Auto,
                ConnectionSelection::Auto,
                true,
                true,
                true,
                false,
            ),
            Ok(ResolvedConfig {
                use_piv: true,
                use_openpgp: false,
                connection_mode: ConnectionMode::Persistent,
            })
        );
        assert_eq!(
            resolve_config(
                AppletSelection::Auto,
                ConnectionSelection::Persistent,
                true,
                true,
                true,
                false,
            ),
            Ok(ResolvedConfig {
                use_piv: true,
                use_openpgp: false,
                connection_mode: ConnectionMode::Persistent,
            })
        );
        assert_eq!(
            resolve_config(
                AppletSelection::Auto,
                ConnectionSelection::Ephemeral,
                true,
                true,
                true,
                false,
            ),
            Ok(ResolvedConfig {
                use_piv: true,
                use_openpgp: false,
                connection_mode: ConnectionMode::Ephemeral,
            })
        );
    }

    #[test]
    fn auto_applet_selects_only_openpgp_when_only_openpgp_has_identities() {
        assert_eq!(
            resolve_config(
                AppletSelection::Auto,
                ConnectionSelection::Auto,
                true,
                true,
                false,
                true,
            ),
            Ok(ResolvedConfig {
                use_piv: false,
                use_openpgp: true,
                connection_mode: ConnectionMode::Persistent,
            })
        );
        assert_eq!(
            resolve_config(
                AppletSelection::Auto,
                ConnectionSelection::Persistent,
                true,
                true,
                false,
                true,
            ),
            Ok(ResolvedConfig {
                use_piv: false,
                use_openpgp: true,
                connection_mode: ConnectionMode::Persistent,
            })
        );
        assert_eq!(
            resolve_config(
                AppletSelection::Auto,
                ConnectionSelection::Ephemeral,
                true,
                true,
                false,
                true,
            ),
            Ok(ResolvedConfig {
                use_piv: false,
                use_openpgp: true,
                connection_mode: ConnectionMode::Ephemeral,
            })
        );
    }

    #[test]
    fn auto_applet_selects_both_when_both_have_identities() {
        assert_eq!(
            resolve_config(
                AppletSelection::Auto,
                ConnectionSelection::Auto,
                true,
                true,
                true,
                true,
            ),
            Ok(ResolvedConfig {
                use_piv: true,
                use_openpgp: true,
                connection_mode: ConnectionMode::Ephemeral,
            })
        );
        assert_eq!(
            resolve_config(
                AppletSelection::Auto,
                ConnectionSelection::Ephemeral,
                true,
                true,
                true,
                true,
            ),
            Ok(ResolvedConfig {
                use_piv: true,
                use_openpgp: true,
                connection_mode: ConnectionMode::Ephemeral,
            })
        );

        let err = resolve_config(
            AppletSelection::Auto,
            ConnectionSelection::Persistent,
            true,
            true,
            true,
            true,
        )
        .unwrap_err();
        assert!(err.contains("PIN verification"));
        assert!(err.contains("--connection=ephemeral"));
    }

    #[test]
    fn auto_applet_keeps_both_when_neither_has_identities() {
        assert_eq!(
            resolve_config(
                AppletSelection::Auto,
                ConnectionSelection::Auto,
                true,
                true,
                false,
                false,
            ),
            Ok(ResolvedConfig {
                use_piv: true,
                use_openpgp: true,
                connection_mode: ConnectionMode::Ephemeral,
            })
        );
        assert!(
            resolve_config(
                AppletSelection::Auto,
                ConnectionSelection::Persistent,
                true,
                true,
                false,
                false,
            )
            .is_err()
        );
        assert_eq!(
            resolve_config(
                AppletSelection::Auto,
                ConnectionSelection::Ephemeral,
                true,
                true,
                false,
                false,
            ),
            Ok(ResolvedConfig {
                use_piv: true,
                use_openpgp: true,
                connection_mode: ConnectionMode::Ephemeral,
            })
        );
    }

    #[test]
    fn auto_applet_keeps_single_present_applet_when_neither_has_identities() {
        for (has_piv, has_openpgp) in [(true, false), (false, true)] {
            for (connection, expected_mode) in [
                (ConnectionSelection::Auto, ConnectionMode::Persistent),
                (ConnectionSelection::Persistent, ConnectionMode::Persistent),
                (ConnectionSelection::Ephemeral, ConnectionMode::Ephemeral),
            ] {
                assert_eq!(
                    resolve_config(
                        AppletSelection::Auto,
                        connection,
                        has_piv,
                        has_openpgp,
                        false,
                        false,
                    ),
                    Ok(ResolvedConfig {
                        use_piv: has_piv,
                        use_openpgp: has_openpgp,
                        connection_mode: expected_mode,
                    })
                );
            }
        }
    }

    #[test]
    fn auto_applet_errors_when_no_applets_present() {
        assert!(
            resolve_config(
                AppletSelection::Auto,
                ConnectionSelection::Auto,
                false,
                false,
                false,
                false,
            )
            .is_err()
        );
    }
}
