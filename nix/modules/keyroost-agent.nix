{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.keyroost-agent;
in
{
  options.services.keyroost-agent = {
    enable = lib.mkEnableOption "the socket-activated keyroost-agent systemd user service";

    package = lib.mkOption {
      type = lib.types.package;
      description = "The keyroost-agent package to use.";
    };

    socket = lib.mkOption {
      type = lib.types.str;
      default = "keyroost-agent/ssh.socket";
      example = "keyroost-agent/my.socket";
      description = ''
        The SSH agent's socket; interpreted as a suffix to {env}`$XDG_RUNTIME_DIR`
        on Linux.
      '';
    };

    reader = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = ''
        Smart-card reader whose name contains this text (case-insensitive).
      '';
    };

    applets = lib.mkOption {
      type = lib.types.enum [
        "auto"
        "piv"
        "openpgp"
        "both"
      ];
      default = "auto";
      description = ''
        Smart-card applet selection passed via {option}`--applet`.
        `"auto"` enables applets that have usable SSH identities; `"piv"`,
        `"openpgp"`, and `"both"` explicitly select the corresponding applet(s).
      '';
    };

    connection = lib.mkOption {
      type = lib.types.enum [
        "auto"
        "persistent"
        "ephemeral"
      ];
      default = "auto";
      description = ''
        Smart-card connection mode passed via {option}`--connection`.
        `"auto"` uses `"persistent"` when a single applet is active and
        `"ephemeral"` when both applets are active.
      '';
    };

    idleTimeout = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "30m";
      description = ''
        Idle timeout after which persistent smart-card sessions are released,
        passed via {option}`--idle-timeout` (for example `"30s"`, `"30m"`,
        `"1h"`, or `"0"` to disable).
      '';
    };

    pinentry = {
      package = lib.mkPackageOption pkgs "pinentry-gnome3" {
        nullable = true;
        default = null;
        extraDescription = ''
          Which pinentry interface to use. If not `null`, it sets the
          {option}`--pinentry` command line option.
        '';
      };

      program = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        example = "pinentry-wayprompt";
        description = ''
          Which program to search for in the configured `pinentry.package`.
        '';
      };
    };

    pinCache = {
      mode = lib.mkOption {
        type = lib.types.enum [
          "none"
          "memory"
          "pinentry"
        ];
        default = "none";
        description = ''
          PIN caching strategy passed via {option}`--pin-cache`.
          `"none"` disables caching; `"memory"` caches PINs in process memory
          for the configured TTL; `"pinentry"` delegates PIN caching to
          `pinentry`'s external password cache (for example GNOME Keyring,
          KWallet, or macOS Keychain).
        '';
      };

      ttl = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "10m";
        description = ''
          Sliding TTL for cached PINs passed via {option}`--pin-cache-ttl`
          (for example `"30s"`, `"10m"`, `"1h"`).
        '';
      };

      maxTtl = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "1h";
        description = ''
          Optional absolute maximum lifetime for cached PINs passed via
          {option}`--pin-cache-max-ttl` (`"0"` disables the cap).
        '';
      };
    };
  };

  config = lib.mkIf cfg.enable {
    # Grab the default binary name and fallback to expected value if `meta.mainProgram` not set
    services.keyroost-agent.pinentry.program = lib.mkOptionDefault (
      cfg.pinentry.package.meta.mainProgram or "pinentry"
    );

    home.packages = [ cfg.package ];

    sshAuthSock = {
      enable = true;
      initialization =
        let
          socketPath = "\${XDG_RUNTIME_DIR}/${cfg.socket}";
        in
        {
          bash = ''export SSH_AUTH_SOCK="${socketPath}"'';
          fish = ''set -x SSH_AUTH_SOCK "${socketPath}"'';
          nushell = "$env.SSH_AUTH_SOCK = $env.XDG_RUNTIME_DIR/${cfg.socket}";
        };
      systemd.socketProviderUnit = "keyroost-agent.service";
    };

    systemd.user = {
      sockets."keyroost-agent" = {
        Unit.Description = "keyroost-agent socket activation";
        # systemd specifier syntax; %t is the user runtime directory ($XDG_RUNTIME_DIR)
        Socket.ListenStream = [ "%t/${cfg.socket}" ];
        Install.WantedBy = [ "sockets.target" ];
      };

      services."keyroost-agent" = {
        Unit = {
          Description = "keyroost-agent service";
          Requires = "keyroost-agent.socket";
          After = "keyroost-agent.socket";
          RefuseManualStart = true;
        };
        Service = {
          ExecStart = lib.concatStringsSep " " (
            [ "${cfg.package}/bin/keyroost-agent" ]
            ++ lib.optional (cfg.reader != null) "--reader=${lib.escapeShellArg cfg.reader}"
            ++ lib.optional (cfg.applets != "auto") "--applet=${cfg.applets}"
            ++ lib.optional (cfg.connection != "auto") "--connection=${cfg.connection}"
            ++ lib.optional (
              cfg.idleTimeout != null
            ) "--idle-timeout=${lib.escapeShellArg cfg.idleTimeout}"
            ++ lib.optional (
              cfg.pinentry.package != null
            ) "--pinentry=${lib.getExe' cfg.pinentry.package cfg.pinentry.program}"
            ++ lib.optional (cfg.pinCache.mode != "none") "--pin-cache=${cfg.pinCache.mode}"
            ++ lib.optional (
              cfg.pinCache.ttl != null
            ) "--pin-cache-ttl=${lib.escapeShellArg cfg.pinCache.ttl}"
            ++ lib.optional (
              cfg.pinCache.maxTtl != null
            ) "--pin-cache-max-ttl=${lib.escapeShellArg cfg.pinCache.maxTtl}"
          );
        };
      };
    };
  };
}
