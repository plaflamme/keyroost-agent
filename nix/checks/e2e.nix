{
  pkgs,
  sftcrd,
  home-manager,
  keyroostctl,
  keyroost-agent,
  keyroostAgentModule,
  system,
  ...
}:
let
  nixosModule = sftcrd.nixosModules.sftcrd;

  mockPinentry = pkgs.writeScriptBin "pinentry" ''
    #!${pkgs.python3}/bin/python3
    import fcntl
    import os
    import sys

    responses_path = os.environ.get("MOCK_PINENTRY_RESPONSES", "/tmp/pinentry-responses")
    log_path = os.environ.get("MOCK_PINENTRY_LOG", "/tmp/pinentry-commands.log")


    def reply(line: str) -> None:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()


    def log_command(line: str) -> None:
        if not log_path:
            return
        try:
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError:
            pass


    def pop_response() -> tuple[str | None, str | None]:
        if not os.path.exists(responses_path):
            return None, "ERR 83886179 Mock pinentry response file missing"

        with open(responses_path, "r+", encoding="utf-8") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            lines = f.read().splitlines()
            if not lines:
                return None, "ERR 83886179 Mock pinentry response file exhausted"
            first, rest = lines[0], lines[1:]
            f.seek(0)
            f.truncate()
            if rest:
                f.write("\n".join(rest) + "\n")
            f.flush()
            return first, None


    reply("OK Pleased to meet you")

    for raw_line in sys.stdin:
        line = raw_line.rstrip("\r\n")
        if not line:
            continue

        log_command(line)
        cmd = line.split(" ", 1)[0].upper()

        if cmd == "BYE":
            reply("OK closing connection")
            break
        elif cmd == "GETPIN":
            entry, err = pop_response()
            if err is not None:
                reply(err)
            elif entry.startswith("ERR "):
                reply(entry)
            elif entry == "":
                reply("OK")
            else:
                encoded = entry.replace("%", "%25")
                reply(f"D {encoded}")
                reply("OK")
        else:
            reply("OK")
  '';
  suites = [
    "piv"
    "openpgp"
    "dual"
    "gpg"
  ];

  mkCheck = name: path: {
    inherit name;
    value = pkgs.testers.runNixOSTest {

      inherit name;

      imports = [
        path
      ];

      sshBackdoor.enable = true;

      nodes = {
        host =
          {
            config,
            lib,
            pkgs,
            ...
          }:
          {
            imports = [
              nixosModule
              home-manager.nixosModules.home-manager
            ];

            home-manager.useGlobalPkgs = true;
            home-manager.users = lib.mkIf (config.users.users ? testuser) {
              testuser = {
                imports = [ keyroostAgentModule ];
                home.stateVersion = "26.11";
                programs.bash.enable = true;
                services.keyroost-agent = {
                  package = keyroost-agent;
                  pinentry.package = lib.mkDefault mockPinentry;
                };
              };
            };

            services.sftcrd = {
              enable = true;
              log-level = "trace";
            };

            environment.systemPackages = [
              pkgs.gnupg
              pkgs.openssl
              pkgs.openssh
              pkgs.yubico-piv-tool
              keyroostctl
              keyroost-agent
              mockPinentry
            ];
          };
      };

      testScript = pkgs.lib.mkBefore ''
        start_all()
        host.wait_for_unit("pcscd.socket")
        host.wait_for_unit("sftcrd.service")

        def keyroostctl(args, pin="123456", admin_pin="12345678", mgmt="010203040506070801020304050607080102030405060708", **kwargs):
            env_parts = []
            if pin:
                env_parts.append(f"PIN={pin}")
            if admin_pin:
                env_parts.append(f"ADMIN_PIN={admin_pin}")
            if mgmt:
                env_parts.append(f"MGMT={mgmt}")
            for key, value in kwargs.items():
                env_parts.append(f"{key}={value}")
            env_str = " ".join(env_parts) + " " if env_parts else ""
            cmd = f"{env_str}keyroostctl {args}"
            return host.succeed(cmd)
      '';
    };
  };
in
pkgs.lib.optionalAttrs (system == "x86_64-linux") (
  builtins.listToAttrs (
    pkgs.lib.concatMap (
      suite:
      map (
        name:
        let
          test = pkgs.lib.strings.removeSuffix ".nix" name;
        in
        mkCheck "e2e-${suite}-${test}" (./. + "/${suite}/${name}")
      ) (builtins.attrNames (builtins.readDir (./. + "/${suite}")))
    ) suites
    ++ [
      (mkCheck "e2e-pin-cache" ./pin-cache.nix)
      (mkCheck "e2e-pinentry-cache" ./pinentry-cache.nix)
    ]
  )
)
