{
  pkgs,
  sftcrd,
  keyroostctl,
  keyroost-agent,
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
  ];

  mkCheck =
    suite: test: {
      name = "e2e-${suite}-${test}";
      value = pkgs.testers.runNixOSTest {

        name = "e2e-${suite}-${test}";

        imports = [
          (./. + "/${suite}/${test}.nix")
        ];

        sshBackdoor.enable = true;

        nodes = {
          host =
            { pkgs, ... }:
            {
              imports = [ nixosModule ];

              services.sftcrd = {
                enable = true;
                log-level = "trace";
              };

              environment.systemPackages = [
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
      map
        (name: mkCheck suite (pkgs.lib.strings.removeSuffix ".nix" name))
        (builtins.attrNames (builtins.readDir (./. + "/${suite}")))
    ) suites
  )
)
