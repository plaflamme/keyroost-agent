{
  pkgs,
  sftcrd,
  keyroostctl,
  system,
  ...
}:
let
  nixosModule = sftcrd.nixosModules.sftcrd;
in
pkgs.lib.optionalAttrs (system == "x86_64-linux") (
  builtins.listToAttrs (
    map
      (test: {
        name = "piv-${test}";
        value = pkgs.testers.runNixOSTest {

          name = "piv-${test}";

          imports = [
            ./piv/${test}.nix
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
                  pkgs.yubico-piv-tool
                  keyroostctl
                ];
              };
          };

          testScript = pkgs.lib.mkBefore ''
            start_all()
            host.wait_for_unit("pcscd.socket")
            host.wait_for_unit("sftcrd.service")

            def keyroostctl(args, pin="123456", mgmt="010203040506070801020304050607080102030405060708", **kwargs):
                env_parts = []
                if pin:
                    env_parts.append(f"PIN={pin}")
                if mgmt:
                    env_parts.append(f"MGMT={mgmt}")
                for key, value in kwargs.items():
                    env_parts.append(f"{key}={value}")
                env_str = " ".join(env_parts) + " " if env_parts else ""
                cmd = f"{env_str}keyroostctl {args}"
                return host.succeed(cmd)
          '';
        };
      })
      (
        map (name: pkgs.lib.strings.removeSuffix ".nix" name) (builtins.attrNames (builtins.readDir ./piv))
      )
  )
)
