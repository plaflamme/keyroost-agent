{
  pkgs,
  keyroost,
  keyroost-piv-applet,
  system,
}:

# Helper function to create a PIV test check
# Usage: make-piv-check { name = "test-name"; testScript = '' ... ''; }
# Each check only needs to define its testScript - the rest is boilerplate

{ name, testScript }:

let
  commonSetup = ''
    start_all()
    host.wait_for_unit("pcscd.socket")
    host.wait_for_unit("piv-vsmartcard.service")

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
in
pkgs.testers.runNixOSTest {
  inherit name;
  sshBackdoor.enable = true;
  nodes = {
    host =
      { pkgs, ... }:
      {
        services.pcscd.enable = true;
        services.vsmartcard-vpcd.enable = true;
        services.vsmartcard-vpcd.hostname = "127.0.0.1";

        environment.systemPackages = [
          pkgs.openssl
          pkgs.yubico-piv-tool
          keyroost.packages.${system}.keyroostctl
        ];

        systemd.services.piv-vsmartcard = {
          wantedBy = [ "multi-user.target" ];
          serviceConfig = {
            Environment = "RUST_LOG=trace";
            ExecStart = "${keyroost-piv-applet}/bin/piv-vsmartcard";
          };
        };
      };
  };
  testScript = commonSetup + testScript;
}
