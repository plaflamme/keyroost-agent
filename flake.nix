{
  nixConfig = {
    extra-substituters = [ "https://keyroost-agent.cachix.org" ];
    extra-trusted-public-keys = [
      "keyroost-agent.cachix.org-1:nrFszUmhznRvl52Zes9nEhgu7NjjJt/otBRAILg2Uo0="
    ];
  };
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    rust-flake = {
      url = "github:juspay/rust-flake";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.rust-overlay.follows = "rust-overlay";
    };
  };

  outputs =
    inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {

      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];

      imports = [
        inputs.rust-flake.flakeModules.default
        inputs.rust-flake.flakeModules.nixpkgs
      ];

      perSystem =
        {
          config,
          pkgs,
          ...
        }:
        let
          jcardengine = pkgs.callPackage ./nix/jcardengine.nix { };
        in
        {
          rust-project = {
            crates = {
              # The workspace root package is not in `members`, so
              # rust-flake does not find it on its own; point it at the
              # workspace source explicitly.
              keyroost-agent =
                { rust-project, ... }:
                {
                  path = rust-project.src + "/";
                  crane = {
                    extraBuildArgs = {
                      CARGO_PROFILE = "dev"; # TODO: how do we output both release and dev profiles?
                    };
                    args = {
                      nativeBuildInputs = with pkgs; [
                        pkg-config
                      ];
                      buildInputs = [ pkgs.pcsclite ];
                    };
                  };
                };
            };
          };

          packages = {
            # default = config.packages.keyroost-agent;
            jcardengine = jcardengine;
          };

          checks = {
            piv-vsmartcard = pkgs.testers.runNixOSTest {
              name = "piv-vsmartcard";
              nodes = {
                host =
                  { pkgs, ... }:
                  {
                    # The PC/SC stack: the resource manager plus the
                    # VSmartCard reader driver, which listens on its default
                    # port (35963) for a vpicc to connect to.
                    services.pcscd.enable = true;
                    services.vsmartcard-vpcd.enable = true;

                    # The vpicc side: our PIV applet front end, which
                    # connects to that listener and answers as a card.
                    systemd.services.piv-vsmartcard = {
                      wantedBy = [ "multi-user.target" ];
                      serviceConfig = {
                        ExecStart = "${config.packages.keyroost-piv-applet}/bin/piv-vsmartcard";
                      };
                    };
                  };
              };
              testScript = ''
                start_all()

                # pcscd is socket-activated: the socket unit is what is
                # active at boot; the service itself only starts on the
                # first PC/SC client.
                host.wait_for_unit("pcscd.socket")
                host.wait_for_unit("piv-vsmartcard.service")
              '';
            };
          };

          devShells.default = config.devShells.rust;
        };
    };
}
