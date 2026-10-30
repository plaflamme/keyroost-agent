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
    keyroost.url = "github:framefilter/keyroost/v0.14.0";
  };

  outputs =
    inputs@{ flake-parts, keyroost, ... }:
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
          system,
          pkgs,
          ...
        }:
        let
          keyroost-piv-applet = config.packages.keyroost-piv-applet;
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
            default = config.packages.keyroost-agent;
          };

          checks = {
            piv-info = pkgs.callPackage ./nix/checks/piv-info.nix {
              inherit keyroost keyroost-piv-applet system;
            };
            piv-pin-change = pkgs.callPackage ./nix/checks/piv-pin-change.nix {
              inherit keyroost keyroost-piv-applet system;
            };
            piv-puk-change = pkgs.callPackage ./nix/checks/piv-puk-change.nix {
              inherit keyroost keyroost-piv-applet system;
            };
            piv-pin-block = pkgs.callPackage ./nix/checks/piv-pin-block.nix {
              inherit keyroost keyroost-piv-applet system;
            };
            piv-reset = pkgs.callPackage ./nix/checks/piv-reset.nix {
              inherit keyroost keyroost-piv-applet system;
            };
            piv-algorithms = pkgs.callPackage ./nix/checks/piv-algorithms.nix {
              inherit keyroost keyroost-piv-applet system;
            };
            piv-multi-slot = pkgs.callPackage ./nix/checks/piv-multi-slot.nix {
              inherit keyroost keyroost-piv-applet system;
            };
            piv-attest = pkgs.callPackage ./nix/checks/piv-attest.nix {
              inherit keyroost keyroost-piv-applet system;
            };
          };

          devShells.default = config.devShells.rust;
        };
    };
}
