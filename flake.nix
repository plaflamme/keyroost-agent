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
    keyroost.url = "github:framefilter/keyroost/v0.16.0";
    sftcrd.url = "github:plaflamme/sftcrd";
    home-manager = {
      url = "github:nix-community/home-manager";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    inputs@{
      flake-parts,
      keyroost,
      sftcrd,
      home-manager,
      ...
    }:
    let
      keyroostAgentModule =
        { lib, pkgs, ... }:
        {
          imports = [ ./nix/modules/keyroost-agent.nix ];
          services.keyroost-agent.package =
            lib.mkDefault inputs.self.packages.${pkgs.stdenv.hostPlatform.system}.keyroost-agent;
        };
    in
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

      flake.homeModules = {
        keyroost-agent = keyroostAgentModule;
        default = keyroostAgentModule;
      };

      perSystem =
        {
          config,
          system,
          pkgs,
          ...
        }@inputs:
        let
          keyroostctl = keyroost.packages.${system}.keyroostctl;
          eval = pkgs.lib.evalModules {
            specialArgs = { inherit pkgs; };
            modules = [
              keyroostAgentModule
              { _module.check = false; }
            ];
          };
          optionsDoc = pkgs.nixosOptionsDoc { options = eval.options; };
          craneLib = config.rust-project.crane-lib;
          src = config.rust-project.src;
          rustdoc = craneLib.cargoDoc (
            config.rust-project.crates.keyroost-agent.crane.args
            // {
              inherit src;
              pname = "keyroost-agent-rustdoc";
              cargoArtifacts = craneLib.buildDepsOnly (
                config.rust-project.crates.keyroost-agent.crane.args
                // {
                  inherit src;
                  pname = "keyroost-agent-rustdoc-deps";
                }
              );
              cargoDocExtraArgs = "--workspace --no-deps";
              RUSTDOCFLAGS = "-Z unstable-options --enable-index-page";
            }
          );
        in
        {
          rust-project = {
            crates = {
              keyroost-agent = {
                crane = {
                  args = {
                    nativeBuildInputs = [ pkgs.pkg-config ];
                    buildInputs = [ pkgs.pcsclite ];
                  };
                };
              };

            };
          };

          packages = {
            default = config.packages.keyroost-agent;
            docs = pkgs.callPackage ./nix/docs.nix {
              inherit optionsDoc rustdoc;
            };
            keyroost-agent-debug = craneLib.buildPackage (
              config.rust-project.crates.keyroost-agent.crane.args
              // {
                inherit src;
                pname = "keyroost-agent-debug";
                CARGO_PROFILE = "dev";
              }
            );
          };

          checks =
            let
              keyroost-agent = config.packages.keyroost-agent-debug;
              ctx = inputs // {
                inherit
                  sftcrd
                  home-manager
                  keyroostctl
                  keyroost-agent
                  keyroostAgentModule
                  ;
              };
            in
            { } // (import ./nix/checks/e2e.nix ctx) // (removeAttrs config.packages [ "default" ]);

          devShells.default = config.devShells.rust;
        };
    };
}
