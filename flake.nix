{
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

        in
        {
          rust-project = {
            crates = {
              keyroost-agent = {
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

          packages.default = config.packages.keyroost-agent;
          devShells.default = config.devShells.rust;
        };
    };
}
