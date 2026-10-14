{
  description = "Independent, vendor-neutral GUI and CLI for managing hardware security keys (FIDO2, OATH, OpenPGP, PIV, Token2 TOTP tokens)";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
  };

  outputs =
    inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];

      perSystem =
        {
          config,
          pkgs,
          ...
        }:
        let
          keyroostAgentCargo = fromTOML (builtins.readFile ./Cargo.toml);

          buildKeyroostPackage =
            extraBuildInputs: debug:
            pkgs.rustPlatform.buildRustPackage {
              pname = keyroostAgentCargo.package.name;
              version = keyroostAgentCargo.package.version;
              src = ./.;
              cargoLock = {
                lockFile = ./Cargo.lock;
              };

              buildType = if debug then "debug" else "release";
              dontStrip = debug;

              buildNoDefaultFeatures = true;

              nativeBuildInputs = with pkgs; [
                pkg-config
              ];

              buildInputs = [ pkgs.pcsclite ] ++ extraBuildInputs;

              postFixup = pkgs.lib.optionalString (pkgs.stdenv.hostPlatform.isLinux) ''
                patchelf \
                  --set-rpath "${pkgs.lib.makeLibraryPath ([ pkgs.pcsclite ] ++ extraBuildInputs)}" \
                  $out/bin/${keyroostAgentCargo.package.name}
              '';

              meta = {
                description = keyroostAgentCargo.package.description;
                homepage = "https://github.com/plaflamme/keyroost-agent";
                license = with pkgs.lib.licenses; [
                  mit
                  asl20
                ];
                platforms = pkgs.lib.platforms.unix;
              };
            };

          keyroostExtraBuildInputs = pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux (
            with pkgs;
            [
              libGL
              libx11
              libxcb
              libxcursor
              libxi
              libxkbcommon
              libxrandr
              wayland
            ]
          );

          buildKeyroostAgent = buildKeyroostPackage keyroostExtraBuildInputs;
        in
        {
          packages = {
            keyroostAgent = buildKeyroostAgent false;
            keyroostAgent-debug = buildKeyroostAgent true;

            default = config.packages.keyroostAgent;
          };

          devShells.default = pkgs.mkShell {
            inputsFrom = [
              config.packages.keyroostAgent
            ];

            buildInputs = with pkgs; [ udev ]; # keyroost-hid

            RUST_SRC_PATH = "${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";

            packages = with pkgs; [
              nixfmt
              nixd
              clippy
              rustfmt
              rust-analyzer
            ];
          };
        };
    };
}
