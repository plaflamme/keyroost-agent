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
    keyroost.url = "github:framefilter/keyroost/v0.13.0";
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
              sshBackdoor.enable = true;
              nodes = {
                host =
                  { pkgs, ... }:
                  {
                    # The PC/SC stack: the resource manager plus the
                    # VSmartCard reader driver, which connects to the vpicc
                    # listener at 127.0.0.1 on its default port (35963)
                    # instead of listening itself.
                    services.pcscd.enable = true;
                    services.vsmartcard-vpcd.enable = true;
                    services.vsmartcard-vpcd.hostname = "127.0.0.1";

                    # A PC/SC client for the test to use.
                    environment.systemPackages = [
                      pkgs.opensc
                      keyroost.packages.${system}.keyroostctl
                    ];

                    # The vpicc side: our PIV applet front end, which
                    # listens on the default port (35963) and answers as a
                    # card.
                    systemd.services.piv-vsmartcard = {
                      wantedBy = [ "multi-user.target" ];
                      serviceConfig = {
                        Environment = "RUST_LOG=trace";
                        ExecStart = "${config.packages.keyroost-piv-applet}/bin/piv-vsmartcard";
                      };
                    };
                  };
              };
              testScript = ''
                start_all()
                host.wait_for_unit("pcscd.socket")
                host.wait_for_unit("piv-vsmartcard.service")

                # Read-only status: fingerprint, version, serial, PIN retries, slots.
                host.succeed("keyroostctl piv info")

                # PIN change: CHANGE REFERENCE verifies the old PIN.
                host.succeed("OLD=123456 NEW=654321 keyroostctl piv pin change --pin env:OLD --new-pin env:NEW")
                host.succeed("OLD=654321 NEW=123456 keyroostctl piv pin change --pin env:OLD --new-pin env:NEW")

                # PUK change: the same command with the PUK reference.
                host.succeed("OLD=12345678 NEW=87654321 keyroostctl piv puk change --puk env:OLD --new-puk env:NEW")
                host.succeed("OLD=87654321 NEW=12345678 keyroostctl piv puk change --puk env:OLD --new-puk env:NEW")

                # Block the PIN: five wrong old PINs, each burning one try.
                host.fail("BAD=000000 keyroostctl piv pin change --pin env:BAD --new-pin env:000000")
                host.fail("BAD=000000 keyroostctl piv pin change --pin env:BAD --new-pin env:000000")
                host.fail("BAD=000000 keyroostctl piv pin change --pin env:BAD --new-pin env:000000")
                host.fail("BAD=000000 keyroostctl piv pin change --pin env:BAD --new-pin env:000000")
                host.fail("BAD=000000 keyroostctl piv pin change --pin env:BAD --new-pin env:000000")

                # Unblock with the PUK (RESET RETRY COUNTER), then restore the factory PIN.
                host.succeed("PUK=12345678 NEW=654321 keyroostctl piv pin unblock --puk env:PUK --new-pin env:NEW")

                # Set the retry counts (Yubico 0xFA): needs the management key and the
                # verified PIN; also resets both credentials to factory values.
                host.succeed("PIN=654321 MGMT=010203040506070801020304050607080102030405060708 keyroostctl piv retries set --pin-tries 2 --puk-tries 2 --pin env:PIN --mgmt-key env:MGMT --yes")

                # Factory reset: the host burns the PIN and PUK counters itself, then sends RESET.
                host.succeed("keyroostctl piv reset --yes")

                # The card is back at factory state: the factory PIN and the factory
                # management key work again.
                host.succeed("PIN=123456 MGMT=010203040506070801020304050607080102030405060708 keyroostctl piv retries set --pin-tries 5 --puk-tries 3 --pin env:PIN --mgmt-key env:MGMT --yes")

                # --- Slot section (plan-06 T8): the end-to-end key-material pass. ---
                # The card is at factory state from the reset above: factory PIN,
                # factory management key, no keys, no certificates, no CHUID.

                # Empty card: slot 9A reports no key.
                host.succeed("keyroostctl piv info | grep -F 'authentication (9A)' | grep -q 'empty'")

                # Generate a P-256 key pair in 9A (management key only, no PIN).
                host.succeed("MGMT=010203040506070801020304050607080102030405060708 keyroostctl piv key generate --slot 9a --mgmt-key env:MGMT --yes")

                # Key present, no certificate yet.
                host.succeed("keyroostctl piv info | grep -F 'authentication (9A)' | grep -q 'key present, no certificate'")

                # Mint a self-signed certificate on the card from the public key
                # read through GET METADATA (9A's PIN policy is once, so the
                # on-card sign takes the PIN). Then the import/export round trip:
                # re-import the exported file and byte-compare the two exports.
                host.succeed("PIN=123456 MGMT=010203040506070801020304050607080102030405060708 keyroostctl piv cert generate --slot 9a --subject 'CN=VM-Test' --mgmt-key env:MGMT --pin env:PIN --yes")
                host.succeed("keyroostctl piv cert export --slot 9a --out /tmp/cert1.pem --overwrite")
                host.succeed("MGMT=010203040506070801020304050607080102030405060708 keyroostctl piv cert import --slot 9a --in /tmp/cert1.pem --mgmt-key env:MGMT --yes")
                host.succeed("keyroostctl piv cert export --slot 9a --out /tmp/cert2.pem --overwrite")
                host.succeed("cmp /tmp/cert1.pem /tmp/cert2.pem")

                # The stored certificate is readable and its public key matches
                # the card's key: piv test signs on the card and verifies.
                host.succeed("PIN=123456 keyroostctl piv test --slot 9a --pin env:PIN")

                # CHUID: write one, then see it in the status.
                host.succeed("MGMT=010203040506070801020304050607080102030405060708 keyroostctl piv chuid generate --mgmt-key env:MGMT")
                host.succeed("keyroostctl piv info | grep -q 'FASC-N'")

                # Move the key to 9C: the key and its policies move, the
                # certificate stays in 9A.
                host.succeed("MGMT=010203040506070801020304050607080102030405060708 keyroostctl piv key move --from 9a --to 9c --mgmt-key env:MGMT")
                host.succeed("keyroostctl piv info | grep -F 'authentication (9A)' | grep -q 'cert present'")
                host.succeed("keyroostctl piv info | grep -F 'signature (9C)' | grep -q 'key present, no certificate'")

                # Delete the moved key and the certificate: both slots empty again.
                host.succeed("MGMT=010203040506070801020304050607080102030405060708 keyroostctl piv key delete --slot 9c --mgmt-key env:MGMT --yes")
                host.succeed("MGMT=010203040506070801020304050607080102030405060708 keyroostctl piv cert delete --slot 9a --mgmt-key env:MGMT --yes")
                host.succeed("keyroostctl piv info | grep -F 'authentication (9A)' | grep -q 'empty'")
                host.succeed("keyroostctl piv info | grep -F 'signature (9C)' | grep -q 'empty'")
              '';
            };
          };

          devShells.default = config.devShells.rust;
        };
    };
}
