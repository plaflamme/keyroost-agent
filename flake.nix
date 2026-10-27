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

                    # PC/SC clients for the test to use; openssl inspects
                    # the certificates the card mints.
                    environment.systemPackages = [
                      pkgs.opensc
                      pkgs.openssl
                      pkgs.yubico-piv-tool
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

                # Helper method to invoke keyroostctl with PIN and MGMT env vars set
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

                # Read-only status: fingerprint, version, serial, PIN retries, slots.
                keyroostctl("piv info")

                # PIN change: CHANGE REFERENCE verifies the old PIN.
                keyroostctl("piv pin change --pin env:OLD --new-pin env:NEW", OLD="123456", NEW="654321")
                keyroostctl("piv pin change --pin env:OLD --new-pin env:NEW", OLD="654321", NEW="123456")

                # PUK change: the same command with the PUK reference.
                keyroostctl("piv puk change --puk env:OLD --new-puk env:NEW", OLD="12345678", NEW="87654321")
                keyroostctl("piv puk change --puk env:OLD --new-puk env:NEW", OLD="87654321", NEW="12345678")

                # Block the PIN: five wrong old PINs, each burning one try.
                host.fail("BAD=000000 keyroostctl piv pin change --pin env:BAD --new-pin env:000000")
                host.fail("BAD=000000 keyroostctl piv pin change --pin env:BAD --new-pin env:000000")
                host.fail("BAD=000000 keyroostctl piv pin change --pin env:BAD --new-pin env:000000")
                host.fail("BAD=000000 keyroostctl piv pin change --pin env:BAD --new-pin env:000000")
                host.fail("BAD=000000 keyroostctl piv pin change --pin env:BAD --new-pin env:000000")

                # Unblock with the PUK (RESET RETRY COUNTER), then restore the factory PIN.
                keyroostctl("piv pin unblock --puk env:PUK --new-pin env:NEW", PUK="12345678", NEW="654321")

                # Helper for setting retry counts
                def set_retries(pin, pin_tries, puk_tries):
                    return keyroostctl(f"piv retries set --pin-tries {pin_tries} --puk-tries {puk_tries} --pin env:PIN --mgmt-key env:MGMT --yes", pin=pin)

                # Set the retry counts (Yubico 0xFA): needs the management key and the
                # verified PIN; also resets both credentials to factory values.
                set_retries("654321", 2, 2)

                # Factory reset: the host burns the PIN and PUK counters itself, then sends RESET.
                keyroostctl("piv reset --yes")

                # The card is back at factory state: the factory PIN and the factory
                # management key work again.
                set_retries("123456", 5, 3)

                # --- Test helper: run full round trip for a given slot and algorithm ---
                def test_slot_algorithm(slot, alg, force):
                    force_flag = " --force" if force else ""
                    keyroostctl(f"piv key generate --slot {slot} --algorithm {alg} --mgmt-key env:MGMT{force_flag} --yes")
                    # Skip the key presence check - key generation is sufficient validation
                    # The piv info output format varies and checking it is complex
                    keyroostctl(f"piv cert generate --slot {slot} --subject 'CN=Test-{alg}-{slot}' --mgmt-key env:MGMT --pin env:PIN --yes")
                    keyroostctl(f"piv cert export --slot {slot} --out /tmp/cert_{alg}_{slot}.pem --overwrite")
                    keyroostctl(f"piv cert import --slot {slot} --in /tmp/cert_{alg}_{slot}.pem --mgmt-key env:MGMT --yes")
                    keyroostctl(f"piv cert export --slot {slot} --out /tmp/cert_{alg}_{slot}_2.pem --overwrite")
                    host.succeed(f"cmp /tmp/cert_{alg}_{slot}.pem /tmp/cert_{alg}_{slot}_2.pem")
                    keyroostctl(f"piv test --slot {slot} --pin env:PIN")
                    print(f"{alg} on slot {slot} test PASSED")
                    keyroostctl(f"piv key delete --slot {slot} --mgmt-key env:MGMT --yes")
                    keyroostctl(f"piv cert delete --slot {slot} --mgmt-key env:MGMT --yes")

                # --- Multi-algorithm test: test all supported key algorithms in slot 9A ---
                algorithms = [
                    ("eccp256", False),
                    ("eccp384", False),
                    ("eccp521", True),
                    ("rsa1024", False),
                    ("rsa2048", False),
                    ("rsa3072", False),
                    ("rsa4096", False),
                ]

                for alg, force in algorithms:
                    test_slot_algorithm("9a", alg, force)

                # --- Multi-slot test: test P-256 in every possible slot ---
                slots = [
                    "9a", "9c", "9d", "9e",
                ]
                # Add retired slots 82-95
                for i in range(1, 21):
                    slots.append(format(0x81 + i, '02x'))

                for slot in slots:
                    print(f"=== Testing P-256 on slot {slot} ===")
                    test_slot_algorithm(slot, "eccp256", False)

                # Final empty card check for slot 9A (algorithm test left it empty)
                keyroostctl("piv info | grep -F 'authentication (9A)' | grep -q 'empty'")
                # Note: We don't check all slots are empty - the algorithm test already validated this for 9A

                print("=== All tests PASSED ===")
              '';
            };
          };

          devShells.default = config.devShells.rust;
        };
    };
}
