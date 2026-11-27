{ pkgs, ... }:
let
  fingerprint = "9066F10B3F48BCE71A0FDC0C59A2FDBC66890257";
  authPubKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINnYa/XzYq+b+X2R2wwNveKcMe78zwwsunZGqFTntDzD";
  signPubKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG6KghqhNGgMulMRdw6OkCLc+LQxjSEgGm81uqf12y52";
  authPubFile = pkgs.writeText "openpgp-auth.pub" "${authPubKey}\n";
  authAllowedSigners = pkgs.writeText "allowed_signers_auth" "auth@example ${authPubKey}\n";
  pubKeyFile = pkgs.writeText "test-gpg-pub.asc" ''
    -----BEGIN PGP PUBLIC KEY BLOCK-----

    mDMEawnGFRYJKwYBBAHaRw8BAQdAboqCGqE0aAy6UxF3Do6QItz4tDGNISAabzW6
    p/XbLna0HFRlc3QgVXNlciA8dGVzdEBleGFtcGxlLmNvbT6IkAQTFgoAOBYhBJBm
    8Qs/SLznGg/cDFmi/bxmiQJXBQJrCcYVAhsDBQsJCAcCBhUKCQgLAgQWAgMBAh4B
    AheAAAoJEFmi/bxmiQJXznoA/05VHpnr77N5ghf/Ig5x39Tky0LBVDfe8ZaJ14hN
    TXMGAP43wyNk4TsMmGUaMB0lLkIJlwPfcWKVRbeJR0rqJTD2Drg4BGsJxhUSCisG
    AQQBl1UBBQEBB0BJHMSJzrMAq0mpwrC+GjLILqsgftMDR/khsZQ1e+FdDgMBCAeI
    eAQYFgoAIBYhBJBm8Qs/SLznGg/cDFmi/bxmiQJXBQJrCcYVAhsMAAoJEFmi/bxm
    iQJXAVIBAM3SPn5ZZo4FGeMPka9NdY5GMR3LkjC/30ouKYIE7S3oAP43UkM+Dr1M
    t8sQvvywMmeSXN/VKTELbvThx2/H3JC4BrgzBGsJxhUWCSsGAQQB2kcPAQEHQNnY
    a/XzYq+b+X2R2wwNveKcMe78zwwsunZGqFTntDzDiHgEGBYKACAWIQSQZvELP0i8
    5xoP3AxZov28ZokCVwUCawnGFQIbIAAKCRBZov28ZokCV2p6AQCeT/+4veXBFQAO
    qxNjJXj0l86EakasjaRX7OFv8J0sXgEAyWa16q1CU1J9zsyLPDCApBA5TY0znjGb
    +ZwudD7aogM=
    =PolJ
    -----END PGP PUBLIC KEY BLOCK-----
  '';
in
{
  nodes.host = {
    users.users.testuser = {
      isNormalUser = true;
      linger = true;
    };

    # Ensure Home Manager links user systemd socket units before linger-users starts user@1000.
    systemd.services."home-manager-testuser".before = [ "linger-users.service" ];

    home-manager.users.testuser.services.keyroost-agent = {
      enable = true;
      ssh.enable = true;
      gpg.enable = true;
      applets = "openpgp";
      connection = "persistent";
    };

    services.sftcrd.config = {
      pgp.slots = {
        sign.key = ''
          -----BEGIN PRIVATE KEY-----
          MC4CAQAwBQYDK2VwBCIEIPKfAnomN2aIqLDYpfKVtY44p0gk3dIeL+8i2z5Lxdkn
          -----END PRIVATE KEY-----
        '';
        decrypt.key = ''
          -----BEGIN PRIVATE KEY-----
          MC4CAQAwBQYDK2VuBCIEIMCMq/pbF7AsGLIKD1QloZBXh9VWQw5cYxaYt9WzQqVr
          -----END PRIVATE KEY-----
        '';
        auth.key = ''
          -----BEGIN PRIVATE KEY-----
          MC4CAQAwBQYDK2VwBCIEIDug8A3YmeARd48UCJZ/SeoZEw5hyuygyXbcF5scdEsw
          -----END PRIVATE KEY-----
        '';
      };
    };
  };

  testScript =
    { ... }:
    let
      bash = command: "XDG_RUNTIME_DIR=/run/user/1000 bash -il -c ${pkgs.lib.escapeShellArg command}";
      su = command: "su - testuser -c ${pkgs.lib.escapeShellArg (bash command)}";
      toPythonString = string: builtins.toJSON string;
    in
    ''
      host.wait_for_unit("user@1000.service")
      host.wait_for_unit("home-manager-testuser.service")
      host.wait_for_unit("keyroost-agent-ssh.socket", "testuser")
      host.wait_for_unit("keyroost-agent-gpg.socket", "testuser")

      ssh_socket = "/run/user/1000/keyroost-agent/ssh.socket"
      gpg_socket = "/run/user/1000/gnupg/S.gpg-agent"
      host.wait_for_file(ssh_socket)
      host.wait_for_file(gpg_socket)

      assert host.succeed(${toPythonString (su "printf %s $SSH_AUTH_SOCK")}) == ssh_socket
      assert host.succeed(${toPythonString (su "gpgconf --list-dirs agent-socket")}).strip() == gpg_socket

      # Import only the public OpenPGP key into testuser's default GNUPGHOME
      # Pre-create ~/.gnupg so GnuPG 2.4 uses pubring.kbx instead of enabling keyboxd.
      host.succeed(${toPythonString (su ''mkdir -p "$HOME/.gnupg" && chmod 700 "$HOME/.gnupg"'')})
      host.succeed(${toPythonString (su "gpg --batch --no-autostart --import ${pubKeyFile}")})
      host.succeed(
          ${toPythonString (su ''test ! -d "$HOME/.gnupg/private-keys-v1.d" || [ -z "$(ls -A "$HOME/.gnupg/private-keys-v1.d")" ]'')}
      )

      # 1. SSH: ssh-add -L triggers socket activation and lists Auth + Sign identities
      identities = host.succeed(${toPythonString (su "ssh-add -L")}).strip()
      expected_identities = "\n".join([
          "${authPubKey} OpenPGP 87654321:Auth",
          "${signPubKey} OpenPGP 87654321:Sign",
      ])
      assert identities == expected_identities, (
          f"Expected:\n{expected_identities!r}\nGot:\n{identities!r}"
      )

      agent_pid = host.succeed(
          ${toPythonString (su "systemctl --user show -p MainPID --value keyroost-agent.service")}
      ).strip()
      assert agent_pid.isdigit() and int(agent_pid) > 0, f"Invalid MainPID: {agent_pid!r}"

      # 2. SSH: ssh-keygen -Y sign and verify (verifies PW1_OTHER on the persistent session)
      host.succeed(${toPythonString (su "printf 'hello dual protocol\n' > /tmp/payload")})
      host.succeed(${toPythonString (su "printf '123456\n' > /tmp/pinentry-responses")})
      host.succeed(
          ${toPythonString (su "ssh-keygen -Y sign -f ${authPubFile} -n file /tmp/payload")}
      )
      host.succeed(
          ${toPythonString (su "ssh-keygen -Y verify -f ${authAllowedSigners} -I auth@example -n file -s /tmp/payload.sig < /tmp/payload")}
      )

      # 3. GPG: detach-sign and verify (verifies PW1_SIGN)
      host.succeed(${toPythonString (su "printf '123456\n' > /tmp/pinentry-responses")})
      host.succeed(
          ${toPythonString (su "gpg --batch --no-autostart --detach-sign -u ${fingerprint} -o /tmp/payload.asc /tmp/payload")}
      )
      host.succeed(
          ${toPythonString (su "gpg --batch --no-autostart --verify /tmp/payload.asc /tmp/payload")}
      )

      # 4. GPG: encrypt and decrypt (reuses verified PW1_OTHER on the same persistent session)
      host.succeed(
          ${toPythonString (su "gpg --batch --no-autostart --encrypt --trust-model always -r test@example.com -o /tmp/payload.gpg /tmp/payload")}
      )
      host.succeed(${toPythonString (su ": > /tmp/pinentry-responses")})
      host.succeed(
          ${toPythonString (su "gpg --batch --no-autostart --decrypt -o /tmp/decrypted /tmp/payload.gpg")}
      )
      host.succeed(${toPythonString (su "cmp /tmp/payload /tmp/decrypted")})

      # Confirm a single socket-activated keyroost-agent process handled all SSH + GPG operations
      final_pid = host.succeed(
          ${toPythonString (su "systemctl --user show -p MainPID --value keyroost-agent.service")}
      ).strip()
      assert final_pid == agent_pid, f"keyroost-agent PID changed from {agent_pid} to {final_pid}"

      # Verify pinentry was called twice: once for PW1_OTHER (SSH Auth, reused by GPG Decrypt)
      # and once for PW1_SIGN (GPG Sign)
      pinentry_log = host.succeed("cat /tmp/pinentry-commands.log")
      assert "SETDESC Please unlock OpenPGP card 87654321" in pinentry_log, (
          f"Missing SSH SETDESC in pinentry log:\n{pinentry_log}"
      )
      assert "Test User <test@example.com>" in pinentry_log, (
          f"Missing GPG SETDESC in pinentry log:\n{pinentry_log}"
      )
      assert pinentry_log.count("GETPIN") == 2, f"Expected 2 GETPIN calls, got:\n{pinentry_log}"
    '';
}
