{ pkgs, ... }:
let
  pivPubKey = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBO23Pn1SC+Iz1QgYPfnqK8NMFcFRCJejr5d+EQpf6d361VcKPuIVCbUSjm5bBxR50zbCMSoXkhtquVPA3VWjuCw=";
  pgpAuthPubKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK1A88n4jUSTSIjnpgeRY7OsmY6+Xk4oSrR8SbHjeSnv";

  pivPubFile = pkgs.writeText "piv.pub" "${pivPubKey}\n";
  pgpAuthPubFile = pkgs.writeText "openpgp-auth.pub" "${pgpAuthPubKey}\n";
in
{
  nodes.host = {
    services.openssh = {
      enable = true;
      settings.PasswordAuthentication = false;
    };

    users.users.testuser = {
      isNormalUser = true;
      linger = true;
      openssh.authorizedKeys.keys = [
        pivPubKey
        pgpAuthPubKey
      ];
    };

    home-manager.users.testuser.services.keyroost-agent = {
      enable = true;
      pinCache.mode = "pinentry";
    };

    services.sftcrd.config = {
      piv.slots."9a" = {
        key = ''
          -----BEGIN PRIVATE KEY-----
          MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg5tzOZe/oBLnnHOJ1
          LTLhNrRwI+w/nXX4/rihQGF3yl2hRANCAATttz59UgviM9UIGD356ivDTBXBUQiX
          o6+XfhEKX+nd+tVXCj7iFQm1Eo5uWwcUedM2wjEqF5IbarlTwN1Vo7gs
          -----END PRIVATE KEY-----
        '';
        cert = ''
          -----BEGIN CERTIFICATE-----
          MIIBezCCASGgAwIBAgIUNTBafFkeqb+1kmWpCuUDhVdVS+UwCgYIKoZIzj0EAwIw
          EzERMA8GA1UEAwwIdGVzdC1waXYwHhcNMjYxMTI0MjMwNDM5WhcNMzYxMTIxMjMw
          NDM5WjATMREwDwYDVQQDDAh0ZXN0LXBpdjBZMBMGByqGSM49AgEGCCqGSM49AwEH
          A0IABO23Pn1SC+Iz1QgYPfnqK8NMFcFRCJejr5d+EQpf6d361VcKPuIVCbUSjm5b
          BxR50zbCMSoXkhtquVPA3VWjuCyjUzBRMB0GA1UdDgQWBBRnOHvrWtqFSp1ujL4x
          +Wjk7SCDIDAfBgNVHSMEGDAWgBRnOHvrWtqFSp1ujL4x+Wjk7SCDIDAPBgNVHRMB
          Af8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIEPjM+r0cvYZHUm6YJXFTRfFqzeb
          96fGb5GdpsBHbOomAiEA1rwJCJcgVuPoTbkXUnyLBaRG/Wo1/0cFglcwJ7cT2Nc=
          -----END CERTIFICATE-----
        '';
      };
      pgp.slots.auth.key = ''
        -----BEGIN PRIVATE KEY-----
        MC4CAQAwBQYDK2VwBCIEIJbJT0jnAugSn9DHay97cqgLdCbGsK0F0sHgA99Ndtks
        -----END PRIVATE KEY-----
      '';
    };
  };

  testScript =
    { ... }:
    let
      bash = command: "XDG_RUNTIME_DIR=/run/user/1000 bash -il -c ${pkgs.lib.escapeShellArg command}";
      su = command: "su - testuser -c ${pkgs.lib.escapeShellArg (bash command)}";
      toPythonString = string: builtins.toJSON string;
      sshCmd =
        pubFile:
        toPythonString (su ''
          ssh -n \
          -o BatchMode=yes \
          -o StrictHostKeyChecking=no \
          -o UserKnownHostsFile=/dev/null \
          -o IdentitiesOnly=yes \
          -i ${pubFile} \
          -T testuser@localhost echo ok
        '');
    in
    ''
      host.wait_for_unit("sshd.service")
      host.wait_for_unit("keyroost-agent-ssh.socket", "testuser")

      socket = "/run/user/1000/keyroost-agent/ssh.socket"
      host.wait_for_file(socket)
      assert (
          host.succeed(${toPythonString (su "printf %s $SSH_AUTH_SOCK")})
          == socket
      )

      log_offset = 0

      def read_new_log():
          global log_offset
          full_log = host.succeed("cat /tmp/pinentry-commands.log")
          delta = full_log[log_offset:]
          log_offset = len(full_log)
          return delta

      # 1. PIV SSH auth enables external password cache with PIV keyinfo
      host.succeed(${toPythonString (su "printf '123456\n' > /tmp/pinentry-responses")})
      assert host.succeed(${sshCmd pivPubFile}).strip() == "ok"

      piv_log = read_new_log()
      assert "SETDESC Please unlock PIV card 87654321" in piv_log, f"Missing PIV SETDESC:\n{piv_log}"
      assert "OPTION allow-external-password-cache" in piv_log, f"Missing allow-external-password-cache:\n{piv_log}"
      assert "SETKEYINFO keyroost-agent-piv-87654321" in piv_log, f"Missing PIV SETKEYINFO:\n{piv_log}"
      assert piv_log.count("GETPIN") == 1, f"Expected 1 GETPIN for PIV auth:\n{piv_log}"

      # 2. OpenPGP SSH auth enables external password cache with OpenPGP keyinfo
      host.succeed(${toPythonString (su "printf '123456\n' > /tmp/pinentry-responses")})
      assert host.succeed(${sshCmd pgpAuthPubFile}).strip() == "ok"

      pgp_log = read_new_log()
      assert "SETDESC Please unlock OpenPGP card 87654321" in pgp_log, f"Missing OpenPGP SETDESC:\n{pgp_log}"
      assert "OPTION allow-external-password-cache" in pgp_log, f"Missing allow-external-password-cache:\n{pgp_log}"
      assert "SETKEYINFO keyroost-agent-openpgp-87654321" in pgp_log, f"Missing OpenPGP SETKEYINFO:\n{pgp_log}"
      assert pgp_log.count("GETPIN") == 1, f"Expected 1 GETPIN for OpenPGP auth:\n{pgp_log}"

      # 3. Wrong PIN from external-cache-enabled prompt retries once with SETERROR
      #    and WITHOUT allow-external-password-cache or SETKEYINFO
      host.succeed(${toPythonString (su "printf '000000\n123456\n' > /tmp/pinentry-responses")})
      assert host.succeed(${sshCmd pivPubFile}).strip() == "ok"

      retry_log = read_new_log()
      sessions = [s.strip() for s in retry_log.split("BYE") if s.strip()]
      assert len(sessions) == 2, f"Expected 2 pinentry sessions (initial + retry), got {len(sessions)}:\n{retry_log}"

      initial_session, retry_session = sessions
      assert "OPTION allow-external-password-cache" in initial_session, f"Initial session missing external cache option:\n{initial_session}"
      assert "SETKEYINFO keyroost-agent-piv-87654321" in initial_session, f"Initial session missing SETKEYINFO:\n{initial_session}"
      assert "SETERROR Incorrect PIN" not in initial_session, f"Initial session should not have SETERROR:\n{initial_session}"

      assert "SETERROR Incorrect PIN" in retry_session, f"Retry session missing SETERROR:\n{retry_session}"
      assert "OPTION allow-external-password-cache" not in retry_session, f"Retry session must omit external cache option:\n{retry_session}"
      assert "SETKEYINFO" not in retry_session, f"Retry session must omit SETKEYINFO:\n{retry_session}"
    '';
}
