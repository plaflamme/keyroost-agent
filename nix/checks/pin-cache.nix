{ pkgs, ... }:
let
  pivPubKey = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBO23Pn1SC+Iz1QgYPfnqK8NMFcFRCJejr5d+EQpf6d361VcKPuIVCbUSjm5bBxR50zbCMSoXkhtquVPA3VWjuCw=";
  pgpAuthPubKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK1A88n4jUSTSIjnpgeRY7OsmY6+Xk4oSrR8SbHjeSnv";
  pgpSignPubKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJlv2RY10VzoVaFtZIByr3T49+n/ZZokJKFxUA5HmP/u";

  pivPubFile = pkgs.writeText "piv.pub" "${pivPubKey}\n";
  pgpAuthPubFile = pkgs.writeText "openpgp-auth.pub" "${pgpAuthPubKey}\n";
  pgpSignPubFile = pkgs.writeText "openpgp-sign.pub" "${pgpSignPubKey}\n";
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
        pgpSignPubKey
      ];
    };

    home-manager.users.testuser.services.keyroost-agent = {
      enable = true;
      pinCache = {
        mode = "memory";
        ttl = "60s";
        maxTtl = "5m";
      };
    };

    # Provision both PIV and OpenPGP identities so --connection=auto resolves to
    # ephemeral mode (resetting card state between operations), exercising the
    # in-memory PIN cache across ephemeral sessions and applet switches.
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
      pgp.slots = {
        auth.key = ''
          -----BEGIN PRIVATE KEY-----
          MC4CAQAwBQYDK2VwBCIEIJbJT0jnAugSn9DHay97cqgLdCbGsK0F0sHgA99Ndtks
          -----END PRIVATE KEY-----
        '';
        sign.key = ''
          -----BEGIN PRIVATE KEY-----
          MC4CAQAwBQYDK2VwBCIEIC+Lw9E0+qXwbDS3u0R+ta//c+ekDb6CgXN/js2Kv8XM
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

      def getpin_count():
          log = host.succeed("cat /tmp/pinentry-commands.log")
          return log.count("GETPIN"), log

      # 1. PIV SSH auth prompts once and caches the PIN across ephemeral sessions
      host.succeed(${toPythonString (su "printf '123456\n' > /tmp/pinentry-responses")})
      assert host.succeed(${sshCmd pivPubFile}).strip() == "ok"
      assert host.succeed(${sshCmd pivPubFile}).strip() == "ok"

      count, pinentry_log = getpin_count()
      assert "SETDESC Please unlock PIV card 87654321" in pinentry_log, f"Missing PIV SETDESC:\n{pinentry_log}"
      assert count == 1, f"Expected 1 GETPIN after repeated PIV auth, got {count}:\n{pinentry_log}"

      # 2. OpenPGP SSH auth prompts once and caches across both Auth and Sign keys,
      #    and switching back to PIV still hits the PIV cache without reprompting.
      host.succeed(${toPythonString (su "printf '123456\n' > /tmp/pinentry-responses")})
      assert host.succeed(${sshCmd pgpAuthPubFile}).strip() == "ok"
      assert host.succeed(${sshCmd pgpSignPubFile}).strip() == "ok"
      assert host.succeed(${sshCmd pivPubFile}).strip() == "ok"

      count, pinentry_log = getpin_count()
      assert "SETDESC Please unlock OpenPGP card 87654321" in pinentry_log, f"Missing OpenPGP SETDESC:\n{pinentry_log}"
      assert count == 2, f"Expected 2 GETPIN calls (1 PIV + 1 OpenPGP), got {count}:\n{pinentry_log}"

      # 3. ssh-add -D clears the in-memory PIN cache for both applets
      host.succeed(${toPythonString (su "ssh-add -D")})

      host.succeed(${toPythonString (su "printf '123456\n' > /tmp/pinentry-responses")})
      assert host.succeed(${sshCmd pivPubFile}).strip() == "ok"
      count, pinentry_log = getpin_count()
      assert count == 3, f"Expected 3 GETPIN calls after ssh-add -D + PIV auth, got {count}:\n{pinentry_log}"

      host.succeed(${toPythonString (su "printf '123456\n' > /tmp/pinentry-responses")})
      assert host.succeed(${sshCmd pgpAuthPubFile}).strip() == "ok"
      count, pinentry_log = getpin_count()
      assert count == 4, f"Expected 4 GETPIN calls after ssh-add -D + OpenPGP auth, got {count}:\n{pinentry_log}"

      # 4. Evict-and-reprompt: change PIV PIN on the card while old PIN is cached,
      #    then provide the new PIN via pinentry and verify auth succeeds and caches it.
      keyroostctl("piv pin change --pin env:PIN --new-pin env:NEW_PIN", pin="123456", NEW_PIN="654321")

      host.succeed(${toPythonString (su "printf '654321\n' > /tmp/pinentry-responses")})
      assert host.succeed(${sshCmd pivPubFile}).strip() == "ok"
      count, pinentry_log = getpin_count()
      assert count == 5, f"Expected 5 GETPIN calls after stale cached PIV PIN eviction, got {count}:\n{pinentry_log}"

      # Subsequent PIV auth must use the newly cached PIN without prompting again
      assert host.succeed(${sshCmd pivPubFile}).strip() == "ok"
      count, pinentry_log = getpin_count()
      assert count == 5, f"Expected 5 GETPIN calls after re-caching new PIV PIN, got {count}:\n{pinentry_log}"
    '';
}
