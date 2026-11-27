{ pkgs, ... }:
let
  sshPubKey = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBO23Pn1SC+Iz1QgYPfnqK8NMFcFRCJejr5d+EQpf6d361VcKPuIVCbUSjm5bBxR50zbCMSoXkhtquVPA3VWjuCw=";
  pubKeyFile = pkgs.writeText "piv.pub" "${sshPubKey}\n";
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
      openssh.authorizedKeys.keys = [ sshPubKey ];
    };

    home-manager.users.testuser.services.keyroost-agent.enable = true;

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
    };
  };

  testScript =
    { ... }:
    let
      bash = command: "XDG_RUNTIME_DIR=/run/user/1000 bash -il -c ${pkgs.lib.escapeShellArg command}";
      su = command: "su - testuser -c ${pkgs.lib.escapeShellArg (bash command)}";
      # toPythonString "foo "bar" baz" => ""foo \"bar\" baz""
      toPythonString = string: builtins.toJSON string;
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

      # Provide the valid PIV PIN via mockPinentry
      host.succeed(${toPythonString (su "printf '123456\n' > /tmp/pinentry-responses")})

      # Authenticate over SSH using the socket-activated keyroost-agent and SSH_AUTH_SOCK
      ssh_output = host.succeed(${toPythonString (su ''
        ssh -n \
        -o BatchMode=yes \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o IdentitiesOnly=yes \
        -i ${pubKeyFile} \
        -T testuser@localhost echo ok
      '')}).strip()
      assert ssh_output == "ok", f"Expected 'ok', got {ssh_output!r}"

      # Verify mockPinentry was invoked with the expected card description and GETPIN
      pinentry_log = host.succeed("cat /tmp/pinentry-commands.log")
      assert "SETDESC Please unlock PIV card 87654321" in pinentry_log, f"Missing SETDESC in pinentry log:\n{pinentry_log}"
      assert pinentry_log.count("GETPIN") == 1, f"Expected 1 GETPIN call, got:\n{pinentry_log}"
    '';
}
