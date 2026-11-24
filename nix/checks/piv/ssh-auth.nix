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
      openssh.authorizedKeys.keys = [ sshPubKey ];
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
    };
  };

  testScript = ''
    host.wait_for_unit("sshd.service")

    # Start keyroost-agent in background binding to a unix socket
    socket = "/tmp/agent.sock"
    host.succeed(f"keyroost-agent --socket {socket} >/tmp/keyroost-agent.log 2>&1 &")
    host.wait_for_file(socket)

    # Provide the valid PIV PIN via mockPinentry
    host.succeed("printf '123456\n' > /tmp/pinentry-responses")

    # Authenticate over SSH using only the keyroost-agent socket and static public key
    ssh_output = host.succeed(
        f"SSH_AUTH_SOCK={socket} ssh "
        "-n "
        "-o BatchMode=yes "
        "-o StrictHostKeyChecking=no "
        "-o UserKnownHostsFile=/dev/null "
        "-o IdentitiesOnly=yes "
        "-i ${pubKeyFile} "
        "-T testuser@localhost echo ok"
    ).strip()
    assert ssh_output == "ok", f"Expected 'ok', got {ssh_output!r}"

    # Verify mockPinentry was invoked with the expected card description and GETPIN
    pinentry_log = host.succeed("cat /tmp/pinentry-commands.log")
    assert "SETDESC Please unlock PIV card 87654321" in pinentry_log, f"Missing SETDESC in pinentry log:\n{pinentry_log}"
    assert pinentry_log.count("GETPIN") == 1, f"Expected 1 GETPIN call, got:\n{pinentry_log}"
  '';
}
