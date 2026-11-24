{ pkgs, ... }:
let
  sshPubKey = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBO23Pn1SC+Iz1QgYPfnqK8NMFcFRCJejr5d+EQpf6d361VcKPuIVCbUSjm5bBxR50zbCMSoXkhtquVPA3VWjuCw=";
  pubKeyFile = pkgs.writeText "piv.pub" "${sshPubKey}\n";
  allowedSignersFile = pkgs.writeText "allowed_signers" "test@example ${sshPubKey}\n";
in
{
  nodes.host.services.sftcrd.config = {
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

  testScript = ''
    # Start keyroost-agent in background binding to a unix socket
    socket = "/tmp/agent.sock"
    host.succeed(f"keyroost-agent --socket {socket} >/tmp/keyroost-agent.log 2>&1 &")
    host.wait_for_file(socket)

    # Verify ssh-add -L lists the pre-configured PIV identity
    agent_output = host.succeed(f"SSH_AUTH_SOCK={socket} ssh-add -L").strip()
    expected_line = "${sshPubKey} PIV 87654321:Authentication"
    assert agent_output == expected_line, f"Expected:\n{expected_line!r}\nGot:\n{agent_output!r}"

    host.succeed("printf 'hello piv signing\n' > /tmp/payload")

    # First test cancelled pinentry: signing must fail without crashing the agent
    host.succeed("printf 'ERR 83886179 Operation cancelled\n' > /tmp/pinentry-responses")
    host.fail(f"SSH_AUTH_SOCK={socket} ssh-keygen -Y sign -f ${pubKeyFile} -n file /tmp/payload")

    # Now provide the valid PIV PIN via mockPinentry and sign
    host.succeed("printf '123456\n' > /tmp/pinentry-responses")
    host.succeed(f"SSH_AUTH_SOCK={socket} ssh-keygen -Y sign -f ${pubKeyFile} -n file /tmp/payload")

    # Verify the signature against the static allowed_signers file
    host.succeed("ssh-keygen -Y verify -f ${allowedSignersFile} -I test@example -n file -s /tmp/payload.sig < /tmp/payload")

    # Verify mockPinentry was invoked with the expected card description and GETPIN
    pinentry_log = host.succeed("cat /tmp/pinentry-commands.log")
    assert "SETDESC Please unlock PIV card 87654321" in pinentry_log, f"Missing SETDESC in pinentry log:\n{pinentry_log}"
    assert pinentry_log.count("GETPIN") == 2, f"Expected 2 GETPIN calls, got:\n{pinentry_log}"
  '';
}
