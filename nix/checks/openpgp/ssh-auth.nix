{ pkgs, ... }:
let
  authPubKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK1A88n4jUSTSIjnpgeRY7OsmY6+Xk4oSrR8SbHjeSnv";
  signPubKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJlv2RY10VzoVaFtZIByr3T49+n/ZZokJKFxUA5HmP/u";
  authPubFile = pkgs.writeText "openpgp-auth.pub" "${authPubKey}\n";
  signPubFile = pkgs.writeText "openpgp-sign.pub" "${signPubKey}\n";
in
{
  nodes.host = {
    services.openssh = {
      enable = true;
      settings.PasswordAuthentication = false;
    };

    users.users.testuser = {
      isNormalUser = true;
      openssh.authorizedKeys.keys = [
        authPubKey
        signPubKey
      ];
    };

    services.sftcrd.config = {
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

  testScript = ''
    host.wait_for_unit("sshd.service")

    # Start keyroost-agent in background binding to a unix socket
    socket = "/tmp/agent.sock"
    host.succeed(f"keyroost-agent --socket {socket} >/tmp/keyroost-agent.log 2>&1 &")
    host.wait_for_file(socket)

    # Authenticate over SSH with both Auth and Sign keys via keyroost-agent
    for pub_file in ["${authPubFile}", "${signPubFile}"]:
        host.succeed("printf '123456\n' > /tmp/pinentry-responses")
        ssh_output = host.succeed(
            f"SSH_AUTH_SOCK={socket} ssh "
            "-n "
            "-o BatchMode=yes "
            "-o StrictHostKeyChecking=no "
            "-o UserKnownHostsFile=/dev/null "
            "-o IdentitiesOnly=yes "
            f"-i {pub_file} "
            "-T testuser@localhost echo ok"
        ).strip()
        assert ssh_output == "ok", f"Expected 'ok', got {ssh_output!r}"

    # Verify mockPinentry was invoked with the expected card description and GETPIN count
    pinentry_log = host.succeed("cat /tmp/pinentry-commands.log")
    assert "SETDESC Please unlock OpenPGP card 87654321" in pinentry_log, f"Missing SETDESC in pinentry log:\n{pinentry_log}"
    assert pinentry_log.count("GETPIN") == 2, f"Expected 2 GETPIN calls, got:\n{pinentry_log}"
  '';
}
