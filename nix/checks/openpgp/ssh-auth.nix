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
      linger = true;
      openssh.authorizedKeys.keys = [
        authPubKey
        signPubKey
      ];
    };

    home-manager.users.testuser.services.keyroost-agent.enable = true;

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

  testScript =
    { ... }:
    let
      bash = command: "XDG_RUNTIME_DIR=/run/user/1000 bash -il -c ${pkgs.lib.escapeShellArg command}";
      su = command: "su - testuser -c ${pkgs.lib.escapeShellArg (bash command)}";
      # toPythonString "foo "bar" baz" => ""foo \"bar\" baz""
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
      host.wait_for_unit("keyroost-agent.socket", "testuser")

      socket = "/run/user/1000/keyroost-agent/ssh.socket"
      host.wait_for_file(socket)
      assert (
          host.succeed(${toPythonString (su "printf %s $SSH_AUTH_SOCK")})
          == socket
      )

      # Authenticate over SSH with both Auth and Sign keys via socket-activated keyroost-agent
      for ssh_cmd in [${sshCmd authPubFile}, ${sshCmd signPubFile}]:
          host.succeed(${toPythonString (su "printf '123456\n' > /tmp/pinentry-responses")})
          ssh_output = host.succeed(ssh_cmd).strip()
          assert ssh_output == "ok", f"Expected 'ok', got {ssh_output!r}"

      # Verify mockPinentry was invoked with the expected card description and GETPIN count
      pinentry_log = host.succeed("cat /tmp/pinentry-commands.log")
      assert "SETDESC Please unlock OpenPGP card 87654321" in pinentry_log, f"Missing SETDESC in pinentry log:\n{pinentry_log}"
      assert pinentry_log.count("GETPIN") == 2, f"Expected 2 GETPIN calls, got:\n{pinentry_log}"
    '';
}
