{ pkgs, ... }:
let
  authPubKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK1A88n4jUSTSIjnpgeRY7OsmY6+Xk4oSrR8SbHjeSnv";
  authPubFile = pkgs.writeText "openpgp-auth.pub" "${authPubKey}\n";
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
      openssh.authorizedKeys.keys = [ authPubKey ];
    };

    home-manager.users.testuser.services.keyroost-agent = {
      enable = true;
      connection = "ephemeral";
    };

    services.sftcrd.config = {
      pgp.slots = {
        auth.key = ''
          -----BEGIN PRIVATE KEY-----
          MC4CAQAwBQYDK2VwBCIEIJbJT0jnAugSn9DHay97cqgLdCbGsK0F0sHgA99Ndtks
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
      sshCmd = toPythonString (su ''
        ssh -n \
        -o BatchMode=yes \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o IdentitiesOnly=yes \
        -i ${authPubFile} \
        -T testuser@localhost echo ok
      '');
    in
    ''
      host.wait_for_unit("sshd.service")
      host.wait_for_unit("keyroost-agent.socket", "testuser")

      socket = "/run/user/1000/keyroost-agent/ssh.socket"
      host.wait_for_file(socket)

      # First Auth SSH authentication prompts for PIN
      host.succeed(${toPythonString (su "printf '123456\n' > /tmp/pinentry-responses")})
      ssh_output = host.succeed(${sshCmd}).strip()
      assert ssh_output == "ok", f"Expected 'ok', got {ssh_output!r}"

      # Confirm the card is released between operations and accessible to other PC/SC clients
      keyroostctl("openpgp info")

      # Second Auth SSH authentication must prompt again because connection=ephemeral releases the card
      host.succeed(${toPythonString (su "printf '123456\n' > /tmp/pinentry-responses")})
      ssh_output = host.succeed(${sshCmd}).strip()
      assert ssh_output == "ok", f"Expected 'ok', got {ssh_output!r}"

      pinentry_log = host.succeed("cat /tmp/pinentry-commands.log")
      assert "SETDESC Please unlock OpenPGP card 87654321" in pinentry_log, f"Missing SETDESC in pinentry log:\n{pinentry_log}"
      assert pinentry_log.count("GETPIN") == 2, f"Expected 2 GETPIN calls in ephemeral mode, got:\n{pinentry_log}"
    '';
}
