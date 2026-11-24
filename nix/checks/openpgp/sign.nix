{ pkgs, ... }:
let
  authPubKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK1A88n4jUSTSIjnpgeRY7OsmY6+Xk4oSrR8SbHjeSnv";
  signPubKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJlv2RY10VzoVaFtZIByr3T49+n/ZZokJKFxUA5HmP/u";
  authPubFile = pkgs.writeText "openpgp-auth.pub" "${authPubKey}\n";
  signPubFile = pkgs.writeText "openpgp-sign.pub" "${signPubKey}\n";
  authAllowedSigners = pkgs.writeText "allowed_signers_auth" "auth@example ${authPubKey}\n";
  signAllowedSigners = pkgs.writeText "allowed_signers_sign" "sign@example ${signPubKey}\n";
in
{
  nodes.host.services.sftcrd.config = {
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

  testScript = ''
    # Start keyroost-agent in background binding to a unix socket
    socket = "/tmp/agent.sock"
    host.succeed(f"keyroost-agent --socket {socket} >/tmp/keyroost-agent.log 2>&1 &")
    host.wait_for_file(socket)

    # Verify ssh-add -L lists the pre-configured Auth and Sign identities
    agent_output = host.succeed(f"SSH_AUTH_SOCK={socket} ssh-add -L").strip()
    expected_output = "\n".join([
        "${authPubKey} OpenPGP 87654321:Auth",
        "${signPubKey} OpenPGP 87654321:Sign",
    ])
    assert agent_output == expected_output, f"Expected:\n{expected_output!r}\nGot:\n{agent_output!r}"

    host.succeed("printf 'hello openpgp signing\n' > /tmp/payload")

    slots = [
        ("auth@example", "${authPubFile}", "${authAllowedSigners}"),
        ("sign@example", "${signPubFile}", "${signAllowedSigners}"),
    ]

    for principal, pub_file, allowed_signers in slots:
        # Test cancelled pinentry
        host.succeed("printf 'ERR 83886179 Operation cancelled\n' > /tmp/pinentry-responses")
        host.fail(f"SSH_AUTH_SOCK={socket} ssh-keygen -Y sign -f {pub_file} -n file /tmp/payload")

        # Provide valid OpenPGP user PIN, sign, and verify
        host.succeed("printf '123456\n' > /tmp/pinentry-responses")
        host.succeed(f"SSH_AUTH_SOCK={socket} ssh-keygen -Y sign -f {pub_file} -n file /tmp/payload")
        host.succeed(f"ssh-keygen -Y verify -f {allowed_signers} -I {principal} -n file -s /tmp/payload.sig < /tmp/payload")
        host.succeed("rm -f /tmp/payload.sig")

    # Verify mockPinentry was invoked with the expected card description and GETPIN count
    pinentry_log = host.succeed("cat /tmp/pinentry-commands.log")
    assert "SETDESC Please unlock OpenPGP card 87654321" in pinentry_log, f"Missing SETDESC in pinentry log:\n{pinentry_log}"
    assert pinentry_log.count("GETPIN") == 4, f"Expected 4 GETPIN calls, got:\n{pinentry_log}"
  '';
}
