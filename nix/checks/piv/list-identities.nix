{
  testScript = ''
    # Generate a key and certificate on slot 9A (PIV Authentication)
    keyroostctl("piv key generate --slot 9a --mgmt-key env:MGMT --yes")
    keyroostctl("piv cert generate --slot 9a --subject CN=test-user --pin env:PIN --mgmt-key env:MGMT --yes")

    # Export the certificate, extract the public key, and convert it to SSH public key format
    keyroostctl("piv cert export --slot 9a --out /tmp/cert.pem")
    host.succeed("openssl x509 -in /tmp/cert.pem -pubkey -noout > /tmp/pubkey.pem")
    expected_pubkey = host.succeed("ssh-keygen -i -m PKCS8 -f /tmp/pubkey.pem").strip()
    print(f"Expected SSH public key:\n{expected_pubkey}")

    # Start keyroost-agent in background binding to a unix socket
    socket = "/tmp/agent.sock"
    host.succeed(f"keyroost-agent --socket {socket} >/tmp/keyroost-agent.log 2>&1 &")

    # Wait for the socket to appear
    host.wait_for_file(socket)

    # Query keyroost-agent via ssh-add -L to list public keys
    agent_output = host.succeed(f"SSH_AUTH_SOCK={socket} ssh-add -L").strip()
    print(f"Agent output:\n{agent_output}")

    # Exhaustive validation: exactly one identity must be present matching the converted public key and comment
    expected_line = f"{expected_pubkey} PIV 87654321:Authentication"
    assert agent_output == expected_line, f"Expected exactly:\n{expected_line!r}\nGot:\n{agent_output!r}"
  '';
}
