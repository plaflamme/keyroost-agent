{
  testScript = ''
    # Generate an ECC key and certificate on slot 9A (PIV Authentication)
    keyroostctl("piv key generate --slot 9a --mgmt-key env:MGMT --yes")
    keyroostctl("piv cert generate --slot 9a --subject CN=test-user --pin env:PIN --mgmt-key env:MGMT --yes")

    # Generate an RSA-2048 key and certificate on slot 9C (PIV Digital Signature)
    keyroostctl("piv key generate --slot 9c --algorithm rsa2048 --mgmt-key env:MGMT --yes")
    keyroostctl("piv cert generate --slot 9c --subject CN=test-user-rsa --pin env:PIN --mgmt-key env:MGMT --yes")

    # Export the certificates, extract the public keys, and convert them to SSH public key format
    keyroostctl("piv cert export --slot 9a --out /tmp/cert.pem")
    host.succeed("openssl x509 -in /tmp/cert.pem -pubkey -noout > /tmp/pubkey.pem")
    expected_pubkey = host.succeed("ssh-keygen -i -m PKCS8 -f /tmp/pubkey.pem").strip()
    print(f"Expected 9a SSH public key:\n{expected_pubkey}")

    keyroostctl("piv cert export --slot 9c --out /tmp/cert-9c.pem")
    host.succeed("openssl x509 -in /tmp/cert-9c.pem -pubkey -noout > /tmp/pubkey-9c.pem")
    expected_rsa_pubkey = host.succeed("ssh-keygen -i -m PKCS8 -f /tmp/pubkey-9c.pem").strip()
    print(f"Expected 9c SSH public key:\n{expected_rsa_pubkey}")

    # Start keyroost-agent in background binding to a unix socket
    socket = "/tmp/agent.sock"
    host.succeed(f"keyroost-agent --socket {socket} >/tmp/keyroost-agent.log 2>&1 &")

    # Wait for the socket to appear
    host.wait_for_file(socket)

    # Query keyroost-agent via ssh-add -L to list public keys
    agent_output = host.succeed(f"SSH_AUTH_SOCK={socket} ssh-add -L").strip()
    print(f"Agent output:\n{agent_output}")

    # Exhaustive validation: both identities must be present matching the converted public keys and comments
    expected_lines = "\n".join([
        f"{expected_pubkey} PIV 87654321:Authentication",
        f"{expected_rsa_pubkey} PIV 87654321:Signature",
    ])
    assert agent_output == expected_lines, f"Expected exactly:\n{expected_lines!r}\nGot:\n{agent_output!r}"
  '';
}
