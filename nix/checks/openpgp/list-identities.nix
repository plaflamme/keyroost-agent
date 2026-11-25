{
  testScript = ''
    import json

    # Generate an Ed25519 key in the auth slot and an RSA-2048 key in the sign slot
    keyroostctl("openpgp key generate --slot auth --algorithm ed25519 --admin-pin env:ADMIN_PIN --yes")
    keyroostctl("openpgp key generate --slot sign --algorithm rsa2048 --admin-pin env:ADMIN_PIN --yes")

    info = json.loads(keyroostctl("--json openpgp info"))
    serial = int(info["serial"], 16)

    # Start keyroost-agent in background binding to a unix socket
    socket = "/tmp/agent.sock"
    host.succeed(f"keyroost-agent --socket {socket} >/tmp/keyroost-agent.log 2>&1 &")
    host.wait_for_file(socket)

    # Query keyroost-agent via ssh-add -L to list public keys
    agent_output = host.succeed(f"SSH_AUTH_SOCK={socket} ssh-add -L").strip()
    print(f"Agent output:\n{agent_output}")

    lines = agent_output.splitlines()
    assert len(lines) == 2, f"Expected 2 identities, got:\n{agent_output!r}"
    assert lines[0].startswith("ssh-ed25519 ") and lines[0].endswith(f" OpenPGP {serial}:Auth"), (
        f"Unexpected Auth identity:\n{lines[0]!r}"
    )
    assert lines[1].startswith("ssh-rsa ") and lines[1].endswith(f" OpenPGP {serial}:Sign"), (
        f"Unexpected Sign identity:\n{lines[1]!r}"
    )
  '';
}
