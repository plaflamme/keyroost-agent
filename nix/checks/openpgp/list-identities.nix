{
  testScript = ''
    import base64
    import json
    import re
    import struct

    def raw_ed25519_to_ssh(hex_point: str) -> str:
        raw = bytes.fromhex(hex_point)
        key_type = b"ssh-ed25519"
        wire = struct.pack(">I", len(key_type)) + key_type + struct.pack(">I", len(raw)) + raw
        return f"ssh-ed25519 {base64.b64encode(wire).decode('ascii')}"

    # Generate Ed25519 keys in the auth and sign slots
    keyroostctl("openpgp key generate --slot auth --algorithm ed25519 --admin-pin env:ADMIN_PIN --yes")
    keyroostctl("openpgp key generate --slot sign --algorithm ed25519 --admin-pin env:ADMIN_PIN --yes")

    info = json.loads(keyroostctl("--json openpgp info"))
    serial = int(info["serial"], 16)

    auth_key_out = keyroostctl("openpgp key show --slot auth")
    sign_key_out = keyroostctl("openpgp key show --slot sign")

    def extract_ed25519_hex(output: str) -> str:
        match = re.search(r"\b([0-9a-fA-F]{64})\b", output)
        assert match is not None, f"Could not find 64-char hex Ed25519 key in:\n{output}"
        return match.group(1)

    auth_hex = extract_ed25519_hex(auth_key_out)
    sign_hex = extract_ed25519_hex(sign_key_out)

    expected_auth_pubkey = raw_ed25519_to_ssh(auth_hex)
    expected_sign_pubkey = raw_ed25519_to_ssh(sign_hex)

    # Start keyroost-agent in background binding to a unix socket
    socket = "/tmp/agent.sock"
    host.succeed(f"keyroost-agent --socket {socket} >/tmp/keyroost-agent.log 2>&1 &")
    host.wait_for_file(socket)

    # Query keyroost-agent via ssh-add -L to list public keys
    agent_output = host.succeed(f"SSH_AUTH_SOCK={socket} ssh-add -L").strip()
    print(f"Agent output:\n{agent_output}")

    expected_lines = "\n".join([
        f"{expected_auth_pubkey} OpenPGP {serial}:Auth",
        f"{expected_sign_pubkey} OpenPGP {serial}:Sign",
    ])
    assert agent_output == expected_lines, f"Expected exactly:\n{expected_lines!r}\nGot:\n{agent_output!r}"
  '';
}
