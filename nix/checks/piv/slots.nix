{
  testScript = ''
    # Generate keys and certificates on 9A (Authentication), 9C (Signature),
    # 9D (Key Management - excluded from defaults), and 82 (Retired 1).
    pubkeys = {}
    for slot in ("9a", "9c", "9d", "82"):
        keyroostctl(f"piv key generate --slot {slot} --mgmt-key env:MGMT --yes")
        keyroostctl(
            f"piv cert generate --slot {slot} --subject CN=test-{slot} --pin env:PIN --mgmt-key env:MGMT --yes"
        )
        cert_path = f"/tmp/cert-{slot}.pem"
        pub_path = f"/tmp/pubkey-{slot}.pem"
        keyroostctl(f"piv cert export --slot {slot} --out {cert_path}")
        host.succeed(f"openssl x509 -in {cert_path} -pubkey -noout > {pub_path}")
        pubkeys[slot] = host.succeed(f"ssh-keygen -i -m PKCS8 -f {pub_path}").strip()

    def start_agent(socket, extra_args=""):
        host.succeed(
            f"keyroost-agent --socket {socket} {extra_args} >/tmp/keyroost-agent.log 2>&1 & echo $! > /tmp/agent.pid"
        )
        host.wait_for_file(socket)

    def stop_agent(socket):
        host.succeed("kill $(cat /tmp/agent.pid) && wait $(cat /tmp/agent.pid) || true")
        host.succeed(f"rm -f {socket} /tmp/agent.pid")

    # 1. Default slot set exposes 9A, 9C, and 82, but NOT 9D.
    default_sock = "/tmp/agent-default.sock"
    start_agent(default_sock)
    default_lines = host.succeed(f"SSH_AUTH_SOCK={default_sock} ssh-add -L").strip().splitlines()
    expected_default = [
        f"{pubkeys['9a']} PIV 87654321:Authentication",
        f"{pubkeys['9c']} PIV 87654321:Signature",
        f"{pubkeys['82']} PIV 87654321:Retired(1)",
    ]
    assert default_lines == expected_default, (
        f"Default slots mismatch:\nExpected: {expected_default!r}\nGot: {default_lines!r}"
    )
    stop_agent(default_sock)

    # 2. Explicit selection via comma-separated and repeated --piv-slot flags:
    #    - 9D is selectable when explicitly requested
    #    - Duplicate 9C is deduplicated preserving order
    explicit_sock = "/tmp/agent-explicit.sock"
    start_agent(explicit_sock, "--piv-slot 9c,9d --piv-slot 9c")
    explicit_lines = host.succeed(f"SSH_AUTH_SOCK={explicit_sock} ssh-add -L").strip().splitlines()
    expected_explicit = [
        f"{pubkeys['9c']} PIV 87654321:Signature",
        f"{pubkeys['9d']} PIV 87654321:KeyManagement",
    ]
    assert explicit_lines == expected_explicit, (
        f"Explicit slots mismatch:\nExpected: {expected_explicit!r}\nGot: {explicit_lines!r}"
    )

    # Verify signing with explicitly selected slot 9D works end-to-end.
    host.succeed(f"printf '%s\n' '{pubkeys['9d']}' > /tmp/slot-9d.pub")
    host.succeed(f"printf 'test@example %s\n' '{pubkeys['9d']}' > /tmp/allowed_signers_9d")
    host.succeed("printf 'hello 9d signing\n' > /tmp/payload-9d")
    host.succeed("printf '123456\n' > /tmp/pinentry-responses")
    host.succeed(
        f"SSH_AUTH_SOCK={explicit_sock} ssh-keygen -Y sign -f /tmp/slot-9d.pub -n file /tmp/payload-9d"
    )
    host.succeed(
        "ssh-keygen -Y verify -f /tmp/allowed_signers_9d -I test@example -n file -s /tmp/payload-9d.sig < /tmp/payload-9d"
    )
    stop_agent(explicit_sock)

    # 3. Named slot selection (auth and retired1).
    named_sock = "/tmp/agent-named.sock"
    start_agent(named_sock, "--piv-slot auth,retired1")
    named_lines = host.succeed(f"SSH_AUTH_SOCK={named_sock} ssh-add -L").strip().splitlines()
    expected_named = [
        f"{pubkeys['9a']} PIV 87654321:Authentication",
        f"{pubkeys['82']} PIV 87654321:Retired(1)",
    ]
    assert named_lines == expected_named, (
        f"Named slots mismatch:\nExpected: {expected_named!r}\nGot: {named_lines!r}"
    )
    stop_agent(named_sock)

    # 4. Invalid slot and --piv-slot combined with --applet=openpgp must fail.
    host.fail("keyroost-agent --socket /tmp/bad.sock --piv-slot bogus")
    host.fail("keyroost-agent --socket /tmp/bad.sock --applet=openpgp --piv-slot 9a")
  '';
}
