{ pkgs, ... }:
let
  fingerprint = "9066F10B3F48BCE71A0FDC0C59A2FDBC66890257";
  signKeygrip = "8A95D79ED260E17BFDB1B8EF6EBEEE168C752E32";
  pubKeyFile = pkgs.writeText "test-gpg-pub.asc" ''
    -----BEGIN PGP PUBLIC KEY BLOCK-----

    mDMEawnGFRYJKwYBBAHaRw8BAQdAboqCGqE0aAy6UxF3Do6QItz4tDGNISAabzW6
    p/XbLna0HFRlc3QgVXNlciA8dGVzdEBleGFtcGxlLmNvbT6IkAQTFgoAOBYhBJBm
    8Qs/SLznGg/cDFmi/bxmiQJXBQJrCcYVAhsDBQsJCAcCBhUKCQgLAgQWAgMBAh4B
    AheAAAoJEFmi/bxmiQJXznoA/05VHpnr77N5ghf/Ig5x39Tky0LBVDfe8ZaJ14hN
    TXMGAP43wyNk4TsMmGUaMB0lLkIJlwPfcWKVRbeJR0rqJTD2Drg4BGsJxhUSCisG
    AQQBl1UBBQEBB0BJHMSJzrMAq0mpwrC+GjLILqsgftMDR/khsZQ1e+FdDgMBCAeI
    eAQYFgoAIBYhBJBm8Qs/SLznGg/cDFmi/bxmiQJXBQJrCcYVAhsMAAoJEFmi/bxm
    iQJXAVIBAM3SPn5ZZo4FGeMPka9NdY5GMR3LkjC/30ouKYIE7S3oAP43UkM+Dr1M
    t8sQvvywMmeSXN/VKTELbvThx2/H3JC4BrgzBGsJxhUWCSsGAQQB2kcPAQEHQNnY
    a/XzYq+b+X2R2wwNveKcMe78zwwsunZGqFTntDzDiHgEGBYKACAWIQSQZvELP0i8
    5xoP3AxZov28ZokCVwUCawnGFQIbIAAKCRBZov28ZokCV2p6AQCeT/+4veXBFQAO
    qxNjJXj0l86EakasjaRX7OFv8J0sXgEAyWa16q1CU1J9zsyLPDCApBA5TY0znjGb
    +ZwudD7aogM=
    =PolJ
    -----END PGP PUBLIC KEY BLOCK-----
  '';
in
{
  nodes.host.services.sftcrd.config = {
    pgp.slots = {
      sign.key = ''
        -----BEGIN PRIVATE KEY-----
        MC4CAQAwBQYDK2VwBCIEIPKfAnomN2aIqLDYpfKVtY44p0gk3dIeL+8i2z5Lxdkn
        -----END PRIVATE KEY-----
      '';
    };
  };

  testScript = ''
    gnupghome = "/tmp/gnupg"
    host.succeed(f"mkdir -p {gnupghome} && chmod 700 {gnupghome}")

    # Import only the public key — no private key files in private-keys-v1.d
    host.succeed(f"GNUPGHOME={gnupghome} gpg --batch --no-autostart --import ${pubKeyFile}")
    host.succeed(
        f"test ! -d {gnupghome}/private-keys-v1.d || [ -z \"$(ls -A {gnupghome}/private-keys-v1.d)\" ]"
    )

    # Resolve the exact agent socket path that gpg will connect to for this GNUPGHOME
    agent_socket = host.succeed(f"GNUPGHOME={gnupghome} gpgconf --list-dirs agent-socket").strip()
    host.succeed(f"mkdir -p \"$(dirname {agent_socket})\"")

    # Start keyroost-agent serving the GPG Assuan protocol on that socket
    host.succeed(f"keyroost-agent --gpg-socket {agent_socket} >/tmp/keyroost-agent.log 2>&1 &")
    host.wait_for_file(agent_socket)

    # Verify KEYINFO --list exposes the card Sign keygrip
    keyinfo_out = host.succeed(
        f"GNUPGHOME={gnupghome} gpg-connect-agent --no-autostart 'KEYINFO --list' /bye"
    )
    assert "${signKeygrip}" in keyinfo_out, f"Missing Sign keygrip in KEYINFO:\n{keyinfo_out}"

    # Verify gpg --list-secret-keys discovers the card key via keyroost-agent
    secret_keys = host.succeed(
        f"GNUPGHOME={gnupghome} gpg --batch --no-autostart --list-secret-keys --with-keygrip"
    )
    assert "${fingerprint}" in secret_keys, f"Missing fingerprint in --list-secret-keys:\n{secret_keys}"
    assert "${signKeygrip}" in secret_keys, f"Missing Sign keygrip in --list-secret-keys:\n{secret_keys}"

    host.succeed("printf 'hello gpg signing\n' > /tmp/payload")

    # Cancelled pinentry must fail signing
    host.succeed("printf 'ERR 83886179 Operation cancelled\n' > /tmp/pinentry-responses")
    host.fail(
        f"GNUPGHOME={gnupghome} gpg --batch --no-autostart --detach-sign "
        f"-u ${fingerprint} -o /tmp/payload.sig /tmp/payload"
    )

    # Valid PIN produces a signature verified by gpg --verify
    host.succeed("printf '123456\n' > /tmp/pinentry-responses")
    host.succeed(
        f"GNUPGHOME={gnupghome} gpg --batch --no-autostart --detach-sign "
        f"-u ${fingerprint} -o /tmp/payload.sig /tmp/payload"
    )
    host.succeed(
        f"GNUPGHOME={gnupghome} gpg --batch --no-autostart --verify /tmp/payload.sig /tmp/payload"
    )

    # Verify mockPinentry was invoked with the GPG key description and GETPIN count
    pinentry_log = host.succeed("cat /tmp/pinentry-commands.log")
    assert "Test User <test@example.com>" in pinentry_log, (
        f"Missing key description in pinentry log:\n{pinentry_log}"
    )
    assert pinentry_log.count("GETPIN") == 2, f"Expected 2 GETPIN calls, got:\n{pinentry_log}"
  '';
}
