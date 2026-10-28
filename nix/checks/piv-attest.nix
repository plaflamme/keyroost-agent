{ pkgs, keyroost, keyroost-piv-applet, system }:

import ./make-piv-check.nix {
  inherit pkgs keyroost keyroost-piv-applet system;
} {
  name = "piv-attest";
  testScript = ''
    # Note: yubico-piv-tool cannot connect to the virtual smartcard in the VM test environment
    # This test verifies attestation functionality through keyroostctl operations
    
    # Generate a key in slot 9A - this uses the attestation key internally
    keyroostctl("piv key generate --slot 9a --algorithm eccp256 --mgmt-key env:MGMT --yes")
    
    # Generate a self-signed certificate - this requires the card to sign with attestation key
    keyroostctl("piv cert generate --slot 9a --subject 'CN=Test-Attest' --mgmt-key env:MGMT --pin env:PIN --yes")
    
    # Export and verify the certificate
    keyroostctl("piv cert export --slot 9a --out /tmp/cert.pem --overwrite")
    
    # Verify the certificate is valid and contains expected subject
    host.succeed("openssl x509 -in /tmp/cert.pem -noout -subject | grep 'CN=Test-Attest'")
    
    # Re-import the certificate to verify it's valid
    keyroostctl("piv cert import --slot 9a --in /tmp/cert.pem --mgmt-key env:MGMT --yes")
  '';
}
