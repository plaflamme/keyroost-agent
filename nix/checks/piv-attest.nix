{
  pkgs,
  keyroost,
  keyroost-piv-applet,
  system,
}:

import ./make-piv-check.nix
  {
    inherit
      pkgs
      keyroost
      keyroost-piv-applet
      system
      ;
  }
  {
    name = "piv-attest";
    testScript = ''
      # Generate a key in slot 9A using keyroostctl
      keyroostctl("piv key generate --slot 9a --mgmt-key env:MGMT --yes")

      # ATTEST slot 9a's key, generating a F9-signed certificate
      host.succeed("yubico-piv-tool -r 'Virtual PCD 00 00' --action attest --slot 9a > 9a.pem")

      # export F9 certificate (keyroostctl doesn't support reading f9)
      host.succeed("yubico-piv-tool -r 'Virtual PCD 00 00' --action read-certificate --slot f9 > f9.pem")

      # verify the signature
      host.succeed("openssl verify -CAfile f9.pem 9a.pem")
    '';
  }
