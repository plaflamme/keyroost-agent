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
      keyroostctl("piv key generate --slot 9a --algorithm eccp256 --mgmt-key env:MGMT --yes")

      # Use yubico-piv-tool with the Virtual PCD reader to test attestation
      # The reader name matches what vsmartcard-vpcd exposes
      host.succeed("yubico-piv-tool -r 'Virtual PCD 00 00' --action attest --slot 9a > attested.pem")

      # export attestation certificate (keyroostctl doesn't support reading f9)
      host.succeed("yubico-piv-tool -r 'Virtual PCD 00 00' --action read-certificate --slot f9 > attestation.pem")

      # verify the signature
      # host.succeed("openssl verify -partial_chain -purpose any -CAfile attestation.pem attested.pem")
    '';
  }
