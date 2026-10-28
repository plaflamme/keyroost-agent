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
    name = "piv-multi-slot";
    testScript = ''
      # Test P-256 in every possible slot
      slots = [
          "9a", "9c", "9d", "9e",
      ]
      # Add retired slots 82-95
      for i in range(1, 21):
          slots.append(format(0x81 + i, '02x'))

      for slot in slots:
          print(f"=== Testing P-256 on slot {slot} ===")
          keyroostctl(f"piv key generate --slot {slot} --algorithm eccp256 --mgmt-key env:MGMT --yes")
          keyroostctl(f"piv cert generate --slot {slot} --subject 'CN=Test-{slot}' --mgmt-key env:MGMT --pin env:PIN --yes")
    '';
  }
