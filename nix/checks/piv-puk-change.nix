{ pkgs, keyroost, keyroost-piv-applet, system }:

import ./make-piv-check.nix {
  inherit pkgs keyroost keyroost-piv-applet system;
} {
  name = "piv-puk-change";
  testScript = ''
    # PUK change: the same command with the PUK reference.
    keyroostctl("piv puk change --puk env:OLD --new-puk env:NEW", OLD="12345678", NEW="87654321")
    keyroostctl("piv puk change --puk env:OLD --new-puk env:NEW", OLD="87654321", NEW="12345678")
  '';
}
