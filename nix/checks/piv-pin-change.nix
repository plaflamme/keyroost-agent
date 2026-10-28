{ pkgs, keyroost, keyroost-piv-applet, system }:

import ./make-piv-check.nix {
  inherit pkgs keyroost keyroost-piv-applet system;
} {
  name = "piv-pin-change";
  testScript = ''
    # PIN change: CHANGE REFERENCE verifies the old PIN.
    keyroostctl("piv pin change --pin env:OLD --new-pin env:NEW", OLD="123456", NEW="654321")
    keyroostctl("piv pin change --pin env:OLD --new-pin env:NEW", OLD="654321", NEW="123456")
  '';
}
