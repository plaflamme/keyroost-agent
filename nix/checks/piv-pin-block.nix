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
    name = "piv-pin-block";
    testScript = ''
      # Block the PIN: five wrong old PINs, each burning one try.
      host.fail("BAD=000000 NEW=000000 keyroostctl piv pin change --pin env:BAD --new-pin env:NEW")
      host.fail("BAD=000000 NEW=000000 keyroostctl piv pin change --pin env:BAD --new-pin env:NEW")
      host.fail("BAD=000000 NEW=000000 keyroostctl piv pin change --pin env:BAD --new-pin env:NEW")
      host.fail("BAD=000000 NEW=000000 keyroostctl piv pin change --pin env:BAD --new-pin env:NEW")
      host.fail("BAD=000000 NEW=000000 keyroostctl piv pin change --pin env:BAD --new-pin env:NEW")

      # PIN is blocked
      host.fail("PIN=123456 NEW=654321 keyroostctl piv pin change --pin env:PIN --new-pin env:NEW")
      # Unblock
      keyroostctl("piv pin unblock --puk env:PUK --new-pin env:NEW", PUK="12345678", NEW="654321")
      # PIN is unblocked
      keyroostctl("piv pin change --pin env:OLD --new-pin env:NEW", OLD="654321", NEW="123456")
    '';
  }
