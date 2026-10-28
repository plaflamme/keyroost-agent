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
    name = "piv-reset";
    testScript = ''
      # Change the pin
      keyroostctl("piv pin change --pin env:PIN --new-pin env:NEW", NEW="654321")

      # Factory reset: the host burns the PIN and PUK counters itself, then sends RESET.
      keyroostctl("piv reset --yes")

      # The card is back at factory state: the factory PIN and the factory
      # management key work again.
      keyroostctl("piv retries set --pin-tries 2 --puk-tries 2 --pin env:PIN --mgmt-key env:MGMT --yes")
    '';
  }
