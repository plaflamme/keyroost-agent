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
    name = "piv-info";
    testScript = ''
      keyroostctl("piv info | grep Serial: | grep 0x01020304")
    '';
  }
