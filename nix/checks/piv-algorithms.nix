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
    name = "piv-algorithms";
    testScript = ''
      # Test all supported key algorithms in slot 9A
      algorithms = [
          ("eccp256", False),
          ("eccp384", False),
          ("eccp521", True),
          ("rsa1024", False),
          ("rsa2048", False),
          ("rsa3072", False),
          ("rsa4096", False),
      ]

      slot="9a"
      for alg, force in algorithms:
          force_flag = " --force" if force else ""
          keyroostctl(f"piv key generate --slot {slot} --algorithm {alg} --mgmt-key env:MGMT{force_flag} --yes")
          keyroostctl(f"piv cert generate --slot {slot} --subject 'CN=Test-{alg}-{slot}' --mgmt-key env:MGMT --pin env:PIN --yes")
          keyroostctl(f"piv cert export --slot {slot} --out /tmp/cert_{alg}_{slot}.pem --overwrite")
          keyroostctl(f"piv cert import --slot {slot} --in /tmp/cert_{alg}_{slot}.pem --mgmt-key env:MGMT --yes")
          keyroostctl(f"piv cert export --slot {slot} --out /tmp/cert_{alg}_{slot}_2.pem --overwrite")
          host.succeed(f"cmp /tmp/cert_{alg}_{slot}.pem /tmp/cert_{alg}_{slot}_2.pem")
    '';
  }
