{
  pkgs,
  optionsDoc,
  rustdoc,
  ...
}:
let
  ndgToml = pkgs.writeText "ndg.toml" ''
    title = "keyroost-agent Documentation"
    revision = "main"
    footer_text = "<a href=\"https://github.com/plaflamme/keyroost-agent\">keyroost-agent</a>"
  '';
in
pkgs.stdenv.mkDerivation {
  name = "keyroost-agent-docs";
  src = ../.;

  nativeBuildInputs = [ pkgs.ndg ];

  buildPhase = ''
    mkdir -p input
    cp -rL ./docs/* input

    # Run NDG directly on the generated options.json
    # This will output a structured, complete HTML document set
    ndg --config-file ${ndgToml} \
      html \
      --module-options ${optionsDoc.optionsJSON}/share/doc/nixos/options.json \
      --options-filter-prefix services.keyroost-agent \
      --input-dir ./input \
      --output-dir ./dist
  '';

  installPhase = ''
    mkdir -p $out
    cp -r dist/* $out/
    cp -r ${rustdoc}/share/doc $out/rustdoc
  '';
}
