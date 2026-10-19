{
  lib,
  jdk_headless,
  fetchFromGitHub,
  maven,
  makeWrapper,
}:
maven.buildMavenPackage (finalAttrs: {
  pname = "jcardengine";
  version = "26.08.23";

  src = fetchFromGitHub {
    owner = "martinpaljak";
    repo = "JCardEngine";
    tag = "v${finalAttrs.version}";
    hash = "sha256-08oIWI2rt5u/1o73tZal9IpflcpH8Oy1q2C70B7rYBY=";
    fetchSubmodules = true;
  };

  buildOffline = true;

  # Install the vendored SDK JARs into the Maven repository layout, where
  # the pom's `install-file` executions would have put them. JARs must be
  # named `<artifactId>-<version>.jar` for Maven to resolve them.
  afterDepsSetup = ''
    echo "Installing vendored SDK JARs into Maven repository..."
    mkdir -p "$mvnDeps/.m2/oracle/javacard/api_classic/3.0.5"
    cp -v "$(pwd)/simulator/sdks/jc320v26.0_kit/lib/api_classic-3.0.5.jar" \
       "$mvnDeps/.m2/oracle/javacard/api_classic/3.0.5/api_classic-3.0.5.jar"
    mkdir -p "$mvnDeps/.m2/org/globalplatform/api/1.8"
    cp -v "$(pwd)/simulator/gpapi-globalplatform_1.8.jar" \
       "$mvnDeps/.m2/org/globalplatform/api/1.8/api-1.8.jar"
    mkdir -p "$mvnDeps/.m2/org/globalplatform/contactless/1.4"
    cp -v "$(pwd)/simulator/gpapi-contactless_1.4.jar" \
       "$mvnDeps/.m2/org/globalplatform/contactless/1.4/contactless-1.4.jar"
  '';

  mvnHash = "sha256-d4hOtOY0VPBOUw2qyL0YyZvTe00w5WnZ3MMLldBDikM=";

  manualMvnArtifacts = [
    "org.slf4j:slf4j-simple:2.0.18"
    "com.github.martinpaljak:apdu4j-remote:26.06.04"
  ];

  doCheck = false;
  mvnParameters = "-Dmaven.antrun.skip=true";

  nativeBuildInputs = [ makeWrapper ];

  installPhase = ''
    runHook preInstall

    # jcard tool: shaded executable JAR with a `jcard` launcher
    mkdir -p $out/bin $out/share/jcardengine
    cp tool/target/jcard.jar $out/share/jcardengine/jcard.jar
    makeWrapper ${jdk_headless}/bin/java $out/bin/jcard \
      --add-flag -jar \
      --add-flag ${placeholder "out"}/share/jcardengine/jcard.jar

    runHook postInstall
  '';

  meta = with lib; {
    description = "Java Card Runtime Engine for Java - run JavaCard applet source code without a physical device";
    homepage = "https://github.com/martinpaljak/JCardEngine";
    license = licenses.asl20;
    platforms = platforms.all;
  };
})
