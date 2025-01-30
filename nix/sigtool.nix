# Copy of https://github.com/NixOS/nixpkgs/blob/d5d4a123b6001550962f7d9464bb506cabb86cb5/pkgs/development/compilers/dotnet/sigtool.nix
{ cctools
, darwin
, fetchFromGitHub
, makeWrapper
,
}:

darwin.sigtool.overrideAttrs (old: {
  # this is a fork of sigtool that supports -v and --remove-signature, which are
  # used by the dotnet sdk
  src = fetchFromGitHub {
    owner = "corngood";
    repo = "sigtool";
    rev = "new-commands";
    sha256 = "sha256-EVM5ZG3sAHrIXuWrnqA9/4pDkJOpWCeBUl5fh0mkK4k=";
  };

  nativeBuildInputs = old.nativeBuildInputs or [ ] ++ [
    makeWrapper
  ];

  postInstall =
    old.postInstall or ""
    + ''
      wrapProgram $out/bin/codesign \
        --set-default CODESIGN_ALLOCATE \
          "${cctools}/bin/${cctools.targetPrefix}codesign_allocate"
    '';
})
