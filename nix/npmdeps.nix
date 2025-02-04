{ lib, stdenv, fetchNpmDeps }:
let
  inherit (lib) fileset;
in
(fetchNpmDeps {
  src = fileset.toSource {
    root = ./..;
    fileset = fileset.unions [
      ../package-lock.json
      ../package.json
      ../clijs/package.json
      ../docs/package.json
      ../niljs/package.json
      ../create-nil-hardhat-project/package.json
      ../smart-contracts/package.json
      ../explorer_backend/package.json
      ../explorer_frontend/package.json
      ../uniswap/package.json
    ];
  };
  hash = "sha256-jGDU2sne4TpmjfHtP4/kHuu4f1ZpnTsWCHup/a5bW6U=";
})
