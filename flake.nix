{
  description = "Blackbird — native C++23 + Lua 5.5.1 coding harness and sovereign multi-agent Command Post";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      version = "0.3.0";

      sources = {
        "aarch64-darwin" = {
          target = "darwin-arm64";
          url = "https://github.com/antimemeai/blackbird/releases/download/v${version}/blackbird-v${version}-darwin-arm64.tar.gz";
          hash = "sha256-JG9S3S7cgl8xRkZyr3SB0jsnUGrlujQxbxh8ozqgDpo=";
        };
        "x86_64-linux" = {
          target = "linux-x86_64";
          url = "https://github.com/antimemeai/blackbird/releases/download/v${version}/blackbird-v${version}-linux-x86_64.tar.gz";
          hash = "sha256-w2eOG1vq2g9n4dsv05rx3nn9YCbHFCiCMSFE2O4MCeQ=";
        };
      };

      supportedSystems = builtins.attrNames sources;
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          inherit (pkgs) lib stdenv;
          srcInfo = sources.${system};
        in
        {
          blackbird = stdenv.mkDerivation {
            pname = "blackbird";
            inherit version;

            src = pkgs.fetchurl {
              inherit (srcInfo) url hash;
            };

            sourceRoot = "blackbird-v${version}-${srcInfo.target}";

            nativeBuildInputs = lib.optionals stdenv.hostPlatform.isLinux [
              pkgs.patchelf
            ];

            # Keep bundled LLVM 23 libc++ / OpenSSL 3 / Lua 5.5.1 shared libraries
            # and $ORIGIN/../lib RPATH completely intact.
            dontConfigure = true;
            dontBuild = true;
            dontStrip = true;
            dontPatchELF = true;

            installPhase = ''
              runHook preInstall

              mkdir -p "$out/lib/blackbird" "$out/bin"
              cp -a bin scripts share MANIFEST "$out/lib/blackbird/"
              if [ -d lib ]; then
                cp -a lib "$out/lib/blackbird/"
              fi

              ${lib.optionalString stdenv.hostPlatform.isLinux ''
                interp="$(cat "$NIX_CC/nix-support/dynamic-linker")"
                for binfile in "$out/lib/blackbird/bin/"*; do
                  if [ -f "$binfile" ] && [ -x "$binfile" ]; then
                    patchelf --set-interpreter "$interp" "$binfile"
                  fi
                done
              ''}

              cat > "$out/bin/blackbird" <<EOF
              #!/bin/sh
              set -eu
              export BLACKBIRD_SPRITE_ASSET="\''${BLACKBIRD_SPRITE_ASSET:-$out/lib/blackbird/share/blackbird/assets/sr71.png}"
              exec "$out/lib/blackbird/scripts/blackbird" "\$@"
              EOF
              chmod 755 "$out/bin/blackbird"

              runHook postInstall
            '';

            doInstallCheck = true;
            installCheckPhase = ''
              runHook preInstallCheck
              "$out/bin/blackbird" --version | grep -q "^blackbird "
              test -f "$out/lib/blackbird/share/blackbird/assets/sr71.png"
              test -f "$out/lib/blackbird/share/blackbird/programs/turn.lua"
              runHook postInstallCheck
            '';

            meta = with lib; {
              description = "Native C++23 + Lua 5.5.1 coding harness and sovereign multi-agent Command Post";
              homepage = "https://github.com/antimemeai/blackbird";
              changelog = "https://github.com/antimemeai/blackbird/releases/tag/v${version}";
              license = licenses.mit;
              mainProgram = "blackbird";
              platforms = supportedSystems;
            };
          };

          default = self.packages.${system}.blackbird;
        }
      );

      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.blackbird}/bin/blackbird";
        };
      });
    };
}
