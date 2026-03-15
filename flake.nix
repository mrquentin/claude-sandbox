{
  description = "NixOS sandbox for Claude Code — OS-level isolation with bubblewrap";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-linux" ];
    in
    flake-utils.lib.eachSystem supportedSystems (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        # ── Tool profiles ──────────────────────────────────────────────
        minimalTools = with pkgs; [
          bashInteractive
          coreutils
          findutils
          gnugrep
          gnused
          gawk
          git
          ripgrep
          fd
          jq
          curl
          cacert
        ];

        defaultTools = minimalTools ++ (with pkgs; [
          gcc
          gnumake
          cmake
          python3
          nodejs_20
          tree
          less
          diffutils
          patch
          gnutar
          gzip
          which
          file
          procps
        ]);

        fullTools = defaultTools ++ (with pkgs; [
          clang
          rustc
          cargo
          go
          ninja
          pkg-config
          neovim
          tmux
          htop
          wget
          openssh
          docker-client
        ]);

        # ── Seccomp profile generator ─────────────────────────────────
        seccompProfile = pkgs.callPackage ./lib/seccomp.nix {};

        # ── Build the sandbox wrapper ─────────────────────────────────
        mkSandbox = { tools, name ? "claude-sandbox" }:
          let
            toolPath = pkgs.lib.makeBinPath tools;
            sslCertFile = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
          in
          pkgs.stdenv.mkDerivation {
            pname = name;
            version = "0.1.0";

            src = ./lib;

            nativeBuildInputs = [ pkgs.makeWrapper ];

            buildInputs = [ pkgs.bubblewrap ];

            installPhase = ''
              mkdir -p $out/bin $out/lib

              # Install library scripts
              cp detect.sh $out/lib/
              cp sanitize-git.sh $out/lib/
              cp healthcheck.sh $out/lib/
              cp security-tests.sh $out/lib/
              cp seccomp-gen.py $out/lib/
              cp config.example.json $out/lib/
              chmod +x $out/lib/*.sh $out/lib/seccomp-gen.py

              # Install seccomp profile (must succeed — sandbox refuses to start without it)
              cp ${seccompProfile}/seccomp.bpf $out/lib/seccomp.bpf

              # Install main sandbox script
              cp sandbox.sh $out/bin/${name}
              chmod +x $out/bin/${name}

              # Patch paths in the script
              substituteInPlace $out/bin/${name} \
                --replace-fail '@BWRAP@' '${pkgs.bubblewrap}/bin/bwrap' \
                --replace-fail '@TOOL_PATH@' '${toolPath}' \
                --replace-fail '@SSL_CERT_FILE@' '${sslCertFile}' \
                --replace-fail '@BASH@' '${pkgs.bashInteractive}/bin/bash' \
                --replace-fail '@LIB_DIR@' "$out/lib" \
                --replace-fail '@COREUTILS@' '${pkgs.coreutils}' \
                --replace-fail '@GIT@' '${pkgs.git}' \
                --replace-fail '@GNUSED@' '${pkgs.gnused}' \
                --replace-fail '@GNUGREP@' '${pkgs.gnugrep}' \
                --replace-fail '@PYTHON3@' '${pkgs.python3}/bin/python3' \
                --replace-fail '@JQ@' '${pkgs.jq}/bin/jq'

              substituteInPlace $out/lib/detect.sh \
                --replace-fail '@BWRAP@' '${pkgs.bubblewrap}/bin/bwrap' \
                --replace-fail '@TRUE@' '${pkgs.coreutils}/bin/true' \
                --replace-fail '@GNUGREP@' '${pkgs.gnugrep}/bin/grep' \
                --replace-fail '@COREUTILS@' '${pkgs.coreutils}'

              substituteInPlace $out/lib/sanitize-git.sh \
                --replace-fail '@GNUSED@' '${pkgs.gnused}/bin/sed' \
                --replace-fail '@GNUGREP@' '${pkgs.gnugrep}/bin/grep'

              substituteInPlace $out/lib/healthcheck.sh \
                --replace-fail '@BWRAP@' '${pkgs.bubblewrap}/bin/bwrap' \
                --replace-fail '@TOOL_PATH@' '${toolPath}' \
                --replace-fail '@SSL_CERT_FILE@' '${sslCertFile}' \
                --replace-fail '@BASH@' '${pkgs.bashInteractive}/bin/bash' \
                --replace-fail '@GIT@' '${pkgs.git}/bin/git' \
                --replace-fail '@CURL@' '${pkgs.curl}/bin/curl' \
                --replace-fail '@TRUE@' '${pkgs.coreutils}/bin/true' \
                --replace-fail '@GNUGREP@' '${pkgs.gnugrep}/bin/grep'
            '';

            meta = with pkgs.lib; {
              description = "OS-level sandbox for Claude Code using bubblewrap";
              license = licenses.mit;
              platforms = platforms.linux;
            };
          };

        sandboxDefault = mkSandbox { tools = defaultTools; };
        sandboxMinimal = mkSandbox { tools = minimalTools; name = "claude-sandbox-minimal"; };
        sandboxFull    = mkSandbox { tools = fullTools; name = "claude-sandbox-full"; };

      in {
        packages = {
          default = sandboxDefault;
          minimal = sandboxMinimal;
          full    = sandboxFull;
        };

        apps = {
          default = {
            type = "app";
            program = "${sandboxDefault}/bin/claude-sandbox";
          };
          minimal = {
            type = "app";
            program = "${sandboxMinimal}/bin/claude-sandbox-minimal";
          };
          full = {
            type = "app";
            program = "${sandboxFull}/bin/claude-sandbox-full";
          };
        };

        devShells.default = pkgs.mkShell {
          buildInputs = defaultTools ++ [
            pkgs.bubblewrap
            sandboxDefault
          ];
          shellHook = ''
            echo "claude-sandbox dev environment"
            echo "  claude-sandbox [project-dir]    — launch sandboxed Claude Code"
            echo "  claude-sandbox test             — run health checks"
            echo "  claude-sandbox --help           — show usage"
          '';
        };
      }
    ) // {
      # ── NixOS module ─────────────────────────────────────────────
      nixosModules.default = import ./modules/nixos.nix { inherit self; };
    };
}
