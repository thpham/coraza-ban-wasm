{
  description = "coraza-ban-wasm - Distributed WAF-Aware Adaptive Banning System";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    { nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs =
            with pkgs;
            [
              # Go toolchain (proxy-wasm-go-sdk requires Go 1.19-1.23)
              go_1_23
              gopls
              golangci-lint
              go-tools

              # TinyGo for WASM compilation
              tinygo
              wasm-tools

              # Build tools
              just

              # Testing infrastructure
              redis
              # envoy is only available on Linux
            ]
            ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
              envoy
            ]
            ++ [
              # Utilities
              jq
              curl
              httpie
            ];

          shellHook = ''
            # Override system Go - ensure nix Go takes precedence
            export GOROOT="${pkgs.go_1_23}/share/go"
            export GOPATH="$HOME/go"
            # Filter out any system Go paths from PATH
            export PATH="${pkgs.go_1_23}/bin:$PATH"

            echo "coraza-ban-wasm development environment"
            echo ""
            echo "Development:"
            echo "  just build       - Build WASM plugin"
            echo "  just test        - Run tests"
            echo "  just lint        - Run linter"
            echo "  just fmt         - Format code"
            echo "  just clean       - Clean build artifacts"
            echo "  just all         - Full cycle: fmt, lint, build, verify"
            echo "  just dev         - Dev workflow: tidy, test, build"
            echo ""
            echo "Local Testing (Docker Compose):"
            echo "  just up          - Start local stack (Envoy + Redis + Webdis)"
            echo "  just down        - Stop local stack"
            echo "  just logs        - View Envoy logs"
            echo "  just reload      - Rebuild WASM and restart Envoy"
            echo "  just test-ban    - Run integration test"
            echo "  just integration - Full integration test cycle"
            echo ""
            echo "Ban Management:"
            echo "  just ban-list    - List all bans in Redis"
            echo "  just ban-check <fp> - Check ban status for fingerprint"
            echo "  just ban-clear   - Clear all bans"
            echo ""
            echo "TinyGo version: $(tinygo version)"
            echo "Go version: $(go version)"
          '';

          # Environment variables are set in shellHook to properly expand $HOME
          CGO_ENABLED = "0";
        };
      }
    );
}
