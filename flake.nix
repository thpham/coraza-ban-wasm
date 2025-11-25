{
  description = "coraza-ban-wasm - Distributed WAF-Aware Adaptive Banning System";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            # Go toolchain (proxy-wasm-go-sdk requires Go 1.24+)
            go
            gopls
            golangci-lint
            go-tools

            # TinyGo for WASM compilation
            tinygo

            # Build tools
            just
            gnumake

            # Testing infrastructure
            redis
            # envoy is only available on Linux
          ] ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
            envoy
          ] ++ [
            # Utilities
            jq
            curl
            httpie
          ];

          shellHook = ''
            export GOPATH="$HOME/go"
            echo "coraza-ban-wasm development environment"
            echo ""
            echo "Available commands:"
            echo "  just build    - Build WASM plugin"
            echo "  just test     - Run tests"
            echo "  just lint     - Run linter"
            echo "  just clean    - Clean build artifacts"
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
