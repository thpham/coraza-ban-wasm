# coraza-ban-wasm build commands

# Default recipe
default:
    @just --list

# Build the WASM plugin using TinyGo
build:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Building coraza-ban-wasm.wasm..."
    tinygo build -o coraza-ban-wasm.wasm -target=wasi -scheduler=none -no-debug ./wasm
    echo "Build complete:"
    ls -lh coraza-ban-wasm.wasm

# Build with debug symbols
build-debug:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Building coraza-ban-wasm.wasm with debug symbols..."
    tinygo build -o coraza-ban-wasm.wasm -target=wasi -scheduler=none ./wasm
    echo "Build complete:"
    ls -lh coraza-ban-wasm.wasm

# Run tests
test:
    go test -v ./...

# Run tests with coverage
test-coverage:
    #!/usr/bin/env bash
    set -euo pipefail
    go test -v -coverprofile=coverage.out ./...
    go tool cover -html=coverage.out -o coverage.html
    echo "Coverage report: coverage.html"

# Run linter
lint:
    golangci-lint run ./...

# Format code
fmt:
    #!/usr/bin/env bash
    set -euo pipefail
    go fmt ./...
    gofmt -s -w .

# Tidy dependencies
tidy:
    go mod tidy

# Clean build artifacts
clean:
    #!/usr/bin/env bash
    set -euo pipefail
    rm -f *.wasm
    rm -f coverage.out coverage.html
    echo "Cleaned build artifacts"

# Verify the WASM binary
verify:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Verifying WASM binary..."
    if [ -f coraza-ban-wasm.wasm ]; then
        file coraza-ban-wasm.wasm
    else
        echo "No WASM file found. Run 'just build' first."
        exit 1
    fi

# Start local Redis for testing
redis-start:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Starting Redis on port 6379..."
    redis-server --port 6379 --daemonize yes
    echo "Redis started. Stop with 'just redis-stop'"

# Stop local Redis
redis-stop:
    redis-cli shutdown || true

# Check Redis connection
redis-ping:
    redis-cli ping

# Full build cycle: format, lint, build, verify
all: fmt lint build verify

# Development workflow: tidy, test, build
dev: tidy test build

# =============================================================================
# Docker Compose - Local Integration Testing
# =============================================================================

# Download coraza-proxy-wasm for local testing (latest release)
download-coraza-wasm:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -f coraza-waf.wasm ]; then
        echo "coraza-waf.wasm already exists (delete to re-download)"
        ls -lh coraza-waf.wasm
        exit 0
    fi
    echo "Fetching latest coraza-proxy-wasm release..."
    VERSION=$(curl -sL "https://api.github.com/repos/corazawaf/coraza-proxy-wasm/releases/latest" | jq -r '.tag_name')
    echo "Downloading coraza-proxy-wasm ${VERSION}..."
    curl -sL -o coraza-proxy-wasm.zip \
        "https://github.com/corazawaf/coraza-proxy-wasm/releases/download/${VERSION}/coraza-proxy-wasm-${VERSION}.zip"
    unzip -o coraza-proxy-wasm.zip
    mv coraza-proxy-wasm.wasm coraza-waf.wasm
    rm -f coraza-proxy-wasm.zip
    echo "Downloaded: coraza-waf.wasm (${VERSION})"
    ls -lh coraza-waf.wasm

# Start local test environment
up: build download-coraza-wasm
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Starting local test environment..."
    docker compose up -d
    echo ""
    echo "Services running:"
    echo "  Envoy:   http://localhost:8080"
    echo "  Admin:   http://localhost:9901"
    echo "  Webdis:  http://localhost:7379"
    echo "  Backend: http://localhost:8081"
    echo ""
    echo "Run 'just test-ban' to test the integration"

# Stop local test environment
down:
    docker compose down

# View Envoy logs
logs:
    docker compose logs -f envoy

# View all service logs
logs-all:
    docker compose logs -f

# Rebuild WASM and restart Envoy
reload: build
    #!/usr/bin/env bash
    set -euo pipefail
    docker compose restart envoy
    echo "Envoy restarted with new WASM"

# Run integration test
test-ban:
    ./test/trigger-ban.sh

# Check ban status for a fingerprint
ban-check fp:
    curl -s "http://localhost:7379/GET/ban:{{fp}}" | jq .

# List all bans in Redis
ban-list:
    curl -s "http://localhost:7379/KEYS/ban:*" | jq .

# Clear all bans from Redis
ban-clear:
    #!/usr/bin/env bash
    set -euo pipefail
    curl -s "http://localhost:7379/FLUSHDB" | jq .
    echo "All bans cleared"

# Show Envoy stats
stats:
    #!/usr/bin/env bash
    set -euo pipefail
    curl -s "http://localhost:9901/stats" | grep -E "(wasm|ban)" || echo "No WASM stats yet"

# Full integration test cycle
integration: up
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Waiting for services to be ready..."
    sleep 3
    just test-ban
