# coraza-ban-wasm build commands

# Default recipe
default:
    @just --list

# Build the WASM plugin using TinyGo
build:
    @echo "Building coraza-ban-wasm.wasm..."
    cd wasm && tinygo build -o ../coraza-ban-wasm.wasm -target=wasi -scheduler=none -no-debug .
    @echo "Build complete: coraza-ban-wasm.wasm"
    @ls -lh coraza-ban-wasm.wasm

# Build with debug symbols
build-debug:
    @echo "Building coraza-ban-wasm.wasm with debug symbols..."
    cd wasm && tinygo build -o ../coraza-ban-wasm.wasm -target=wasi -scheduler=none .
    @echo "Build complete: coraza-ban-wasm.wasm"
    @ls -lh coraza-ban-wasm.wasm

# Run tests
test:
    go test -v ./...

# Run tests with coverage
test-coverage:
    go test -v -coverprofile=coverage.out ./...
    go tool cover -html=coverage.out -o coverage.html
    @echo "Coverage report: coverage.html"

# Run linter
lint:
    golangci-lint run ./...

# Format code
fmt:
    go fmt ./...
    gofmt -s -w .

# Tidy dependencies
tidy:
    go mod tidy

# Clean build artifacts
clean:
    rm -f *.wasm
    rm -f coverage.out coverage.html

# Verify the WASM binary
verify:
    @echo "Verifying WASM binary..."
    @file coraza-ban-wasm.wasm || echo "No WASM file found. Run 'just build' first."

# Start local Redis for testing
redis-start:
    @echo "Starting Redis on port 6379..."
    redis-server --port 6379 --daemonize yes
    @echo "Redis started. Stop with 'just redis-stop'"

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
