# Architecture Guide

This document describes the internal architecture of `coraza-ban-wasm`.

## Overview

`coraza-ban-wasm` is a TinyGo-based WASM plugin for Envoy that provides distributed WAF-aware banning. It follows interface-based design principles for testability and maintainability.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           Envoy Proxy                                   │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │                    coraza-ban-wasm (WASM Plugin)                   │ │
│  │                                                                    │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │ │
│  │  │  httpContext │  │pluginContext │  │      vmContext           │  │ │
│  │  │  (per-req)   │  │  (per-VM)    │  │      (global)            │  │ │
│  │  └──────┬───────┘  └──────────────┘  └──────────────────────────┘  │ │
│  │         │                                                          │ │
│  │  ┌──────▼───────────────────────────────────────────────────────┐  │ │
│  │  │                      Service Layer                           │  │ │
│  │  │  ┌────────────┐  ┌─────────────────┐  ┌───────────────────┐  │  │ │
│  │  │  │ BanService │  │FingerprintService│ │ MetadataService   │  │  │ │
│  │  │  └──────┬─────┘  └─────────────────┘  └───────────────────┘  │  │ │
│  │  └─────────┼────────────────────────────────────────────────────┘  │ │
│  │            │                                                       │ │
│  │  ┌─────────▼────────────────────────────────────────────────────┐  │ │
│  │  │                    Infrastructure Layer                      │  │ │
│  │  │  ┌─────────────┐ ┌───────────────┐ ┌───────────────────────┐ │  │ │
│  │  │  │LocalBanStore│ │LocalScoreStore│ │     WebdisClient      │ │  │ │
│  │  │  │(shared-data)│ │ (shared-data) │ │    (Redis HTTP)       │ │  │ │
│  │  │  └─────────────┘ └───────────────┘ └───────────┬───────────┘ │  │ │
│  │  │                                                │             │  │ │
│  │  │  ┌────────────┐  ┌─────────────────────────────┼────────────┐│  │ │
│  │  │  │PluginLogger│  │      EventHandler           │            ││  │ │
│  │  │  └────────────┘  │  (LoggingEventHandler)      │            ││  │ │
│  │  │                  └─────────────────────────────┼────────────┘│  │ │
│  │  └────────────────────────────────────────────────┼─────────────┘  │ │
│  └───────────────────────────────────────────────────┼────────────────┘ │
└──────────────────────────────────────────────────────┼──────────────────┘
                                                       │
                                                ┌──────▼──────┐
                                                │    Redis    │
                                                │  (Webdis)   │
                                                └─────────────┘
```

---

## Design Principles

### 1. Interface-Based Dependency Injection

All services depend on interfaces, not concrete implementations:

```go
type BanService struct {
    config       *PluginConfig
    logger       Logger           // Interface
    banStore     BanStore         // Interface
    scoreStore   ScoreStore       // Interface
    redisClient  RedisClient      // Interface
    eventHandler EventHandler     // Interface
}
```

This enables:

- Unit testing with mock implementations
- Swappable implementations
- Clear contracts between components

### 2. Compile-Time Interface Verification

Every implementation includes a compile-time check:

```go
// At the bottom of each implementation file
var _ BanStore = (*LocalBanStore)(nil)
var _ RedisClient = (*WebdisClient)(nil)
var _ EventHandler = (*LoggingEventHandler)(nil)
```

This catches interface mismatches at compile time, not runtime.

### 3. Null Object Pattern

Optional dependencies use null object implementations:

- `NoopRedisClient` - When Redis is not configured
- `NoopEventHandler` - When events are disabled

```go
func NewNoopRedisClient() *NoopRedisClient {
    return &NoopRedisClient{}
}

func (c *NoopRedisClient) IsConfigured() bool { return false }
func (c *NoopRedisClient) CheckBanAsync(fp string) error { return nil }
// ... all methods are no-ops
```

### 4. Constructor Injection

All dependencies are injected via constructors:

```go
func NewBanService(
    config *PluginConfig,
    logger Logger,
    banStore BanStore,
    scoreStore ScoreStore,
    redisClient RedisClient,
) *BanService
```

---

## Core Interfaces

### Logger

```go
type Logger interface {
    Debug(format string, args ...interface{})
    Info(format string, args ...interface{})
    Warn(format string, args ...interface{})
    Error(format string, args ...interface{})
}
```

**Implementation**: `PluginLogger` (uses proxy-wasm logging)

### BanStore

```go
type BanStore interface {
    CheckBan(fingerprint string) (*BanEntry, bool)
    SetBan(entry *BanEntry) error
    DeleteBan(fingerprint string) error
}
```

**Implementation**: `LocalBanStore` (uses Envoy shared-data)

### ScoreStore

```go
type ScoreStore interface {
    GetScore(fingerprint string) (*ScoreEntry, bool)
    SetScore(entry *ScoreEntry) error
    IncrScore(fingerprint string, increment int) (int, error)
}
```

**Implementation**: `LocalScoreStore` (uses Envoy shared-data, includes decay)

### RedisClient

```go
type RedisClient interface {
    CheckBanAsync(fingerprint string) error
    SetBanAsync(entry *BanEntry) error
    DeleteBanAsync(fingerprint string) error
    IncrScoreAsync(fingerprint string, increment int) error
    GetScoreAsync(fingerprint string) error
    IsConfigured() bool
}
```

**Implementations**:

- `WebdisClient` - Async HTTP calls to Webdis
- `NoopRedisClient` - No-op for local-only mode

### MetadataExtractor

```go
type MetadataExtractor interface {
    Extract() (*CorazaMetadata, bool)
}
```

**Implementation**: `MetadataService` (reads Envoy dynamic metadata)

### FingerprintCalculator

```go
type FingerprintCalculator interface {
    Calculate() string
}
```

**Implementation**: `FingerprintService` (computes composite fingerprint)

### EventHandler

```go
type EventHandler interface {
    OnBanEvent(event *BanEvent)
}
```

**Implementations**:

- `LoggingEventHandler` - Logs events via Logger
- `NoopEventHandler` - No-op for disabled events

---

## Domain Types

### BanEntry

Represents an active ban:

```go
type BanEntry struct {
    Fingerprint string `json:"fingerprint"`
    Reason      string `json:"reason"`
    RuleID      string `json:"rule_id"`
    Severity    string `json:"severity"`
    CreatedAt   int64  `json:"created_at"`
    ExpiresAt   int64  `json:"expires_at"`
    TTL         int    `json:"ttl"`
    Score       int    `json:"score,omitempty"`
}
```

### ScoreEntry

Tracks behavioral score for a fingerprint:

```go
type ScoreEntry struct {
    Fingerprint string    `json:"fingerprint"`
    Score       int       `json:"score"`
    LastUpdated int64     `json:"last_updated"`
    RuleHits    []RuleHit `json:"rule_hits,omitempty"`
}
```

### CorazaMetadata

WAF metadata from Coraza:

```go
type CorazaMetadata struct {
    Action   string `json:"action"`
    RuleID   string `json:"rule_id"`
    Severity string `json:"severity"`
    Message  string `json:"message"`
}
```

### BanEvent

Event emitted for observability:

```go
type BanEvent struct {
    Type        BanEventType `json:"type"`
    Fingerprint string       `json:"fingerprint"`
    RuleID      string       `json:"rule_id,omitempty"`
    Severity    string       `json:"severity,omitempty"`
    Timestamp   int64        `json:"timestamp"`
    Source      string       `json:"source"`
    Score       int          `json:"score,omitempty"`
    Threshold   int          `json:"threshold,omitempty"`
    TTL         int          `json:"ttl,omitempty"`
}
```

---

## Request Flow

### 1. Request Arrives

```
OnHttpRequestHeaders()
├── Calculate fingerprint (FingerprintService)
├── Check local ban cache (LocalBanStore)
├── Check Redis ban (WebdisClient - async)
└── If banned → return 403
```

### 2. WAF Block Detected

```
OnHttpRequestHeaders()
├── Extract Coraza metadata (MetadataService)
├── If action is block/deny/drop:
│   └── BanService.IssueBan()
│       ├── If scoring enabled:
│       │   ├── Increment score
│       │   ├── Apply decay
│       │   └── If score >= threshold → issue ban
│       └── If scoring disabled:
│           └── Issue ban immediately
├── Store in local cache (LocalBanStore)
├── Store in Redis (WebdisClient - async)
└── Emit event (EventHandler)
```

### 3. Response Handling

```
OnHttpResponseHeaders()
├── If inject_cookie enabled:
│   └── Add Set-Cookie header with fingerprint cookie
└── Continue
```

---

## File Organization

| File                     | Layer    | Responsibility                       |
| ------------------------ | -------- | ------------------------------------ |
| `main.go`                | Entry    | Plugin entrypoint, context structs   |
| `types.go`               | Domain   | BanEntry, ScoreEntry, CorazaMetadata |
| `interfaces.go`          | Contract | All interface definitions            |
| `config.go`              | Domain   | Configuration parsing, validation    |
| `logger.go`              | Infra    | PluginLogger implementation          |
| `events.go`              | Domain   | Event types and handlers             |
| `store_local.go`         | Infra    | LocalBanStore, LocalScoreStore       |
| `redis_client.go`        | Infra    | WebdisClient, NoopRedisClient        |
| `service_ban.go`         | Service  | BanService (orchestration)           |
| `service_fingerprint.go` | Service  | FingerprintService                   |
| `service_metadata.go`    | Service  | MetadataService                      |
| `utils.go`               | Utility  | Helper functions                     |

---

## Testing Strategy

### Unit Tests

Test services with mock implementations:

```go
func TestBanService_CheckBan(t *testing.T) {
    logger := NewMockLogger()
    banStore := NewMockBanStore()
    scoreStore := NewMockScoreStore()
    redisClient := NewMockRedisClient()

    service := NewBanService(config, logger, banStore, scoreStore, redisClient)

    // Test scenarios
}
```

### Mock Implementations

All mocks are in `mocks_test.go`:

- `MockLogger` - Captures log messages
- `MockBanStore` - In-memory ban storage
- `MockScoreStore` - In-memory score storage
- `MockRedisClient` - Simulates Redis responses

### Coverage

- **27%** - Unit testable (types, config, services with mocks)
- **73%** - Requires WASM runtime (integration tests with Envoy)

---

## Async HTTP Pattern

Redis operations use Envoy's async HTTP call mechanism:

```go
func (c *WebdisClient) CheckBanAsync(fingerprint string) error {
    url := fmt.Sprintf("/GET/%s", BanKey(fingerprint))

    headers := [][2]string{
        {":method", "GET"},
        {":path", url},
        {":authority", c.cluster},
    }

    _, err := proxywasm.DispatchHttpCall(
        c.cluster,
        headers,
        nil,
        nil,
        c.timeout,
        c.handleCheckBanResponse,
    )

    return err
}

func (c *WebdisClient) handleCheckBanResponse(numHeaders, bodySize, numTrailers int) {
    // Process response asynchronously
}
```

---

## Extension Points

### Custom Event Handlers

Implement `EventHandler` for custom event processing:

```go
type CustomEventHandler struct {
    // Your dependencies
}

func (h *CustomEventHandler) OnBanEvent(event *BanEvent) {
    // Send to external system
}
```

### Alternative Storage

Implement `BanStore` and `ScoreStore` for different backends:

```go
type ExternalBanStore struct {
    // External storage client
}

func (s *ExternalBanStore) CheckBan(fp string) (*BanEntry, bool) {
    // Query external system
}
```

### Custom Fingerprinting

Implement `FingerprintCalculator` for custom logic:

```go
type CustomFingerprintCalculator struct {
    // Dependencies
}

func (c *CustomFingerprintCalculator) Calculate() string {
    // Custom fingerprint logic
}
```
