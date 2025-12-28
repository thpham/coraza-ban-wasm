# coraza-ban-wasm

**Distributed WAF-Aware Adaptive Banning System for Istio / Envoy (WASM + Coraza + Redis)**

`coraza-ban-wasm` is a cloud-native security component designed to enhance Istio Gateway and Envoy-based ingress security by dynamically banning malicious clients. It integrates:

- **Coraza WAF events** (block/deny/log)
- A **TinyGo-based Envoy WASM filter**
- A **cluster-wide distributed banlist stored in Redis**
- **Fingerprint-based banning** (instead of unsafe IP-only bans)
- **Behavioral scoring** with time-based decay and threshold escalation
- **Event-driven architecture** for observability and monitoring

`coraza-ban-wasm` enables **mesh-wide, real-time IP/fingerprint blocking** triggered directly by WAF rules while avoiding collateral damage in shared NAT environments.

---

## Features

| Feature                  | Description                                        |
| ------------------------ | -------------------------------------------------- |
| **Real-time Banning**    | Instantly react to Coraza WAF block events         |
| **Distributed Bans**     | Cluster-wide enforcement via Redis                 |
| **Smart Fingerprinting** | Composite fingerprints avoid NAT collateral damage |
| **Behavioral Scoring**   | Risk-based scoring with time decay                 |
| **Event System**         | Pluggable event handlers for observability         |
| **Dry-Run Mode**         | Test configurations without blocking               |

---

## Quick Start

### Prerequisites

- TinyGo 0.30+
- Go 1.23+
- Envoy or Istio with WASM enabled
- Redis (via Webdis HTTP API)
- [Just](https://github.com/casey/just) task runner

### Build

```bash
# Build the WASM plugin
just build

# Run tests
just test

# Full CI cycle
just all
```

### Deploy

1. Build the WASM binary:

   ```bash
   just build
   ```

2. Configure Envoy to load the filter (see [envoy/](envoy/))

3. Configure Redis/Webdis endpoint in plugin config

---

## Architecture

### Component Overview

```
┌───────────────────────────────────────────────────────────┐
│                     Envoy Proxy                           │
│  ┌───────────────────────────────────────────────────┐    │
│  │              coraza-ban-wasm (WASM)               │    │
│  │  ┌───────────┐  ┌───────────┐  ┌───────────────┐  │    │
│  │  │ BanService│  │Fingerprint│  │MetadataService│  │    │
│  │  │           │  │  Service  │  │               │  │    │
│  │  └─────┬─────┘  └───────────┘  └───────────────┘  │    │
│  │        │                                          │    │
│  │  ┌─────┴─────┐  ┌───────────┐  ┌───────────────┐  │    │
│  │  │LocalStore │  │RedisClient│  │ EventHandler  │  │    │
│  │  │(shared-   │  │ (Webdis)  │  │               │  │    │
│  │  │  data)    │  │           │  │               │  │    │
│  │  └───────────┘  └─────┬─────┘  └───────────────┘  │    │
│  └───────────────────────┼───────────────────────────┘    │
└──────────────────────────┼────────────────────────────────┘
                           │
                    ┌──────▼──────┐
                    │    Redis    │
                    │  (Webdis)   │
                    └─────────────┘
```

### Design Principles

- **Interface-based Dependency Injection** - All services depend on interfaces
- **Compile-time Interface Verification** - `var _ Interface = (*Impl)(nil)`
- **Null Object Pattern** - Graceful degradation when Redis unavailable
- **Constructor Injection** - All dependencies via `NewXxx()` constructors

### Core Interfaces

| Interface               | Purpose                                       |
| ----------------------- | --------------------------------------------- |
| `Logger`                | Structured logging (Debug, Info, Warn, Error) |
| `BanStore`              | Ban storage (CheckBan, SetBan, DeleteBan)     |
| `ScoreStore`            | Score storage with decay                      |
| `RedisClient`           | Async Redis operations via Webdis             |
| `MetadataExtractor`     | Extract Coraza WAF metadata                   |
| `FingerprintCalculator` | Compute client fingerprints                   |
| `EventHandler`          | Handle ban lifecycle events                   |

---

## Configuration

The plugin is configured via JSON in the Envoy WASM config:

```yaml
typed_config:
  "@type": type.googleapis.com/envoy.extensions.filters.http.wasm.v3.Wasm
  config:
    name: coraza-ban-wasm
    configuration:
      "@type": type.googleapis.com/google.protobuf.StringValue
      value: |
        {
          "redis_cluster": "webdis",
          "ban_ttl_default": 600,
          "scoring_enabled": true,
          "score_threshold": 100,
          "fingerprint_mode": "full",
          "log_level": "info"
        }
```

### Configuration Options

| Option                | Type   | Default  | Description                                   |
| --------------------- | ------ | -------- | --------------------------------------------- |
| `redis_cluster`       | string | `""`     | Envoy cluster name for Redis/Webdis           |
| `ban_ttl_default`     | int    | `600`    | Default ban TTL in seconds                    |
| `ban_ttl_by_severity` | map    | `{}`     | TTL by severity (critical, high, medium, low) |
| `scoring_enabled`     | bool   | `false`  | Enable behavioral scoring                     |
| `score_threshold`     | int    | `100`    | Score threshold to trigger ban                |
| `score_decay_seconds` | int    | `60`     | Decay 1 point per interval                    |
| `score_rules`         | map    | `{}`     | Score increment by rule ID                    |
| `score_by_severity`   | map    | `{}`     | Score increment by severity                   |
| `fingerprint_mode`    | string | `"full"` | `full`, `partial`, or `ip-only`               |
| `cookie_name`         | string | `"__bm"` | Tracking cookie name                          |
| `inject_cookie`       | bool   | `false`  | Inject tracking cookie                        |
| `ban_response_code`   | int    | `403`    | HTTP status for banned requests               |
| `ban_response_body`   | string | `""`     | Response body for banned requests             |
| `log_level`           | string | `"info"` | `debug`, `info`, `warn`, `error`              |
| `dry_run`             | bool   | `false`  | Log but don't ban                             |
| `events_enabled`      | bool   | `true`   | Emit ban lifecycle events                     |

See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for detailed configuration guide.

---

## Fingerprinting

`coraza-ban-wasm` creates composite fingerprints to avoid blocking entire NAT networks:

```
fingerprint = sha256(JA3 + User-Agent + IP/24 + cookie)
```

### Fingerprint Modes

| Mode      | Components                | Use Case             |
| --------- | ------------------------- | -------------------- |
| `full`    | JA3 + UA + IP/24 + cookie | Maximum precision    |
| `partial` | UA + IP/24 + cookie       | When JA3 unavailable |
| `ip-only` | IP address only           | Simple deployments   |

---

## Behavioral Scoring

Instead of banning on first WAF block, apply risk-based scoring:

| Event             | Default Score |
| ----------------- | ------------- |
| Critical severity | +50           |
| High severity     | +40           |
| Medium severity   | +20           |
| Low severity      | +10           |

Scores decay over time (default: -1 point per 60 seconds).

Ban triggers when score exceeds threshold (default: 100).

---

## Event System

The plugin emits events for observability:

| Event Type      | Description                    |
| --------------- | ------------------------------ |
| `issued`        | New ban created                |
| `enforced`      | Ban enforced (request blocked) |
| `expired`       | Ban TTL expired                |
| `score_updated` | Score changed                  |

Events are logged via the configured `EventHandler`.

---

## Repository Structure

```
coraza-ban-wasm/
├── wasm/                        # TinyGo WASM filter source
│   ├── main.go                  # Plugin entrypoint, HTTP lifecycle
│   ├── types.go                 # Domain types (BanEntry, ScoreEntry)
│   ├── interfaces.go            # Service interfaces (7 interfaces)
│   ├── config.go                # Configuration with validation
│   ├── logger.go                # PluginLogger implementation
│   ├── events.go                # Event system
│   ├── store_local.go           # Local cache (Envoy shared-data)
│   ├── redis_client.go          # WebdisClient, NoopRedisClient
│   ├── service_ban.go           # BanService (orchestration)
│   ├── service_fingerprint.go   # FingerprintService
│   ├── service_metadata.go      # MetadataService
│   ├── *_test.go                # Unit tests (76 tests)
│   └── mocks_test.go            # Mock implementations
├── envoy/                       # Envoy configuration examples
├── istio/                       # Istio Gateway examples
├── test/                        # Integration test scripts
├── docs/                        # Documentation
├── Justfile                     # Build commands
└── README.md
```

---

## Development

### Commands

| Command      | Description          |
| ------------ | -------------------- |
| `just build` | Build WASM plugin    |
| `just test`  | Run unit tests       |
| `just lint`  | Run linter           |
| `just fmt`   | Format code          |
| `just all`   | Full CI cycle        |
| `just dev`   | Development workflow |

### Local Testing

```bash
# Start local environment (Envoy + Redis + backend)
just up

# Run integration test
just test-ban

# View logs
just logs

# Stop environment
just down
```

### Test Coverage

- 76 unit tests
- 27% code coverage (testable without WASM runtime)
- ~73% requires integration testing with Envoy

---

## Coraza WAF Integration

Coraza emits metadata when a rule is triggered:

```json
{
  "envoy.filters.http.coraza": {
    "action": "block",
    "rule_id": "930120",
    "severity": "high",
    "message": "SQL Injection detected"
  }
}
```

`coraza-ban-wasm` reads this metadata to:

- Issue bans for specific rule IDs
- Apply severity-based scoring
- Skip low-severity rules if configured
