# Configuration Guide

This document describes all configuration options for the `coraza-ban-wasm` plugin.

## Configuration Format

The plugin is configured via JSON passed through the Envoy WASM configuration:

```yaml
http_filters:
  - name: envoy.filters.http.wasm
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.wasm.v3.Wasm
      config:
        name: coraza-ban-wasm
        root_id: coraza_ban_wasm_root
        vm_config:
          runtime: envoy.wasm.runtime.v8
          code:
            local:
              filename: "/etc/envoy/coraza-ban-wasm.wasm"
        configuration:
          "@type": type.googleapis.com/google.protobuf.StringValue
          value: |
            {
              "redis_cluster": "webdis",
              "ban_ttl_default": 600,
              "scoring_enabled": false,
              "log_level": "info"
            }
```

---

## Configuration Options

### Redis Configuration

#### `redis_cluster`

- **Type**: `string`
- **Default**: `""`
- **Description**: Name of the Envoy cluster configured for Redis/Webdis HTTP calls. If empty, Redis is disabled and only local caching is used.

```json
{
  "redis_cluster": "webdis"
}
```

The corresponding Envoy cluster must be configured:

```yaml
clusters:
  - name: webdis
    type: STRICT_DNS
    connect_timeout: 1s
    load_assignment:
      cluster_name: webdis
      endpoints:
        - lb_endpoints:
            - endpoint:
                address:
                  socket_address:
                    address: redis-webdis
                    port_value: 7379
```

---

### Ban TTL Configuration

#### `ban_ttl_default`

- **Type**: `int`
- **Default**: `600` (10 minutes)
- **Range**: `1` to `86400` (24 hours)
- **Description**: Default ban duration in seconds.

#### `ban_ttl_by_severity`

- **Type**: `map[string]int`
- **Default**: `{}`
- **Description**: Override TTL based on WAF rule severity.

```json
{
  "ban_ttl_default": 600,
  "ban_ttl_by_severity": {
    "critical": 3600,
    "high": 1800,
    "medium": 600,
    "low": 300
  }
}
```

---

### Scoring Configuration

When `scoring_enabled` is `true`, the plugin accumulates scores instead of immediately banning. A ban is issued when the score exceeds the threshold.

#### `scoring_enabled`

- **Type**: `bool`
- **Default**: `false`
- **Description**: Enable behavioral scoring mode.

#### `score_threshold`

- **Type**: `int`
- **Default**: `100`
- **Range**: `1` to `10000`
- **Description**: Score threshold that triggers a ban.

#### `score_decay_seconds`

- **Type**: `int`
- **Default**: `60`
- **Description**: Time interval for score decay. Score decreases by 1 point per interval.

#### `score_ttl`

- **Type**: `int`
- **Default**: `3600`
- **Description**: TTL for score entries in Redis (seconds).

#### `score_rules`

- **Type**: `map[string]int`
- **Default**: `{}`
- **Description**: Score increment for specific WAF rule IDs.

#### `score_by_severity`

- **Type**: `map[string]int`
- **Default**: See below
- **Description**: Default score increment by severity level.

**Default severity scores:**
| Severity | Score |
|----------|-------|
| critical | 50 |
| high | 40 |
| medium | 20 |
| low | 10 |

**Example configuration:**

```json
{
  "scoring_enabled": true,
  "score_threshold": 100,
  "score_decay_seconds": 60,
  "score_rules": {
    "930120": 50,
    "941100": 30,
    "942100": 25
  },
  "score_by_severity": {
    "critical": 60,
    "high": 40,
    "medium": 20,
    "low": 10
  }
}
```

---

### Fingerprint Configuration

#### `fingerprint_mode`

- **Type**: `string`
- **Default**: `"full"`
- **Options**: `"full"`, `"partial"`, `"ip-only"`
- **Description**: Controls fingerprint calculation method.

| Mode      | Components                        | Use Case                                   |
| --------- | --------------------------------- | ------------------------------------------ |
| `full`    | JA3 + User-Agent + IP/24 + cookie | Maximum precision, avoids NAT issues       |
| `partial` | User-Agent + IP/24 + cookie       | When JA3 is unavailable                    |
| `ip-only` | IP address only                   | Simple deployments, higher false positives |

#### `cookie_name`

- **Type**: `string`
- **Default**: `"__bm"`
- **Description**: Name of the tracking cookie used in fingerprint calculation.

#### `inject_cookie`

- **Type**: `bool`
- **Default**: `false`
- **Description**: Whether to inject the tracking cookie in responses.

```json
{
  "fingerprint_mode": "full",
  "cookie_name": "__bm",
  "inject_cookie": true
}
```

---

### Response Configuration

#### `ban_response_code`

- **Type**: `int`
- **Default**: `403`
- **Range**: `400-599`
- **Description**: HTTP status code returned for banned requests.

#### `ban_response_body`

- **Type**: `string`
- **Default**: `""`
- **Description**: Custom response body for banned requests.

```json
{
  "ban_response_code": 403,
  "ban_response_body": "Access denied. Your request has been blocked."
}
```

---

### Logging Configuration

#### `log_level`

- **Type**: `string`
- **Default**: `"info"`
- **Options**: `"debug"`, `"info"`, `"warn"`, `"error"`
- **Description**: Minimum log level for plugin messages.

| Level   | Description                   |
| ------- | ----------------------------- |
| `debug` | Verbose debugging information |
| `info`  | Normal operational messages   |
| `warn`  | Warning conditions            |
| `error` | Error conditions only         |

---

### Operational Modes

#### `dry_run`

- **Type**: `bool`
- **Default**: `false`
- **Description**: When enabled, logs ban decisions without actually blocking requests. Useful for testing configurations.

#### `events_enabled`

- **Type**: `bool`
- **Default**: `true`
- **Description**: Emit ban lifecycle events for observability. Disable to reduce logging overhead.

---

## Complete Example

```json
{
  "redis_cluster": "webdis",

  "ban_ttl_default": 600,
  "ban_ttl_by_severity": {
    "critical": 3600,
    "high": 1800,
    "medium": 600,
    "low": 300
  },

  "scoring_enabled": true,
  "score_threshold": 100,
  "score_decay_seconds": 60,
  "score_ttl": 3600,
  "score_rules": {
    "930120": 50,
    "941100": 30
  },
  "score_by_severity": {
    "critical": 60,
    "high": 40,
    "medium": 20,
    "low": 10
  },

  "fingerprint_mode": "full",
  "cookie_name": "__bm",
  "inject_cookie": false,

  "ban_response_code": 403,
  "ban_response_body": "",

  "log_level": "info",
  "dry_run": false,
  "events_enabled": true
}
```

---

## Validation Rules

The plugin validates configuration on startup:

| Field               | Validation                                      |
| ------------------- | ----------------------------------------------- |
| `ban_ttl_default`   | Must be > 0 and <= 86400 (24 hours)             |
| `score_threshold`   | Must be > 0 and <= 10000 (when scoring enabled) |
| `ban_response_code` | Must be 4xx or 5xx                              |
| `cookie_name`       | Required when `inject_cookie` is true           |
| `fingerprint_mode`  | Must be `full`, `partial`, or `ip-only`         |
| `log_level`         | Must be `debug`, `info`, `warn`, or `error`     |

Invalid values are corrected to defaults with a warning log.

---

## Environment-Specific Configurations

### Development

```json
{
  "log_level": "debug",
  "dry_run": true,
  "events_enabled": true
}
```

### Staging

```json
{
  "redis_cluster": "webdis",
  "log_level": "info",
  "dry_run": true,
  "events_enabled": true
}
```

### Production

```json
{
  "redis_cluster": "webdis",
  "ban_ttl_default": 600,
  "scoring_enabled": true,
  "score_threshold": 100,
  "log_level": "warn",
  "dry_run": false,
  "events_enabled": true
}
```
