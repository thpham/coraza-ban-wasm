# coraza-ban-wasm

**Distributed WAF-Aware Adaptive Banning System for Istio / Envoy (WASM + Coraza + Redis)**

`coraza-ban-wasm` is a cloud-native security component designed to enhance Istio Gateway and Envoy-based ingress security by dynamically banning malicious clients. It integrates:

- **Coraza WAF events** (block/deny/log)
- A **TinyGo-based Envoy WASM filter**
- A **cluster-wide distributed banlist stored in Redis**
- **Fingerprint-based banning** (instead of unsafe IP-only bans)
- **Optional behavioral scoring**, rate-based auto-escalation, and multi-layer ban TTL policies

`coraza-ban-wasm` enables **mesh-wide, real-time IP/fingerprint blocking** triggered directly by WAF rules while avoiding collateral damage in shared NAT environments.

---

# 🎯 Objective

The goal of `coraza-ban-wasm` is to provide:

- **Real-time threat mitigation** by reacting instantly to Coraza WAF block events.
- **Distributed bans** propagated across all Envoy/Istio gateways within a cluster.
- **Intelligent fingerprint-based banning** to prevent penalizing entire NAT’ed networks.
- **Extensible and pluggable architecture** that can incorporate scoring engines, custom WAF metadata, and alternative ban sources.
- **WASM-native speed and efficiency**, running inside Envoy without modifying the control plane.

The project makes Envoy/Istio behave like a **dynamic, self-updating firewall**, driven by WAF intelligence.

---

# 🚀 System Overview

`coraza-ban-wasm` is composed of three cooperating components:

## 1. **WASM Filter (TinyGo)**

A custom Envoy WASM plugin written in **TinyGo** intercepts:

- Coraza WAF metadata (via dynamic metadata)
- Request attributes (headers, IP, TLS info)
- Existing banlist state (from shared-data + Redis)

The filter performs:

- Detection of Coraza _blocked_ events
- Calculation of a **client fingerprint**
- Local in-proxy ban caching
- Enforcement (drop or deny)
- Pushes new bans to Redis (asynchronously)

The plugin uses Envoy WASM ABI for async Redis calls and shared-data APIs for local cache.

---

## 2. **Distributed Banlist (Redis)**

`coraza-ban-wasm` uses Redis as the central ban store.

### Redis responsibilities:

- Store fingerprint keys with TTL (e.g., `ban:<fp>`)
- Support tiered TTL per severity
- Make bans instantly available cluster-wide
- Relay ban updates to multiple gateways

### Example Redis schema:

- `ban:<fingerprint>` → `{ ttl: 600s, reason: "waf-rule:930120" }`

---

## 3. **Client Fingerprint Engine**

Because full IP banning is unsafe for NAT’ed users, `coraza-ban-wasm` creates a **composite fingerprint**, typically:

```
fingerprint = sha256(
  JA3 +
  User-Agent +
  partial IP (/24) +
  optional cookie (__bm)
)
```

This reduces the risk of blocking:

- Corporate NAT users
- VPN exit nodes
- Cloud provider shared egress IPs

### Data sources:

- **JA3 TLS fingerprint** (from Envoy TLS properties)
- **User-Agent header**
- **x-forwarded-for** (extract IP prefix)
- **Optional Gateway-injected cookie** for sticky identification
- **Optional behavioral profile** (request rate, paths, anomalies)

---

# 🧠 Behavioral Scoring (Optional)

Instead of banning on first WAF block, `coraza-ban-wasm` may apply a **risk-based scoring** approach:

- +10 for a medium-risk WAF rule
- +40 for high-risk (RCE/SSRF)
- +1 per burst of 20 requests
- +5 per suspicious path (e.g., admin probes)

A ban triggers when score exceeds a threshold.

Scores can be stored locally or in Redis.

---

# 🔧 Detailed WASM Plugin Responsibilities

### 1. Hook into Envoy filter chain:

- `OnHttpRequestHeaders()`
- `OnHttpResponseHeaders()` (for cookie injection)

### 2. Read dynamic metadata from Coraza (example):

```
"envoy.filters.http.coraza": {
  "waf_action": "block",
  "rule_id": "930120",
  "severity": "high"
}
```

### 3. Build fingerprint on each request

- Compute JA3 hash from TLS context
- Extract UA
- Extract partial IP (/24)
- Extract `__bm` cookie or generate it
- Hash them into a unique key

### 4. Ban enforcement

- Check local shared-data banlist
- Check Redis cache (asynchronously)
- If banned → drop or return 403 immediately

### 5. Ban issuance

When a WAF block occurs:

- Compute fingerprint
- Write to shared-data
- Write to Redis with TTL
- Optionally record metadata

---

# 🗂️ Repository Structure

```
`coraza-ban-wasm`/
├── wasm/                     # TinyGo WASM filter code
│   ├── ban.go                # ban issuing + enforcement
│   ├── cache.go              # cache
│   ├── config.go             # config
│   ├── fingerprint.go        # fingerprint engine
│   ├── main.go               # entrypoint
│   ├── metadata.go           # Coraza metadata parsing
│   ├── redis.go              # Redis integration
│   └── utils.go
│
├── envoy/                    # Envoy config snippets
│   └── filter.yaml
│
├── istio/                    # Istio Gateway examples
│   └── gateway.yaml
│
├── operator/ (optional)      # Declarative management
│   └── crds/
│
├── docs/
│   └── architecture.md
│
└── README.md
```

---

# 📦 Build & Development

### Requirements

- TinyGo
- Go 1.22+
- Envoy or Istio with WASM enabled
- Redis

### Build WASM

```
cd wasm
tinygo build -o coraza-ban-wasm.wasm -target=wasi ./
```

### Envoy config snippet

```
http_filters:
- name: envoy.filters.http.wasm
  typed_config:
    @type: type.googleapis.com/envoy.extensions.filters.http.wasm.v3.Wasm
    config:
      name: coraza-ban-wasm
      root_id: `coraza-ban-wasm`_root
      vm_config:
        runtime: envoy.wasm.runtime.v8
        code:
          local: { filename: "coraza-ban-wasm.wasm" }
```

---

# 🛡️ Coraza WAF Integration

Coraza emits metadata when a rule is triggered. `coraza-ban-wasm` listens for:

- `waf_action = block`
- rule ID
- severity
- message or matched data (optional)

This allows `coraza-ban-wasm` to:

- Issue bans on specific rule IDs
- Prioritize critical rule classes (e.g., RCE)
- Skip low-severity/noisy rules if configured

---

# 🧩 Future Extensions

- gRPC-based control-plane operator
- Long-term analytics storage
- UI dashboard for ban management
- Distributed behavioral profiling
- ML-based anomaly detection

---

# 🏁 Summary

`coraza-ban-wasm` empowers Istio and Envoy with **WAF-aware, real-time, distributed banning** using:

- TinyGo WASM
- Coraza WAF
- Redis
- Composite client fingerprinting

It is lightweight, highly extensible, and designed for production-grade, multi-cloud environments where IP-only blocking is dangerous.
