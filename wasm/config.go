package main

import (
	"encoding/json"

	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
)

// Fingerprint mode constants
const (
	FingerprintModeFull    = "full"
	FingerprintModePartial = "partial"
	FingerprintModeIPOnly  = "ip-only"
)

// Log level constants
const (
	LogLevelDebug = "debug"
	LogLevelInfo  = "info"
	LogLevelWarn  = "warn"
	LogLevelError = "error"
)

// Default configuration values
const (
	DefaultBanTTL         = 600
	DefaultScoreThreshold = 100
	DefaultScoreDecay     = 60
	DefaultScoreTTL       = 3600
	DefaultRedisTimeout   = 5000
)

// PluginConfig holds the runtime configuration for the coraza-ban-wasm
// Envoy WASM filter. It is parsed from JSON during plugin startup.
//
// Example configuration:
//
//	{
//	  "redis_cluster": "webdis",
//	  "ban_ttl_default": 600,
//	  "scoring_enabled": true,
//	  "score_threshold": 100,
//	  "fingerprint_mode": "full",
//	  "log_level": "info"
//	}
type PluginConfig struct {
	// RedisCluster is the name of the Envoy cluster for Redis HTTP calls
	RedisCluster string `json:"redis_cluster"`

	// BanTTLDefault is the default ban TTL in seconds (default: 600)
	BanTTLDefault int `json:"ban_ttl_default"`

	// BanTTLBySeverity maps WAF severity levels to ban TTLs
	// e.g., {"critical": 3600, "high": 1800, "medium": 600, "low": 300}
	BanTTLBySeverity map[string]int `json:"ban_ttl_by_severity"`

	// ScoringEnabled enables behavioral scoring instead of immediate banning
	ScoringEnabled bool `json:"scoring_enabled"`

	// ScoreThreshold is the score threshold that triggers a ban (default: 100)
	ScoreThreshold int `json:"score_threshold"`

	// ScoreDecaySeconds is how often scores decay by 1 point (default: 60)
	ScoreDecaySeconds int `json:"score_decay_seconds"`

	// ScoreRules maps WAF rule IDs to score increments
	// e.g., {"930120": 40, "941100": 20}
	ScoreRules map[string]int `json:"score_rules"`

	// ScoreBySeverity maps severity levels to default score increments
	// Used when a rule ID is not in ScoreRules
	ScoreBySeverity map[string]int `json:"score_by_severity"`

	// ScoreTTL is the TTL for score entries in Redis (default: 3600)
	ScoreTTL int `json:"score_ttl"`

	// FingerprintMode controls fingerprint calculation
	// "full" = JA3 + UA + IP/24 + cookie (default)
	// "partial" = UA + IP/24 + cookie (no JA3)
	// "ip-only" = IP address only
	FingerprintMode string `json:"fingerprint_mode"`

	// CookieName is the name of the tracking cookie (default: "__bm")
	CookieName string `json:"cookie_name"`

	// InjectCookie controls whether to inject the tracking cookie
	InjectCookie bool `json:"inject_cookie"`

	// BanResponseCode is the HTTP status code for banned requests (default: 403)
	BanResponseCode int `json:"ban_response_code"`

	// BanResponseBody is the response body for banned requests
	BanResponseBody string `json:"ban_response_body"`

	// LogLevel controls logging verbosity: "debug", "info", "warn", "error"
	LogLevel string `json:"log_level"`

	// DryRun enables dry-run mode (log but don't ban)
	DryRun bool `json:"dry_run"`
}

// DefaultConfig returns a PluginConfig with default values
func DefaultConfig() *PluginConfig {
	return &PluginConfig{
		RedisCluster:      "redis_cluster",
		BanTTLDefault:     DefaultBanTTL,
		BanTTLBySeverity:  map[string]int{},
		ScoringEnabled:    false,
		ScoreThreshold:    DefaultScoreThreshold,
		ScoreDecaySeconds: DefaultScoreDecay,
		ScoreRules:        map[string]int{},
		ScoreBySeverity: map[string]int{
			"critical": 50,
			"high":     40,
			"medium":   20,
			"low":      10,
		},
		ScoreTTL:        DefaultScoreTTL,
		FingerprintMode: FingerprintModeFull,
		CookieName:      "__bm",
		InjectCookie:    false,
		BanResponseCode: 403,
		BanResponseBody: "Forbidden",
		LogLevel:        LogLevelInfo,
		DryRun:          false,
	}
}

// ParseConfig parses JSON configuration data into PluginConfig
func ParseConfig(data []byte) (*PluginConfig, error) {
	config := DefaultConfig()

	if len(data) == 0 {
		proxywasm.LogInfo("No configuration provided, using defaults")
		return config, nil
	}

	if err := json.Unmarshal(data, config); err != nil {
		return nil, err
	}

	// Validate and set defaults for missing fields
	config.validate()

	return config, nil
}

// validate ensures configuration values are valid
func (c *PluginConfig) validate() {
	if c.BanTTLDefault <= 0 {
		c.BanTTLDefault = DefaultBanTTL
	}

	if c.ScoreThreshold <= 0 {
		c.ScoreThreshold = DefaultScoreThreshold
	}

	if c.ScoreDecaySeconds <= 0 {
		c.ScoreDecaySeconds = DefaultScoreDecay
	}

	if c.ScoreTTL <= 0 {
		c.ScoreTTL = DefaultScoreTTL
	}

	// Validate fingerprint mode
	validModes := map[string]bool{
		FingerprintModeFull:    true,
		FingerprintModePartial: true,
		FingerprintModeIPOnly:  true,
	}
	if !validModes[c.FingerprintMode] {
		c.FingerprintMode = FingerprintModeFull
	}

	if c.CookieName == "" {
		c.CookieName = "__bm"
	}

	if c.BanResponseCode <= 0 {
		c.BanResponseCode = 403
	}

	if c.BanResponseBody == "" {
		c.BanResponseBody = "Forbidden"
	}

	// Validate log level
	validLogLevels := map[string]bool{
		LogLevelDebug: true,
		LogLevelInfo:  true,
		LogLevelWarn:  true,
		LogLevelError: true,
	}
	if !validLogLevels[c.LogLevel] {
		c.LogLevel = LogLevelInfo
	}

	// Initialize maps if nil
	if c.BanTTLBySeverity == nil {
		c.BanTTLBySeverity = map[string]int{}
	}

	if c.ScoreRules == nil {
		c.ScoreRules = map[string]int{}
	}

	if c.ScoreBySeverity == nil {
		c.ScoreBySeverity = map[string]int{
			"critical": 50,
			"high":     40,
			"medium":   20,
			"low":      10,
		}
	}
}

// GetBanTTL returns the appropriate TTL for a given severity
func (c *PluginConfig) GetBanTTL(severity string) int {
	if ttl, ok := c.BanTTLBySeverity[severity]; ok {
		return ttl
	}
	return c.BanTTLDefault
}

// GetScore returns the score increment for a given rule ID and severity
func (c *PluginConfig) GetScore(ruleID, severity string) int {
	// Check rule-specific score first
	if score, ok := c.ScoreRules[ruleID]; ok {
		return score
	}

	// Fall back to severity-based score
	if score, ok := c.ScoreBySeverity[severity]; ok {
		return score
	}

	// Default score
	return 10
}

// logLevelPriority maps log level strings to their priority values.
// Higher values mean more severe/important messages.
var logLevelPriority = map[string]int{
	LogLevelDebug: 0,
	LogLevelInfo:  1,
	LogLevelWarn:  2,
	LogLevelError: 3,
}

// ShouldLog returns true if the given level should be logged
// based on the configured log level.
func (c *PluginConfig) ShouldLog(level string) bool {
	configLevel, ok := logLevelPriority[c.LogLevel]
	if !ok {
		configLevel = 1 // default to info
	}

	messageLevel, ok := logLevelPriority[level]
	if !ok {
		messageLevel = 1
	}

	return messageLevel >= configLevel
}
