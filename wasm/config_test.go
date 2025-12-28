package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.BanTTLDefault != DefaultBanTTL {
		t.Errorf("expected BanTTLDefault=%d, got %d", DefaultBanTTL, config.BanTTLDefault)
	}
	if config.ScoreThreshold != DefaultScoreThreshold {
		t.Errorf("expected ScoreThreshold=%d, got %d", DefaultScoreThreshold, config.ScoreThreshold)
	}
	if config.FingerprintMode != FingerprintModeFull {
		t.Errorf("expected FingerprintMode=%s, got %s", FingerprintModeFull, config.FingerprintMode)
	}
	if config.LogLevel != LogLevelInfo {
		t.Errorf("expected LogLevel=%s, got %s", LogLevelInfo, config.LogLevel)
	}
	if config.BanResponseCode != 403 {
		t.Errorf("expected BanResponseCode=403, got %d", config.BanResponseCode)
	}
	if !config.EventsEnabled {
		t.Error("EventsEnabled should default to true")
	}
}

// Note: ParseConfig tests are skipped because they require proxy-wasm context.
// We test the underlying JSON parsing and validation directly instead.

func TestPluginConfig_JSONParsing(t *testing.T) {
	jsonData := `{
		"redis_cluster": "test-cluster",
		"ban_ttl_default": 300,
		"scoring_enabled": true,
		"score_threshold": 50,
		"fingerprint_mode": "ip-only",
		"log_level": "debug",
		"dry_run": true,
		"events_enabled": false
	}`

	config := DefaultConfig()
	err := json.Unmarshal([]byte(jsonData), config)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if config.RedisCluster != "test-cluster" {
		t.Errorf("expected redis_cluster=test-cluster, got %s", config.RedisCluster)
	}
	if config.BanTTLDefault != 300 {
		t.Errorf("expected ban_ttl_default=300, got %d", config.BanTTLDefault)
	}
	if !config.ScoringEnabled {
		t.Error("expected scoring_enabled=true")
	}
	if config.ScoreThreshold != 50 {
		t.Errorf("expected score_threshold=50, got %d", config.ScoreThreshold)
	}
	if config.FingerprintMode != FingerprintModeIPOnly {
		t.Errorf("expected fingerprint_mode=ip-only, got %s", config.FingerprintMode)
	}
	if config.LogLevel != LogLevelDebug {
		t.Errorf("expected log_level=debug, got %s", config.LogLevel)
	}
	if !config.DryRun {
		t.Error("expected dry_run=true")
	}
	if config.EventsEnabled {
		t.Error("expected events_enabled=false")
	}
}

func TestPluginConfig_Validate_InvalidValuesGetDefaults(t *testing.T) {
	// Test validate() method corrects invalid values
	config := &PluginConfig{
		BanTTLDefault:   -1,
		ScoreThreshold:  0,
		FingerprintMode: "invalid",
		LogLevel:        "invalid",
		CookieName:      "",
		BanResponseCode: 0,
		BanResponseBody: "",
	}

	config.validate()

	if config.BanTTLDefault != DefaultBanTTL {
		t.Errorf("invalid ban_ttl should default to %d, got %d", DefaultBanTTL, config.BanTTLDefault)
	}
	if config.ScoreThreshold != DefaultScoreThreshold {
		t.Errorf("invalid score_threshold should default to %d, got %d", DefaultScoreThreshold, config.ScoreThreshold)
	}
	if config.FingerprintMode != FingerprintModeFull {
		t.Errorf("invalid fingerprint_mode should default to %s, got %s", FingerprintModeFull, config.FingerprintMode)
	}
	if config.LogLevel != LogLevelInfo {
		t.Errorf("invalid log_level should default to %s, got %s", LogLevelInfo, config.LogLevel)
	}
}

func TestPluginConfig_Validate_ValidConfig(t *testing.T) {
	config := DefaultConfig()

	err := config.Validate()

	if err != nil {
		t.Errorf("default config should be valid: %v", err)
	}
}

func TestPluginConfig_Validate_InvalidBanTTL(t *testing.T) {
	config := DefaultConfig()
	config.BanTTLDefault = 100000 // > 24 hours

	err := config.Validate()

	if err == nil {
		t.Error("expected validation error for invalid ban_ttl")
	}
	if !strings.Contains(err.Error(), "ban_ttl_default") {
		t.Errorf("error should mention ban_ttl_default: %v", err)
	}
}

func TestPluginConfig_Validate_InvalidScoreThreshold(t *testing.T) {
	config := DefaultConfig()
	config.ScoringEnabled = true
	config.ScoreThreshold = 20000 // > 10000

	err := config.Validate()

	if err == nil {
		t.Error("expected validation error for invalid score_threshold")
	}
	if !strings.Contains(err.Error(), "score_threshold") {
		t.Errorf("error should mention score_threshold: %v", err)
	}
}

func TestPluginConfig_Validate_InvalidBanResponseCode(t *testing.T) {
	config := DefaultConfig()
	config.BanResponseCode = 200 // Not 4xx or 5xx

	err := config.Validate()

	if err == nil {
		t.Error("expected validation error for invalid ban_response_code")
	}
	if !strings.Contains(err.Error(), "ban_response_code") {
		t.Errorf("error should mention ban_response_code: %v", err)
	}
}

func TestPluginConfig_Validate_MissingCookieWhenInjecting(t *testing.T) {
	config := DefaultConfig()
	config.InjectCookie = true
	config.CookieName = ""

	err := config.Validate()

	if err == nil {
		t.Error("expected validation error for missing cookie_name")
	}
	if !strings.Contains(err.Error(), "cookie_name") {
		t.Errorf("error should mention cookie_name: %v", err)
	}
}

func TestPluginConfig_GetBanTTL_Default(t *testing.T) {
	config := DefaultConfig()
	config.BanTTLDefault = 600

	ttl := config.GetBanTTL("unknown")

	if ttl != 600 {
		t.Errorf("expected default TTL 600, got %d", ttl)
	}
}

func TestPluginConfig_GetBanTTL_BySeverity(t *testing.T) {
	config := DefaultConfig()
	config.BanTTLDefault = 600
	config.BanTTLBySeverity = map[string]int{
		"critical": 3600,
		"high":     1800,
	}

	tests := []struct {
		severity string
		expected int
	}{
		{"critical", 3600},
		{"high", 1800},
		{"medium", 600}, // Default
		{"low", 600},    // Default
	}

	for _, tt := range tests {
		ttl := config.GetBanTTL(tt.severity)
		if ttl != tt.expected {
			t.Errorf("GetBanTTL(%s) = %d, expected %d", tt.severity, ttl, tt.expected)
		}
	}
}

func TestPluginConfig_GetScore_RuleSpecific(t *testing.T) {
	config := DefaultConfig()
	config.ScoreRules = map[string]int{
		"930120": 50,
		"941100": 30,
	}

	tests := []struct {
		ruleID   string
		severity string
		expected int
	}{
		{"930120", "high", 50},   // Rule-specific takes precedence
		{"941100", "medium", 30}, // Rule-specific takes precedence
		{"unknown", "high", 40},  // Falls back to severity
		{"unknown", "low", 10},   // Falls back to severity
	}

	for _, tt := range tests {
		score := config.GetScore(tt.ruleID, tt.severity)
		if score != tt.expected {
			t.Errorf("GetScore(%s, %s) = %d, expected %d", tt.ruleID, tt.severity, score, tt.expected)
		}
	}
}

func TestPluginConfig_ShouldLog(t *testing.T) {
	config := DefaultConfig()
	config.LogLevel = LogLevelInfo

	tests := []struct {
		level    string
		expected bool
	}{
		{LogLevelDebug, false}, // Debug < Info
		{LogLevelInfo, true},   // Info == Info
		{LogLevelWarn, true},   // Warn > Info
		{LogLevelError, true},  // Error > Info
	}

	for _, tt := range tests {
		result := config.ShouldLog(tt.level)
		if result != tt.expected {
			t.Errorf("ShouldLog(%s) with LogLevel=info = %v, expected %v", tt.level, result, tt.expected)
		}
	}
}

func TestPluginConfig_ShouldLog_DebugLevel(t *testing.T) {
	config := DefaultConfig()
	config.LogLevel = LogLevelDebug

	// All levels should log when set to debug
	levels := []string{LogLevelDebug, LogLevelInfo, LogLevelWarn, LogLevelError}
	for _, level := range levels {
		if !config.ShouldLog(level) {
			t.Errorf("ShouldLog(%s) with LogLevel=debug should be true", level)
		}
	}
}

func TestPluginConfig_ShouldLog_ErrorLevel(t *testing.T) {
	config := DefaultConfig()
	config.LogLevel = LogLevelError

	tests := []struct {
		level    string
		expected bool
	}{
		{LogLevelDebug, false},
		{LogLevelInfo, false},
		{LogLevelWarn, false},
		{LogLevelError, true},
	}

	for _, tt := range tests {
		result := config.ShouldLog(tt.level)
		if result != tt.expected {
			t.Errorf("ShouldLog(%s) with LogLevel=error = %v, expected %v", tt.level, result, tt.expected)
		}
	}
}
