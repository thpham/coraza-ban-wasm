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

func TestPluginConfig_ShouldLog_UnknownLevels(t *testing.T) {
	config := DefaultConfig()
	config.LogLevel = "unknown_level"

	// Unknown config level defaults to info (priority 1)
	// Unknown message level defaults to info (priority 1)
	if !config.ShouldLog("unknown_message") {
		t.Error("unknown levels should default to info and be logged")
	}
}

func TestPluginConfig_ShouldLog_WarnLevel(t *testing.T) {
	config := DefaultConfig()
	config.LogLevel = LogLevelWarn

	tests := []struct {
		level    string
		expected bool
	}{
		{LogLevelDebug, false},
		{LogLevelInfo, false},
		{LogLevelWarn, true},
		{LogLevelError, true},
	}

	for _, tt := range tests {
		result := config.ShouldLog(tt.level)
		if result != tt.expected {
			t.Errorf("ShouldLog(%s) with LogLevel=warn = %v, expected %v", tt.level, result, tt.expected)
		}
	}
}

func TestPluginConfig_GetScore_DefaultFallback(t *testing.T) {
	config := DefaultConfig()
	// Empty maps - should use default score of 10
	config.ScoreRules = map[string]int{}
	config.ScoreBySeverity = map[string]int{}

	score := config.GetScore("unknown-rule", "unknown-severity")

	if score != 10 {
		t.Errorf("expected default score 10, got %d", score)
	}
}

func TestPluginConfig_GetScore_SeverityFallback(t *testing.T) {
	config := DefaultConfig()
	config.ScoreRules = map[string]int{}
	config.ScoreBySeverity = map[string]int{
		"high":   40,
		"medium": 20,
	}

	// Unknown rule falls back to severity
	score := config.GetScore("unknown-rule", "medium")
	if score != 20 {
		t.Errorf("expected severity score 20, got %d", score)
	}
}

func TestPluginConfig_Validate_Valid5xxResponseCode(t *testing.T) {
	config := DefaultConfig()
	config.BanResponseCode = 503 // Valid 5xx code

	err := config.Validate()

	if err != nil {
		t.Errorf("5xx response code should be valid: %v", err)
	}
}

func TestPluginConfig_Validate_MultipleErrors(t *testing.T) {
	config := DefaultConfig()
	config.BanTTLDefault = 100000      // Invalid
	config.BanResponseCode = 200       // Invalid
	config.ScoringEnabled = true
	config.ScoreThreshold = 20000      // Invalid

	err := config.Validate()

	if err == nil {
		t.Error("expected validation errors")
	}
	// Should contain multiple error messages
	errStr := err.Error()
	if !strings.Contains(errStr, "ban_ttl_default") {
		t.Error("error should mention ban_ttl_default")
	}
	if !strings.Contains(errStr, "ban_response_code") {
		t.Error("error should mention ban_response_code")
	}
	if !strings.Contains(errStr, "score_threshold") {
		t.Error("error should mention score_threshold")
	}
}

func TestPluginConfig_Validate_ScoringDisabled_NoThresholdCheck(t *testing.T) {
	config := DefaultConfig()
	config.ScoringEnabled = false
	config.ScoreThreshold = 20000 // Would be invalid if scoring was enabled

	err := config.Validate()

	// Should pass because scoring is disabled
	if err != nil {
		t.Errorf("should not validate score_threshold when scoring disabled: %v", err)
	}
}

func TestPluginConfig_GetBanTTL_EmptySeverityMap(t *testing.T) {
	config := DefaultConfig()
	config.BanTTLDefault = 300
	config.BanTTLBySeverity = map[string]int{} // Empty

	ttl := config.GetBanTTL("critical")

	if ttl != 300 {
		t.Errorf("expected default TTL 300 with empty severity map, got %d", ttl)
	}
}

func TestPluginConfig_Validate_BoundaryBanTTL(t *testing.T) {
	// Test boundary: exactly 24 hours should be valid
	config := DefaultConfig()
	config.BanTTLDefault = 86400 // 24 hours exactly

	err := config.Validate()

	if err != nil {
		t.Errorf("24 hours TTL should be valid: %v", err)
	}
}

func TestPluginConfig_Validate_BoundaryScoreThreshold(t *testing.T) {
	// Test boundary: exactly 10000 should be valid
	config := DefaultConfig()
	config.ScoringEnabled = true
	config.ScoreThreshold = 10000

	err := config.Validate()

	if err != nil {
		t.Errorf("score threshold 10000 should be valid: %v", err)
	}
}
