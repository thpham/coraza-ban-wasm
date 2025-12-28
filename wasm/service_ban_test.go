package main

import (
	"testing"
)

func TestNewBanService(t *testing.T) {
	config := DefaultConfig()
	logger := NewMockLogger()
	banStore := NewMockBanStore()
	scoreStore := NewMockScoreStore()
	redisClient := NewMockRedisClient(false)

	service := NewBanService(config, logger, banStore, scoreStore, redisClient)

	if service == nil {
		t.Fatal("NewBanService returned nil")
	}
	if service.config != config {
		t.Error("config not set correctly")
	}
}

func TestNewBanService_NilRedisClient(t *testing.T) {
	config := DefaultConfig()
	logger := NewMockLogger()
	banStore := NewMockBanStore()
	scoreStore := NewMockScoreStore()

	// Should not panic with nil redisClient
	service := NewBanService(config, logger, banStore, scoreStore, nil)

	if service == nil {
		t.Fatal("NewBanService returned nil")
	}
	// Should have NoopRedisClient
	if service.redisClient == nil {
		t.Error("redisClient should not be nil")
	}
}

func TestBanService_CheckBan_NotBanned(t *testing.T) {
	config := DefaultConfig()
	logger := NewMockLogger()
	banStore := NewMockBanStore()
	scoreStore := NewMockScoreStore()
	redisClient := NewMockRedisClient(false)

	service := NewBanService(config, logger, banStore, scoreStore, redisClient)

	result := service.CheckBan("test-fingerprint")

	if result.IsBanned {
		t.Error("expected not banned")
	}
	if result.Entry != nil {
		t.Error("expected nil entry")
	}
	if banStore.CheckCalls != 1 {
		t.Errorf("expected 1 CheckBan call, got %d", banStore.CheckCalls)
	}
}

func TestBanService_CheckBan_Banned(t *testing.T) {
	config := DefaultConfig()
	logger := NewMockLogger()
	banStore := NewMockBanStore()
	scoreStore := NewMockScoreStore()
	redisClient := NewMockRedisClient(false)
	eventHandler := NewMockEventHandler()

	// Pre-populate ban
	entry := NewBanEntry("test-fingerprint", "test-reason", "rule-123", "high", 600)
	banStore.Bans["test-fingerprint"] = entry

	service := NewBanService(config, logger, banStore, scoreStore, redisClient)
	service.SetEventHandler(eventHandler)

	result := service.CheckBan("test-fingerprint")

	if !result.IsBanned {
		t.Error("expected banned")
	}
	if result.Entry == nil {
		t.Error("expected non-nil entry")
	}
	if result.Entry.RuleID != "rule-123" {
		t.Errorf("expected rule-123, got %s", result.Entry.RuleID)
	}
	// Should emit enforced event
	if len(eventHandler.Events) != 1 {
		t.Errorf("expected 1 event, got %d", len(eventHandler.Events))
	}
	if eventHandler.Events[0].Type != BanEventEnforced {
		t.Errorf("expected enforced event, got %s", eventHandler.Events[0].Type)
	}
}

func TestBanService_CheckBan_EmptyFingerprint(t *testing.T) {
	config := DefaultConfig()
	logger := NewMockLogger()
	banStore := NewMockBanStore()
	scoreStore := NewMockScoreStore()
	redisClient := NewMockRedisClient(false)

	service := NewBanService(config, logger, banStore, scoreStore, redisClient)

	result := service.CheckBan("")

	if result.IsBanned {
		t.Error("empty fingerprint should not be banned")
	}
	// Should log warning
	if len(logger.WarnMessages) != 1 {
		t.Errorf("expected 1 warning, got %d", len(logger.WarnMessages))
	}
}

func TestBanService_IssueBan_DirectBan(t *testing.T) {
	config := DefaultConfig()
	config.ScoringEnabled = false
	logger := NewMockLogger()
	banStore := NewMockBanStore()
	scoreStore := NewMockScoreStore()
	redisClient := NewMockRedisClient(false)
	eventHandler := NewMockEventHandler()

	service := NewBanService(config, logger, banStore, scoreStore, redisClient)
	service.SetEventHandler(eventHandler)

	metadata := &CorazaMetadata{
		Action:   "block",
		RuleID:   "rule-456",
		Severity: "critical",
	}

	result := service.IssueBan("test-fingerprint", metadata)

	if !result.Issued {
		t.Error("expected ban to be issued")
	}
	if result.Entry == nil {
		t.Error("expected non-nil entry")
	}
	if result.Entry.RuleID != "rule-456" {
		t.Errorf("expected rule-456, got %s", result.Entry.RuleID)
	}
	// Should be stored in ban store
	if banStore.SetCalls != 1 {
		t.Errorf("expected 1 SetBan call, got %d", banStore.SetCalls)
	}
	// Should emit issued event
	if len(eventHandler.Events) != 1 {
		t.Errorf("expected 1 event, got %d", len(eventHandler.Events))
	}
	if eventHandler.Events[0].Type != BanEventIssued {
		t.Errorf("expected issued event, got %s", eventHandler.Events[0].Type)
	}
}

func TestBanService_IssueBan_EmptyFingerprint(t *testing.T) {
	config := DefaultConfig()
	logger := NewMockLogger()
	banStore := NewMockBanStore()
	scoreStore := NewMockScoreStore()
	redisClient := NewMockRedisClient(false)

	service := NewBanService(config, logger, banStore, scoreStore, redisClient)

	metadata := &CorazaMetadata{Action: "block", RuleID: "rule-123"}
	result := service.IssueBan("", metadata)

	if result.Issued {
		t.Error("should not issue ban for empty fingerprint")
	}
}

func TestBanService_IssueBan_NilMetadata(t *testing.T) {
	config := DefaultConfig()
	logger := NewMockLogger()
	banStore := NewMockBanStore()
	scoreStore := NewMockScoreStore()
	redisClient := NewMockRedisClient(false)

	service := NewBanService(config, logger, banStore, scoreStore, redisClient)

	result := service.IssueBan("test-fingerprint", nil)

	if result.Issued {
		t.Error("should not issue ban for nil metadata")
	}
}

func TestBanService_IssueBan_ScoringMode_BelowThreshold(t *testing.T) {
	config := DefaultConfig()
	config.ScoringEnabled = true
	config.ScoreThreshold = 100
	logger := NewMockLogger()
	banStore := NewMockBanStore()
	scoreStore := NewMockScoreStore()
	redisClient := NewMockRedisClient(false)
	eventHandler := NewMockEventHandler()

	service := NewBanService(config, logger, banStore, scoreStore, redisClient)
	service.SetEventHandler(eventHandler)

	metadata := &CorazaMetadata{
		Action:   "block",
		RuleID:   "rule-789",
		Severity: "medium", // Default: 20 points
	}

	result := service.IssueBan("test-fingerprint", metadata)

	if result.Issued {
		t.Error("should not issue ban below threshold")
	}
	if result.Score != 20 {
		t.Errorf("expected score 20, got %d", result.Score)
	}
	// Should emit score updated event
	if len(eventHandler.Events) != 1 {
		t.Errorf("expected 1 event, got %d", len(eventHandler.Events))
	}
	if eventHandler.Events[0].Type != BanEventScoreUpdated {
		t.Errorf("expected score_updated event, got %s", eventHandler.Events[0].Type)
	}
}

func TestBanService_IssueBan_ScoringMode_ExceedsThreshold(t *testing.T) {
	config := DefaultConfig()
	config.ScoringEnabled = true
	config.ScoreThreshold = 50
	logger := NewMockLogger()
	banStore := NewMockBanStore()
	scoreStore := NewMockScoreStore()
	redisClient := NewMockRedisClient(false)
	eventHandler := NewMockEventHandler()

	// Pre-populate score near threshold
	scoreStore.Scores["test-fingerprint"] = &ScoreEntry{
		Fingerprint: "test-fingerprint",
		Score:       40,
	}

	service := NewBanService(config, logger, banStore, scoreStore, redisClient)
	service.SetEventHandler(eventHandler)

	metadata := &CorazaMetadata{
		Action:   "block",
		RuleID:   "rule-789",
		Severity: "medium", // Default: 20 points
	}

	result := service.IssueBan("test-fingerprint", metadata)

	// 40 + 20 = 60 > 50 threshold
	if !result.Issued {
		t.Error("should issue ban when exceeding threshold")
	}
	if result.Score != 60 {
		t.Errorf("expected score 60, got %d", result.Score)
	}
	// Should emit both score_updated and issued events
	if len(eventHandler.Events) != 2 {
		t.Errorf("expected 2 events, got %d", len(eventHandler.Events))
	}
}

func TestBanService_IssueBan_ScoringMode_RedisSyncCalled(t *testing.T) {
	config := DefaultConfig()
	config.ScoringEnabled = true
	config.ScoreThreshold = 100
	logger := NewMockLogger()
	banStore := NewMockBanStore()
	scoreStore := NewMockScoreStore()
	redisClient := NewMockRedisClient(true) // Configured

	service := NewBanService(config, logger, banStore, scoreStore, redisClient)

	metadata := &CorazaMetadata{
		Action:   "block",
		RuleID:   "rule-789",
		Severity: "medium",
	}

	service.IssueBan("test-fingerprint", metadata)

	// Should sync score to Redis
	if redisClient.IncrScoreCalls != 1 {
		t.Errorf("expected 1 IncrScoreAsync call, got %d", redisClient.IncrScoreCalls)
	}
}

func TestBanService_SyncBanFromRedis(t *testing.T) {
	config := DefaultConfig()
	logger := NewMockLogger()
	banStore := NewMockBanStore()
	scoreStore := NewMockScoreStore()
	redisClient := NewMockRedisClient(false)

	service := NewBanService(config, logger, banStore, scoreStore, redisClient)

	entry := NewBanEntry("redis-fingerprint", "reason", "rule-123", "high", 600)
	err := service.SyncBanFromRedis(entry)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	// Should be stored in local cache
	if banStore.SetCalls != 1 {
		t.Errorf("expected 1 SetBan call, got %d", banStore.SetCalls)
	}
	stored, found := banStore.Bans["redis-fingerprint"]
	if !found {
		t.Error("entry not found in store")
	}
	if stored.RuleID != "rule-123" {
		t.Errorf("expected rule-123, got %s", stored.RuleID)
	}
}

func TestBanService_SyncBanFromRedis_NilEntry(t *testing.T) {
	config := DefaultConfig()
	logger := NewMockLogger()
	banStore := NewMockBanStore()
	scoreStore := NewMockScoreStore()
	redisClient := NewMockRedisClient(false)

	service := NewBanService(config, logger, banStore, scoreStore, redisClient)

	err := service.SyncBanFromRedis(nil)

	if err != nil {
		t.Errorf("unexpected error for nil entry: %v", err)
	}
	if banStore.SetCalls != 0 {
		t.Errorf("should not call SetBan for nil entry")
	}
}

func TestBanService_SetEventHandler(t *testing.T) {
	config := DefaultConfig()
	logger := NewMockLogger()
	banStore := NewMockBanStore()
	scoreStore := NewMockScoreStore()
	redisClient := NewMockRedisClient(false)

	service := NewBanService(config, logger, banStore, scoreStore, redisClient)

	customHandler := NewMockEventHandler()
	service.SetEventHandler(customHandler)

	// Trigger an event
	banStore.Bans["test"] = NewBanEntry("test", "reason", "rule", "high", 600)
	service.CheckBan("test")

	if len(customHandler.Events) != 1 {
		t.Error("custom handler should receive events")
	}
}

func TestBanService_SetEventHandler_NilIgnored(t *testing.T) {
	config := DefaultConfig()
	logger := NewMockLogger()
	banStore := NewMockBanStore()
	scoreStore := NewMockScoreStore()
	redisClient := NewMockRedisClient(false)

	service := NewBanService(config, logger, banStore, scoreStore, redisClient)

	// Should not panic
	service.SetEventHandler(nil)
}
