package main

import (
	"testing"
)

func TestNewBanEvent(t *testing.T) {
	event := NewBanEvent(BanEventIssued, "test-fp", "rule-123", "high", "local")

	if event.Type != BanEventIssued {
		t.Errorf("expected type=%s, got %s", BanEventIssued, event.Type)
	}
	if event.Fingerprint != "test-fp" {
		t.Errorf("expected fingerprint=test-fp, got %s", event.Fingerprint)
	}
	if event.RuleID != "rule-123" {
		t.Errorf("expected rule_id=rule-123, got %s", event.RuleID)
	}
	if event.Severity != "high" {
		t.Errorf("expected severity=high, got %s", event.Severity)
	}
	if event.Source != "local" {
		t.Errorf("expected source=local, got %s", event.Source)
	}
	if event.Timestamp <= 0 {
		t.Error("timestamp should be set")
	}
}

func TestNewBanEvent_AllTypes(t *testing.T) {
	types := []BanEventType{
		BanEventIssued,
		BanEventEnforced,
		BanEventExpired,
		BanEventScoreUpdated,
	}

	for _, eventType := range types {
		event := NewBanEvent(eventType, "fp", "rule", "medium", "redis")
		if event.Type != eventType {
			t.Errorf("expected type=%s, got %s", eventType, event.Type)
		}
	}
}

func TestLoggingEventHandler_OnBanEvent_Issued(t *testing.T) {
	logger := NewMockLogger()
	handler := NewLoggingEventHandler(logger)

	event := NewBanEvent(BanEventIssued, "test-fp", "rule-123", "high", "local")
	event.TTL = 600

	handler.OnBanEvent(event)

	if len(logger.InfoMessages) != 1 {
		t.Errorf("expected 1 info message, got %d", len(logger.InfoMessages))
	}
}

func TestLoggingEventHandler_OnBanEvent_Enforced(t *testing.T) {
	logger := NewMockLogger()
	handler := NewLoggingEventHandler(logger)

	event := NewBanEvent(BanEventEnforced, "test-fp", "", "", "local")

	handler.OnBanEvent(event)

	if len(logger.InfoMessages) != 1 {
		t.Errorf("expected 1 info message, got %d", len(logger.InfoMessages))
	}
}

func TestLoggingEventHandler_OnBanEvent_ScoreUpdated(t *testing.T) {
	logger := NewMockLogger()
	handler := NewLoggingEventHandler(logger)

	event := NewBanEvent(BanEventScoreUpdated, "test-fp", "rule-456", "medium", "local")
	event.Score = 50
	event.Threshold = 100

	handler.OnBanEvent(event)

	if len(logger.InfoMessages) != 1 {
		t.Errorf("expected 1 info message, got %d", len(logger.InfoMessages))
	}
}

func TestLoggingEventHandler_OnBanEvent_Expired(t *testing.T) {
	logger := NewMockLogger()
	handler := NewLoggingEventHandler(logger)

	event := NewBanEvent(BanEventExpired, "test-fp", "", "", "local")

	handler.OnBanEvent(event)

	// Expired events are logged at debug level
	if len(logger.DebugMessages) != 1 {
		t.Errorf("expected 1 debug message, got %d", len(logger.DebugMessages))
	}
}

func TestLoggingEventHandler_OnBanEvent_UnknownType(t *testing.T) {
	logger := NewMockLogger()
	handler := NewLoggingEventHandler(logger)

	event := NewBanEvent("unknown_type", "test-fp", "", "", "local")

	handler.OnBanEvent(event)

	// Unknown types are logged at debug level
	if len(logger.DebugMessages) != 1 {
		t.Errorf("expected 1 debug message, got %d", len(logger.DebugMessages))
	}
}

func TestNoopEventHandler_OnBanEvent(t *testing.T) {
	handler := NewNoopEventHandler()

	// Should not panic
	event := NewBanEvent(BanEventIssued, "test-fp", "rule-123", "high", "local")
	handler.OnBanEvent(event)

	// No way to verify no-op, but should not panic
}

func TestBanEventType_Constants(t *testing.T) {
	// Verify event type constants
	if BanEventIssued != "issued" {
		t.Error("BanEventIssued should be 'issued'")
	}
	if BanEventEnforced != "enforced" {
		t.Error("BanEventEnforced should be 'enforced'")
	}
	if BanEventExpired != "expired" {
		t.Error("BanEventExpired should be 'expired'")
	}
	if BanEventScoreUpdated != "score_updated" {
		t.Error("BanEventScoreUpdated should be 'score_updated'")
	}
}
