package main

import (
	"testing"
	"time"
)

func TestNewBanEntry(t *testing.T) {
	entry := NewBanEntry("test-fp", "test-reason", "rule-123", "high", 600)

	if entry.Fingerprint != "test-fp" {
		t.Errorf("expected Fingerprint=test-fp, got %s", entry.Fingerprint)
	}
	if entry.Reason != "test-reason" {
		t.Errorf("expected Reason=test-reason, got %s", entry.Reason)
	}
	if entry.RuleID != "rule-123" {
		t.Errorf("expected RuleID=rule-123, got %s", entry.RuleID)
	}
	if entry.Severity != "high" {
		t.Errorf("expected Severity=high, got %s", entry.Severity)
	}
	if entry.TTL != 600 {
		t.Errorf("expected TTL=600, got %d", entry.TTL)
	}
	if entry.CreatedAt <= 0 {
		t.Error("CreatedAt should be set")
	}
	if entry.ExpiresAt <= entry.CreatedAt {
		t.Error("ExpiresAt should be after CreatedAt")
	}
}

func TestBanEntry_IsExpired(t *testing.T) {
	// Create entry that expires in the past
	entry := NewBanEntry("test-fp", "reason", "rule", "high", 1)
	entry.ExpiresAt = time.Now().Unix() - 10 // 10 seconds ago

	if !entry.IsExpired() {
		t.Error("entry should be expired")
	}

	// Create entry that expires in the future
	entry2 := NewBanEntry("test-fp", "reason", "rule", "high", 600)

	if entry2.IsExpired() {
		t.Error("entry should not be expired")
	}
}

func TestBanEntry_ToJSON_FromJSON(t *testing.T) {
	original := NewBanEntry("test-fp", "test-reason", "rule-123", "high", 600)
	original.Score = 75

	// Serialize
	jsonData, err := original.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	// Deserialize
	restored, err := BanEntryFromJSON(jsonData)
	if err != nil {
		t.Fatalf("BanEntryFromJSON failed: %v", err)
	}

	// Compare fields
	if restored.Fingerprint != original.Fingerprint {
		t.Errorf("Fingerprint mismatch: %s vs %s", restored.Fingerprint, original.Fingerprint)
	}
	if restored.RuleID != original.RuleID {
		t.Errorf("RuleID mismatch: %s vs %s", restored.RuleID, original.RuleID)
	}
	if restored.Severity != original.Severity {
		t.Errorf("Severity mismatch: %s vs %s", restored.Severity, original.Severity)
	}
	if restored.Score != original.Score {
		t.Errorf("Score mismatch: %d vs %d", restored.Score, original.Score)
	}
}

func TestBanEntryFromJSON_Invalid(t *testing.T) {
	_, err := BanEntryFromJSON([]byte("invalid json"))

	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestNewScoreEntry(t *testing.T) {
	entry := NewScoreEntry("test-fp")

	if entry.Fingerprint != "test-fp" {
		t.Errorf("expected Fingerprint=test-fp, got %s", entry.Fingerprint)
	}
	if entry.Score != 0 {
		t.Errorf("expected Score=0, got %d", entry.Score)
	}
	if entry.LastUpdated <= 0 {
		t.Error("LastUpdated should be set")
	}
}

func TestScoreEntry_DecayScore(t *testing.T) {
	entry := NewScoreEntry("test-fp")
	entry.Score = 100
	// Set last update to 120 seconds ago
	entry.LastUpdated = time.Now().Unix() - 120

	// Decay with 60-second intervals (should decay by 2 points)
	entry.DecayScore(60)

	if entry.Score != 98 {
		t.Errorf("expected Score=98 after decay, got %d", entry.Score)
	}
}

func TestScoreEntry_DecayScore_NoNegative(t *testing.T) {
	entry := NewScoreEntry("test-fp")
	entry.Score = 2
	// Set last update to long ago
	entry.LastUpdated = time.Now().Unix() - 3600

	// Decay should not go negative
	entry.DecayScore(60)

	if entry.Score < 0 {
		t.Errorf("Score should not be negative: %d", entry.Score)
	}
}

func TestScoreEntry_DecayScore_NoDecayIfRecent(t *testing.T) {
	entry := NewScoreEntry("test-fp")
	entry.Score = 100
	// Last update is now (0 decay periods)
	entry.LastUpdated = time.Now().Unix()

	entry.DecayScore(60)

	if entry.Score != 100 {
		t.Errorf("expected Score=100 (no decay), got %d", entry.Score)
	}
}

func TestScoreEntry_ToJSON_FromJSON(t *testing.T) {
	original := NewScoreEntry("test-fp")
	original.Score = 50

	// Serialize
	jsonData, err := original.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	// Deserialize
	restored, err := ScoreEntryFromJSON(jsonData)
	if err != nil {
		t.Fatalf("ScoreEntryFromJSON failed: %v", err)
	}

	if restored.Fingerprint != original.Fingerprint {
		t.Errorf("Fingerprint mismatch")
	}
	if restored.Score != original.Score {
		t.Errorf("Score mismatch: %d vs %d", restored.Score, original.Score)
	}
}

func TestScoreEntryFromJSON_Invalid(t *testing.T) {
	_, err := ScoreEntryFromJSON([]byte("invalid json"))

	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestCorazaMetadata_IsBlocked(t *testing.T) {
	tests := []struct {
		action   string
		expected bool
	}{
		{"block", true},
		{"deny", true},
		{"drop", true},
		{"allow", false},
		{"pass", false},
		{"", false},
	}

	for _, tt := range tests {
		meta := &CorazaMetadata{Action: tt.action}
		result := meta.IsBlocked()
		if result != tt.expected {
			t.Errorf("IsBlocked() with action=%q = %v, expected %v", tt.action, result, tt.expected)
		}
	}
}
