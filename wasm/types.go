package main

import (
	"encoding/json"
	"strings"
	"time"
)

// =============================================================================
// Ban Types
// =============================================================================

// BanEntry represents a ban record stored in cache or Redis.
// It contains all information about why a client was banned and when the ban expires.
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

// NewBanEntry creates a new ban entry with the given parameters.
func NewBanEntry(fingerprint, reason, ruleID, severity string, ttl int) *BanEntry {
	now := time.Now().Unix()
	return &BanEntry{
		Fingerprint: fingerprint,
		Reason:      reason,
		RuleID:      ruleID,
		Severity:    severity,
		CreatedAt:   now,
		ExpiresAt:   now + int64(ttl),
		TTL:         ttl,
	}
}

// IsExpired returns true if the ban has expired.
func (b *BanEntry) IsExpired() bool {
	return time.Now().Unix() > b.ExpiresAt
}

// ToJSON serializes the ban entry to JSON.
func (b *BanEntry) ToJSON() ([]byte, error) {
	return json.Marshal(b)
}

// BanEntryFromJSON deserializes a ban entry from JSON.
func BanEntryFromJSON(data []byte) (*BanEntry, error) {
	var entry BanEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

// BanInfo contains detailed ban information for logging and debugging.
type BanInfo struct {
	Fingerprint string
	ClientIP    string
	UserAgent   string
	RuleID      string
	Severity    string
	TTL         int
	Score       int
	Reason      string
}

// =============================================================================
// Score Types
// =============================================================================

// ScoreEntry represents a behavioral score record for a client fingerprint.
// Scores accumulate based on WAF rule triggers and decay over time.
type ScoreEntry struct {
	Fingerprint string    `json:"fingerprint"`
	Score       int       `json:"score"`
	LastUpdated int64     `json:"last_updated"`
	RuleHits    []RuleHit `json:"rule_hits,omitempty"`
}

// RuleHit records a single WAF rule trigger event.
type RuleHit struct {
	RuleID    string `json:"rule_id"`
	Severity  string `json:"severity"`
	Score     int    `json:"score"`
	Timestamp int64  `json:"timestamp"`
}

// NewScoreEntry creates a new score entry for a fingerprint.
func NewScoreEntry(fingerprint string) *ScoreEntry {
	return &ScoreEntry{
		Fingerprint: fingerprint,
		Score:       0,
		LastUpdated: time.Now().Unix(),
		RuleHits:    []RuleHit{},
	}
}

// AddScore adds a score for a rule hit.
func (s *ScoreEntry) AddScore(ruleID, severity string, score int) {
	now := time.Now().Unix()
	s.Score += score
	s.LastUpdated = now
	s.RuleHits = append(s.RuleHits, RuleHit{
		RuleID:    ruleID,
		Severity:  severity,
		Score:     score,
		Timestamp: now,
	})
}

// DecayScore applies time-based score decay.
// The score decreases by 1 point for each decay interval that has passed.
func (s *ScoreEntry) DecayScore(decaySeconds int) {
	if decaySeconds <= 0 {
		return
	}

	now := time.Now().Unix()
	elapsed := now - s.LastUpdated

	// Decay 1 point per decaySeconds interval
	decay := int(elapsed / int64(decaySeconds))
	if decay > 0 {
		s.Score -= decay
		if s.Score < 0 {
			s.Score = 0
		}
		s.LastUpdated = now
	}
}

// ToJSON serializes the score entry to JSON.
func (s *ScoreEntry) ToJSON() ([]byte, error) {
	return json.Marshal(s)
}

// ScoreEntryFromJSON deserializes a score entry from JSON.
func ScoreEntryFromJSON(data []byte) (*ScoreEntry, error) {
	var entry ScoreEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

// =============================================================================
// WAF Metadata Types
// =============================================================================

// CorazaMetadata represents WAF decision metadata extracted from Coraza.
// This information is used to determine if a request was blocked and why.
type CorazaMetadata struct {
	// Action is the WAF decision: "block", "deny", "drop", "log", "pass"
	Action string `json:"action"`

	// RuleID is the triggered rule identifier (e.g., "930120")
	RuleID string `json:"rule_id"`

	// Severity is the rule severity: "critical", "high", "medium", "low"
	Severity string `json:"severity"`

	// Message is the rule description or matched data
	Message string `json:"message"`

	// MatchedData contains the data that triggered the rule
	MatchedData string `json:"matched_data"`

	// Tags contains rule tags (e.g., ["OWASP_CRS", "attack-sqli"])
	Tags []string `json:"tags"`
}

// IsBlocked returns true if the WAF action indicates a blocked request.
func (m *CorazaMetadata) IsBlocked() bool {
	switch strings.ToLower(m.Action) {
	case "block", "deny", "drop":
		return true
	default:
		return false
	}
}

// =============================================================================
// Key Helpers
// =============================================================================

// Key prefixes for shared data and Redis storage
const (
	banKeyPrefix   = "ban:"
	scoreKeyPrefix = "score:"
)

// BanKey returns the storage key for a fingerprint ban.
func BanKey(fingerprint string) string {
	return banKeyPrefix + fingerprint
}

// ScoreKey returns the storage key for a fingerprint score.
func ScoreKey(fingerprint string) string {
	return scoreKeyPrefix + fingerprint
}
