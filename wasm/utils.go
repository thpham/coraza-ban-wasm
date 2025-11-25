package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
)

// sha256Hash computes the SHA256 hash of the input and returns it as a hex string
func sha256Hash(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

// extractIPPrefix extracts the /24 prefix from an IP address
// e.g., "192.168.1.100" -> "192.168.1"
func extractIPPrefix(ip string) string {
	// Handle IPv6 mapped IPv4 addresses
	if strings.HasPrefix(ip, "::ffff:") {
		ip = strings.TrimPrefix(ip, "::ffff:")
	}

	// Check if IPv4
	parts := strings.Split(ip, ".")
	if len(parts) == 4 {
		// Return /24 prefix (first 3 octets)
		return strings.Join(parts[:3], ".")
	}

	// For IPv6, return /48 prefix (first 3 groups)
	parts = strings.Split(ip, ":")
	if len(parts) >= 3 {
		return strings.Join(parts[:3], ":")
	}

	// Fallback to full IP
	return ip
}

// extractClientIP extracts the client IP from X-Forwarded-For or similar headers
// Returns the leftmost IP (original client) from the chain
func extractClientIP(xForwardedFor string) string {
	if xForwardedFor == "" {
		return ""
	}

	// X-Forwarded-For format: "client, proxy1, proxy2"
	// We want the leftmost (client) IP
	parts := strings.Split(xForwardedFor, ",")
	if len(parts) > 0 {
		return strings.TrimSpace(parts[0])
	}

	return xForwardedFor
}

// parseCookie extracts a specific cookie value from the Cookie header
func parseCookie(cookieHeader, name string) string {
	if cookieHeader == "" {
		return ""
	}

	cookies := strings.Split(cookieHeader, ";")
	for _, cookie := range cookies {
		cookie = strings.TrimSpace(cookie)
		if strings.HasPrefix(cookie, name+"=") {
			return strings.TrimPrefix(cookie, name+"=")
		}
	}

	return ""
}

// generateCookieValue generates a random-ish cookie value for tracking
// Note: In WASM we have limited entropy sources, so we use time + hash
func generateCookieValue() string {
	// Use current timestamp as entropy source
	timestamp := time.Now().UnixNano()
	input := string(rune(timestamp))
	return sha256Hash(input)[:16] // Use first 16 chars
}

// BanEntry represents a ban record
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

// NewBanEntry creates a new ban entry
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

// IsExpired returns true if the ban has expired
func (b *BanEntry) IsExpired() bool {
	return time.Now().Unix() > b.ExpiresAt
}

// ToJSON serializes the ban entry to JSON
func (b *BanEntry) ToJSON() ([]byte, error) {
	return json.Marshal(b)
}

// BanEntryFromJSON deserializes a ban entry from JSON
func BanEntryFromJSON(data []byte) (*BanEntry, error) {
	var entry BanEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

// ScoreEntry represents a behavioral score record
type ScoreEntry struct {
	Fingerprint string    `json:"fingerprint"`
	Score       int       `json:"score"`
	LastUpdated int64     `json:"last_updated"`
	RuleHits    []RuleHit `json:"rule_hits,omitempty"`
}

// RuleHit records a single WAF rule trigger
type RuleHit struct {
	RuleID    string `json:"rule_id"`
	Severity  string `json:"severity"`
	Score     int    `json:"score"`
	Timestamp int64  `json:"timestamp"`
}

// NewScoreEntry creates a new score entry
func NewScoreEntry(fingerprint string) *ScoreEntry {
	return &ScoreEntry{
		Fingerprint: fingerprint,
		Score:       0,
		LastUpdated: time.Now().Unix(),
		RuleHits:    []RuleHit{},
	}
}

// AddScore adds a score for a rule hit
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

// DecayScore applies time-based score decay
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

// ToJSON serializes the score entry to JSON
func (s *ScoreEntry) ToJSON() ([]byte, error) {
	return json.Marshal(s)
}

// ScoreEntryFromJSON deserializes a score entry from JSON
func ScoreEntryFromJSON(data []byte) (*ScoreEntry, error) {
	var entry ScoreEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

// banKeyPrefix is the prefix for ban keys in shared data
const banKeyPrefix = "ban:"

// scoreKeyPrefix is the prefix for score keys in shared data
const scoreKeyPrefix = "score:"

// BanKey returns the shared data key for a fingerprint ban
func BanKey(fingerprint string) string {
	return banKeyPrefix + fingerprint
}

// ScoreKey returns the shared data key for a fingerprint score
func ScoreKey(fingerprint string) string {
	return scoreKeyPrefix + fingerprint
}
