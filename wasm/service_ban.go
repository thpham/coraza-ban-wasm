package main

import (
	"fmt"
)

// =============================================================================
// Ban Service
// =============================================================================

// BanCheckResult contains the result of a ban check operation.
type BanCheckResult struct {
	IsBanned bool
	Entry    *BanEntry
}

// BanIssueResult contains the result of a ban issue operation.
type BanIssueResult struct {
	Issued bool
	Entry  *BanEntry
	Score  int // Current score (for score-based bans)
}

// BanService orchestrates ban checking and issuance operations.
// It uses BanStore and ScoreStore for persistence and handles
// the core ban logic independent of Redis operations.
type BanService struct {
	config       *PluginConfig
	logger       Logger
	banStore     BanStore
	scoreStore   ScoreStore
	eventHandler EventHandler
}

// NewBanService creates a new ban service.
func NewBanService(config *PluginConfig, logger Logger, banStore BanStore, scoreStore ScoreStore) *BanService {
	return &BanService{
		config:       config,
		logger:       logger,
		banStore:     banStore,
		scoreStore:   scoreStore,
		eventHandler: NewLoggingEventHandler(logger),
	}
}

// SetEventHandler sets a custom event handler for ban events.
func (s *BanService) SetEventHandler(handler EventHandler) {
	if handler != nil {
		s.eventHandler = handler
	}
}

// CheckBan checks if a fingerprint is banned in the local store.
// Returns the ban check result. Redis check should be handled separately.
func (s *BanService) CheckBan(fingerprint string) *BanCheckResult {
	if fingerprint == "" {
		s.logger.Warn("no fingerprint available, skipping ban check")
		return &BanCheckResult{IsBanned: false}
	}

	if entry, found := s.banStore.CheckBan(fingerprint); found {
		s.logger.Info("ban found in local cache for %s (rule=%s, expires=%d)",
			fingerprint, entry.RuleID, entry.ExpiresAt)

		// Emit enforced event
		event := NewBanEvent(BanEventEnforced, fingerprint, entry.RuleID, entry.Severity, "local")
		s.eventHandler.OnBanEvent(event)

		return &BanCheckResult{IsBanned: true, Entry: entry}
	}

	return &BanCheckResult{IsBanned: false}
}

// IssueBan creates a ban for a fingerprint based on WAF metadata.
// It handles both direct bans and score-based bans.
func (s *BanService) IssueBan(fingerprint string, metadata *CorazaMetadata) *BanIssueResult {
	if fingerprint == "" {
		s.logger.Warn("no fingerprint available, cannot issue ban")
		return &BanIssueResult{Issued: false}
	}

	if metadata == nil {
		s.logger.Warn("no metadata available, cannot issue ban")
		return &BanIssueResult{Issued: false}
	}

	// Get severity and rule info with defaults
	severity := metadata.Severity
	if severity == "" {
		severity = "medium"
	}

	ruleID := metadata.RuleID
	if ruleID == "" {
		ruleID = "unknown"
	}

	// Check if scoring is enabled
	if s.config.ScoringEnabled {
		return s.issueScoreBasedBan(fingerprint, ruleID, severity)
	}

	// Direct ban (no scoring)
	return s.issueDirectBan(fingerprint, ruleID, severity)
}

// issueDirectBan creates an immediate ban without scoring.
func (s *BanService) issueDirectBan(fingerprint, ruleID, severity string) *BanIssueResult {
	ttl := s.config.GetBanTTL(severity)
	reason := fmt.Sprintf("waf-rule:%s", ruleID)

	entry := NewBanEntry(fingerprint, reason, ruleID, severity, ttl)

	if err := s.banStore.SetBan(entry); err != nil {
		s.logger.Error("failed to store ban in local cache: %v", err)
		return &BanIssueResult{Issued: false}
	}

	s.logger.Info("ban issued: fingerprint=%s, rule=%s, severity=%s, ttl=%d",
		fingerprint, ruleID, severity, ttl)

	// Emit issued event
	event := NewBanEvent(BanEventIssued, fingerprint, ruleID, severity, "local")
	event.TTL = ttl
	s.eventHandler.OnBanEvent(event)

	return &BanIssueResult{Issued: true, Entry: entry}
}

// issueScoreBasedBan updates the score and bans if threshold exceeded.
func (s *BanService) issueScoreBasedBan(fingerprint, ruleID, severity string) *BanIssueResult {
	// Get score increment for this rule
	scoreIncrement := s.config.GetScore(ruleID, severity)

	// Update score using the score store
	newScore, err := s.scoreStore.IncrScore(fingerprint, scoreIncrement)
	if err != nil {
		s.logger.Error("failed to update score: %v", err)
		return &BanIssueResult{Issued: false, Score: 0}
	}

	s.logger.Info("score updated: fingerprint=%s, rule=%s, score=%d/%d",
		fingerprint, ruleID, newScore, s.config.ScoreThreshold)

	// Emit score updated event
	scoreEvent := NewBanEvent(BanEventScoreUpdated, fingerprint, ruleID, severity, "local")
	scoreEvent.Score = newScore
	scoreEvent.Threshold = s.config.ScoreThreshold
	s.eventHandler.OnBanEvent(scoreEvent)

	// Check if threshold exceeded
	if newScore >= s.config.ScoreThreshold {
		s.logger.Info("score threshold exceeded, issuing ban")

		ttl := s.config.GetBanTTL(severity)
		reason := fmt.Sprintf("score-threshold:%d", newScore)

		entry := NewBanEntry(fingerprint, reason, ruleID, severity, ttl)
		entry.Score = newScore

		if err := s.banStore.SetBan(entry); err != nil {
			s.logger.Error("failed to store ban in local cache: %v", err)
			return &BanIssueResult{Issued: false, Score: newScore}
		}

		// Emit issued event
		issuedEvent := NewBanEvent(BanEventIssued, fingerprint, ruleID, severity, "local")
		issuedEvent.TTL = ttl
		issuedEvent.Score = newScore
		s.eventHandler.OnBanEvent(issuedEvent)

		return &BanIssueResult{Issued: true, Entry: entry, Score: newScore}
	}

	return &BanIssueResult{Issued: false, Score: newScore}
}

// SyncBanFromRedis stores a ban entry received from Redis to local cache.
func (s *BanService) SyncBanFromRedis(entry *BanEntry) error {
	if entry == nil {
		return nil
	}
	return s.banStore.SetBan(entry)
}
