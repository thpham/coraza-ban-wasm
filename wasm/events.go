package main

import (
	"time"
)

// =============================================================================
// Event Types
// =============================================================================

// BanEventType represents the type of ban-related event.
type BanEventType string

const (
	// BanEventIssued is emitted when a new ban is created.
	BanEventIssued BanEventType = "issued"
	// BanEventEnforced is emitted when a ban blocks a request.
	BanEventEnforced BanEventType = "enforced"
	// BanEventExpired is emitted when a ban expires.
	BanEventExpired BanEventType = "expired"
	// BanEventScoreUpdated is emitted when a score is updated (scoring mode).
	BanEventScoreUpdated BanEventType = "score_updated"
)

// BanEvent represents a ban-related event for observability.
// Events are emitted during ban lifecycle operations for monitoring,
// alerting, and future webhook integration.
type BanEvent struct {
	// Type of the event
	Type BanEventType `json:"type"`
	// Fingerprint of the client
	Fingerprint string `json:"fingerprint"`
	// RuleID that triggered the event (if applicable)
	RuleID string `json:"rule_id,omitempty"`
	// Severity of the triggering rule
	Severity string `json:"severity,omitempty"`
	// Timestamp when the event occurred (Unix epoch seconds)
	Timestamp int64 `json:"timestamp"`
	// Source of the event (local, redis)
	Source string `json:"source"`
	// Score value (for score-related events)
	Score int `json:"score,omitempty"`
	// Threshold value (for threshold events)
	Threshold int `json:"threshold,omitempty"`
	// TTL of the ban in seconds
	TTL int `json:"ttl,omitempty"`
}

// NewBanEvent creates a new ban event with the current timestamp.
func NewBanEvent(eventType BanEventType, fingerprint, ruleID, severity, source string) *BanEvent {
	return &BanEvent{
		Type:        eventType,
		Fingerprint: fingerprint,
		RuleID:      ruleID,
		Severity:    severity,
		Timestamp:   time.Now().Unix(),
		Source:      source,
	}
}

// =============================================================================
// Event Handler Interface
// =============================================================================

// EventHandler processes ban events.
// Implementations can log events, send webhooks, update metrics, etc.
type EventHandler interface {
	// OnBanEvent is called when a ban event occurs.
	OnBanEvent(event *BanEvent)
}

// =============================================================================
// Logging Event Handler (Default Implementation)
// =============================================================================

// LoggingEventHandler logs events using the plugin logger.
// This is the default implementation for observability.
type LoggingEventHandler struct {
	logger Logger
}

// NewLoggingEventHandler creates a new logging event handler.
func NewLoggingEventHandler(logger Logger) *LoggingEventHandler {
	return &LoggingEventHandler{logger: logger}
}

// OnBanEvent logs the event details.
func (h *LoggingEventHandler) OnBanEvent(event *BanEvent) {
	switch event.Type {
	case BanEventIssued:
		h.logger.Info("ban_event: type=%s fingerprint=%s rule=%s severity=%s ttl=%d source=%s",
			event.Type, event.Fingerprint, event.RuleID, event.Severity, event.TTL, event.Source)
	case BanEventEnforced:
		h.logger.Info("ban_event: type=%s fingerprint=%s source=%s",
			event.Type, event.Fingerprint, event.Source)
	case BanEventScoreUpdated:
		h.logger.Info("ban_event: type=%s fingerprint=%s rule=%s score=%d/%d source=%s",
			event.Type, event.Fingerprint, event.RuleID, event.Score, event.Threshold, event.Source)
	case BanEventExpired:
		h.logger.Debug("ban_event: type=%s fingerprint=%s source=%s",
			event.Type, event.Fingerprint, event.Source)
	default:
		h.logger.Debug("ban_event: type=%s fingerprint=%s source=%s",
			event.Type, event.Fingerprint, event.Source)
	}
}

// =============================================================================
// Noop Event Handler (For Testing/Disabled Events)
// =============================================================================

// NoopEventHandler discards all events.
// Use this when event handling is disabled.
type NoopEventHandler struct{}

// NewNoopEventHandler creates a new no-op event handler.
func NewNoopEventHandler() *NoopEventHandler {
	return &NoopEventHandler{}
}

// OnBanEvent does nothing.
func (h *NoopEventHandler) OnBanEvent(event *BanEvent) {
	// No-op
}

// =============================================================================
// Compile-Time Interface Verification
// =============================================================================

var (
	_ EventHandler = (*LoggingEventHandler)(nil)
	_ EventHandler = (*NoopEventHandler)(nil)
)
