package main

import (
	"fmt"

	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
)

// checkBan checks if the current request should be blocked
// Returns true if the client is banned
func (ctx *httpContext) checkBan() bool {
	if ctx.fingerprint == "" {
		ctx.logWarn("no fingerprint available, skipping ban check")
		return false
	}

	// 1. Check local cache first (fastest)
	if entry, found := ctx.checkLocalBan(ctx.fingerprint); found {
		ctx.logInfo("ban found in local cache for %s (rule=%s, expires=%d)",
			ctx.fingerprint, entry.RuleID, entry.ExpiresAt)
		ctx.isBanned = true
		return true
	}

	// 2. Check Redis asynchronously (if configured)
	if ctx.config.RedisCluster != "" {
		ctx.checkRedisBanAsync()
		// Note: pendingRedis will be set if we need to wait for Redis response
	}

	return false
}

// issueBan creates a ban for the current fingerprint based on WAF metadata
func (ctx *httpContext) issueBan() {
	if ctx.fingerprint == "" {
		ctx.logWarn("no fingerprint available, cannot issue ban")
		return
	}

	if ctx.corazaMetadata == nil {
		ctx.logWarn("no Coraza metadata available, cannot issue ban")
		return
	}

	// Get severity and rule info
	severity := ctx.corazaMetadata.Severity
	if severity == "" {
		severity = "medium" // default severity
	}

	ruleID := ctx.corazaMetadata.RuleID
	if ruleID == "" {
		ruleID = "unknown"
	}

	// Check if scoring is enabled
	if ctx.config.ScoringEnabled {
		ctx.issueScoreBasedBan(ruleID, severity)
		return
	}

	// Direct ban (no scoring)
	ctx.issueDirectBan(ruleID, severity)
}

// issueDirectBan creates an immediate ban without scoring
func (ctx *httpContext) issueDirectBan(ruleID, severity string) {
	ttl := ctx.config.GetBanTTL(severity)
	reason := fmt.Sprintf("waf-rule:%s", ruleID)

	entry := NewBanEntry(ctx.fingerprint, reason, ruleID, severity, ttl)

	// Store in local cache
	if err := ctx.setLocalBan(entry); err != nil {
		ctx.logError("failed to store ban in local cache: %v", err)
	} else {
		ctx.logInfo("ban issued: fingerprint=%s, rule=%s, severity=%s, ttl=%d",
			ctx.fingerprint, ruleID, severity, ttl)
	}

	// Store in Redis asynchronously
	if ctx.config.RedisCluster != "" {
		ctx.setRedisBanAsync(entry)
	}
}

// issueScoreBasedBan updates the score and bans if threshold exceeded
func (ctx *httpContext) issueScoreBasedBan(ruleID, severity string) {
	// Get score increment for this rule
	scoreIncrement := ctx.config.GetScore(ruleID, severity)

	// Update score
	newScore := ctx.updateScore(ctx.fingerprint, ruleID, severity, scoreIncrement)

	ctx.logInfo("score updated: fingerprint=%s, rule=%s, score=%d/%d",
		ctx.fingerprint, ruleID, newScore, ctx.config.ScoreThreshold)

	// Check if threshold exceeded
	if newScore >= ctx.config.ScoreThreshold {
		ctx.logInfo("score threshold exceeded, issuing ban")

		ttl := ctx.config.GetBanTTL(severity)
		reason := fmt.Sprintf("score-threshold:%d", newScore)

		entry := NewBanEntry(ctx.fingerprint, reason, ruleID, severity, ttl)
		entry.Score = newScore

		// Store ban
		if err := ctx.setLocalBan(entry); err != nil {
			ctx.logError("failed to store ban in local cache: %v", err)
		}

		// Store in Redis
		if ctx.config.RedisCluster != "" {
			ctx.setRedisBanAsync(entry)
		}
	}
}

// handleRedisBanResponse processes the response from Redis ban check
func (ctx *httpContext) handleRedisBanResponse(banned bool, entry *BanEntry) {
	ctx.pendingRedis = false

	if banned && entry != nil {
		ctx.logInfo("ban found in Redis for %s", ctx.fingerprint)

		// Update local cache with Redis data
		if err := ctx.setLocalBan(entry); err != nil {
			ctx.logError("failed to sync ban to local cache: %v", err)
		}

		ctx.isBanned = true

		// Resume request processing with denial
		ctx.denyRequest()
	}

	// Resume request if it was paused
	if err := resumeHttpRequest(); err != nil {
		ctx.logError("failed to resume request: %v", err)
	}
}

// handleRedisBanSetResponse processes the response from Redis ban set
func (ctx *httpContext) handleRedisBanSetResponse(success bool) {
	if success {
		ctx.logDebug("ban successfully stored in Redis for %s", ctx.fingerprint)
	} else {
		ctx.logError("failed to store ban in Redis for %s", ctx.fingerprint)
	}
}

// handleRedisScoreResponse processes the response from Redis score operations
func (ctx *httpContext) handleRedisScoreResponse(success bool, score int) {
	if success {
		ctx.logDebug("score synced with Redis for %s: %d", ctx.fingerprint, score)
	}
}

// resumeHttpRequest resumes a paused HTTP request
func resumeHttpRequest() error {
	// In proxy-wasm, we use ResumeHttpRequest to continue processing
	// after an async operation completes
	return proxywasm.ResumeHttpRequest()
}

// BanInfo provides information about a ban for logging/debugging
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

// getBanInfo returns detailed ban information for the current request
func (ctx *httpContext) getBanInfo() *BanInfo {
	info := &BanInfo{
		Fingerprint: ctx.fingerprint,
		ClientIP:    ctx.clientIP,
		UserAgent:   ctx.userAgent,
	}

	if ctx.corazaMetadata != nil {
		info.RuleID = ctx.corazaMetadata.RuleID
		info.Severity = ctx.corazaMetadata.Severity
	}

	return info
}
