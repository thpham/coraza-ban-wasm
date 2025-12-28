package main

import (
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
)

// checkBan checks if the current request should be blocked
// Returns true if the client is banned
func (ctx *httpContext) checkBan() bool {
	// 1. Check local cache first using BanService (fastest)
	result := ctx.banService.CheckBan(ctx.fingerprint)
	if result.IsBanned {
		ctx.isBanned = true
		return true
	}

	// 2. Check Redis asynchronously (if configured)
	if ctx.fingerprint != "" && ctx.config.RedisCluster != "" {
		ctx.checkRedisBanAsync()
		// Note: pendingRedis will be set if we need to wait for Redis response
	}

	return false
}

// issueBan creates a ban for the current fingerprint based on WAF metadata.
// Delegates core logic to BanService, handles Redis sync separately.
func (ctx *httpContext) issueBan() {
	// Use BanService for core ban logic (local cache)
	result := ctx.banService.IssueBan(ctx.fingerprint, ctx.corazaMetadata)

	// Store in Redis asynchronously if ban was issued
	if result.Issued && result.Entry != nil && ctx.config.RedisCluster != "" {
		ctx.setRedisBanAsync(result.Entry)
	}
}

// handleRedisBanResponse processes the response from Redis ban check
func (ctx *httpContext) handleRedisBanResponse(banned bool, entry *BanEntry) {
	ctx.pendingRedis = false

	if banned && entry != nil {
		ctx.logInfo("ban found in Redis for %s", ctx.fingerprint)

		// Sync Redis data to local cache using BanService
		if err := ctx.banService.SyncBanFromRedis(entry); err != nil {
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

// resumeHttpRequest resumes a paused HTTP request
func resumeHttpRequest() error {
	// In proxy-wasm, we use ResumeHttpRequest to continue processing
	// after an async operation completes
	return proxywasm.ResumeHttpRequest()
}
