package main

import (
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
)

// checkLocalBan checks if a fingerprint is banned in the local shared-data cache
func (ctx *httpContext) checkLocalBan(fingerprint string) (*BanEntry, bool) {
	key := BanKey(fingerprint)

	data, _, err := proxywasm.GetSharedData(key)
	if err != nil {
		if err != types.ErrorStatusNotFound {
			ctx.logError("failed to read ban cache for %s: %v", fingerprint, err)
		}
		return nil, false
	}

	if len(data) == 0 {
		return nil, false
	}

	entry, err := BanEntryFromJSON(data)
	if err != nil {
		ctx.logError("failed to parse ban entry for %s: %v", fingerprint, err)
		return nil, false
	}

	// Check if ban has expired
	if entry.IsExpired() {
		ctx.logDebug("ban expired for %s", fingerprint)
		// Optionally delete the expired entry
		ctx.deleteLocalBan(fingerprint)
		return nil, false
	}

	return entry, true
}

// setLocalBan stores a ban entry in the local shared-data cache
func (ctx *httpContext) setLocalBan(entry *BanEntry) error {
	key := BanKey(entry.Fingerprint)

	data, err := entry.ToJSON()
	if err != nil {
		return err
	}

	// Get current CAS value for thread-safe update
	_, cas, _ := proxywasm.GetSharedData(key)

	// Set with CAS (if cas is 0, it's a new entry)
	if err := proxywasm.SetSharedData(key, data, cas); err != nil {
		// If CAS mismatch, retry once with new CAS
		if err == types.ErrorStatusCasMismatch {
			_, newCas, _ := proxywasm.GetSharedData(key)
			return proxywasm.SetSharedData(key, data, newCas)
		}
		return err
	}

	return nil
}

// deleteLocalBan removes a ban entry from the local cache
func (ctx *httpContext) deleteLocalBan(fingerprint string) {
	key := BanKey(fingerprint)

	// Set empty value to "delete" (shared-data doesn't have delete)
	_, cas, _ := proxywasm.GetSharedData(key)
	if err := proxywasm.SetSharedData(key, []byte{}, cas); err != nil {
		ctx.logDebug("failed to delete local ban for %s: %v", fingerprint, err)
	}
}

// checkLocalScore retrieves the score entry from local cache
func (ctx *httpContext) checkLocalScore(fingerprint string) (*ScoreEntry, bool) {
	key := ScoreKey(fingerprint)

	data, _, err := proxywasm.GetSharedData(key)
	if err != nil {
		if err != types.ErrorStatusNotFound {
			ctx.logError("failed to read score cache for %s: %v", fingerprint, err)
		}
		return nil, false
	}

	if len(data) == 0 {
		return nil, false
	}

	entry, err := ScoreEntryFromJSON(data)
	if err != nil {
		ctx.logError("failed to parse score entry for %s: %v", fingerprint, err)
		return nil, false
	}

	return entry, true
}

// setLocalScore stores a score entry in the local cache
func (ctx *httpContext) setLocalScore(entry *ScoreEntry) error {
	key := ScoreKey(entry.Fingerprint)

	data, err := entry.ToJSON()
	if err != nil {
		return err
	}

	_, cas, _ := proxywasm.GetSharedData(key)

	if err := proxywasm.SetSharedData(key, data, cas); err != nil {
		if err == types.ErrorStatusCasMismatch {
			_, newCas, _ := proxywasm.GetSharedData(key)
			return proxywasm.SetSharedData(key, data, newCas)
		}
		return err
	}

	return nil
}

// updateScore updates the score for a fingerprint and returns the new total
func (ctx *httpContext) updateScore(fingerprint, ruleID, severity string, scoreIncrement int) int {
	// Get existing score entry or create new one
	entry, found := ctx.checkLocalScore(fingerprint)
	if !found {
		entry = NewScoreEntry(fingerprint)
	}

	// Apply time-based decay
	entry.DecayScore(ctx.config.ScoreDecaySeconds)

	// Add new score
	entry.AddScore(ruleID, severity, scoreIncrement)

	// Save updated entry
	if err := ctx.setLocalScore(entry); err != nil {
		ctx.logError("failed to save score entry: %v", err)
	}

	ctx.logDebug("score updated for %s: %d (added %d for rule %s)",
		fingerprint, entry.Score, scoreIncrement, ruleID)

	return entry.Score
}

// getLocalBanCount returns the number of active bans in local cache
// Note: This is expensive and should only be used for debugging/metrics
func (ctx *httpContext) getLocalBanCount() int {
	// Shared data doesn't support iteration, so we can't count
	// This would need to be tracked separately if needed
	return -1
}
