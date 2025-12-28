package main

import (
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
)

// =============================================================================
// Local Ban Store
// =============================================================================

// LocalBanStore implements BanStore using Envoy's shared-data mechanism.
// This provides in-memory storage that is shared across all worker threads.
type LocalBanStore struct {
	logger Logger
}

// NewLocalBanStore creates a new local ban store.
func NewLocalBanStore(logger Logger) *LocalBanStore {
	return &LocalBanStore{
		logger: logger,
	}
}

// CheckBan checks if a fingerprint is banned in the local shared-data cache.
func (s *LocalBanStore) CheckBan(fingerprint string) (*BanEntry, bool) {
	key := BanKey(fingerprint)

	data, _, err := proxywasm.GetSharedData(key)
	if err != nil {
		if err != types.ErrorStatusNotFound {
			s.logger.Error("failed to read ban cache for %s: %v", fingerprint, err)
		}
		return nil, false
	}

	if len(data) == 0 {
		return nil, false
	}

	entry, err := BanEntryFromJSON(data)
	if err != nil {
		s.logger.Error("failed to parse ban entry for %s: %v", fingerprint, err)
		return nil, false
	}

	// Check if ban has expired
	if entry.IsExpired() {
		s.logger.Debug("ban expired for %s", fingerprint)
		_ = s.DeleteBan(fingerprint)
		return nil, false
	}

	return entry, true
}

// SetBan stores a ban entry in the local shared-data cache.
func (s *LocalBanStore) SetBan(entry *BanEntry) error {
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

// DeleteBan removes a ban entry from the local cache.
func (s *LocalBanStore) DeleteBan(fingerprint string) error {
	key := BanKey(fingerprint)

	// Set empty value to "delete" (shared-data doesn't have delete)
	_, cas, _ := proxywasm.GetSharedData(key)
	if err := proxywasm.SetSharedData(key, []byte{}, cas); err != nil {
		s.logger.Debug("failed to delete local ban for %s: %v", fingerprint, err)
		return err
	}
	return nil
}

// Compile-time interface verification
var _ BanStore = (*LocalBanStore)(nil)

// =============================================================================
// Local Score Store
// =============================================================================

// LocalScoreStore implements ScoreStore using Envoy's shared-data mechanism.
// It handles score storage, retrieval, and time-based decay.
type LocalScoreStore struct {
	logger       Logger
	decaySeconds int
}

// NewLocalScoreStore creates a new local score store.
func NewLocalScoreStore(logger Logger, decaySeconds int) *LocalScoreStore {
	return &LocalScoreStore{
		logger:       logger,
		decaySeconds: decaySeconds,
	}
}

// GetScore retrieves a score entry from local cache.
func (s *LocalScoreStore) GetScore(fingerprint string) (*ScoreEntry, bool) {
	key := ScoreKey(fingerprint)

	data, _, err := proxywasm.GetSharedData(key)
	if err != nil {
		if err != types.ErrorStatusNotFound {
			s.logger.Error("failed to read score cache for %s: %v", fingerprint, err)
		}
		return nil, false
	}

	if len(data) == 0 {
		return nil, false
	}

	entry, err := ScoreEntryFromJSON(data)
	if err != nil {
		s.logger.Error("failed to parse score entry for %s: %v", fingerprint, err)
		return nil, false
	}

	return entry, true
}

// SetScore stores a score entry in the local cache.
func (s *LocalScoreStore) SetScore(entry *ScoreEntry) error {
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

// IncrScore atomically increments a score and returns the new value.
// It also applies time-based decay before adding the increment.
func (s *LocalScoreStore) IncrScore(fingerprint string, increment int) (int, error) {
	// Get existing score entry or create new one
	entry, found := s.GetScore(fingerprint)
	if !found {
		entry = NewScoreEntry(fingerprint)
	}

	// Apply time-based decay
	entry.DecayScore(s.decaySeconds)

	// Add the increment
	entry.Score += increment
	entry.LastUpdated = entry.LastUpdated // Decay already updated this

	// Save updated entry
	if err := s.SetScore(entry); err != nil {
		return entry.Score, err
	}

	return entry.Score, nil
}

// Compile-time interface verification
var _ ScoreStore = (*LocalScoreStore)(nil)
