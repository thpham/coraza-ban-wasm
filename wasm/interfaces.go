package main

// =============================================================================
// Storage Interfaces
// =============================================================================
// These interfaces enable dependency injection and facilitate unit testing
// by allowing mock implementations to be substituted for the actual storage.

// BanStore defines the interface for ban storage operations.
// Implementations include local shared-data cache and Redis.
type BanStore interface {
	// CheckBan checks if a fingerprint is banned.
	// Returns the ban entry and true if banned, nil and false otherwise.
	CheckBan(fingerprint string) (*BanEntry, bool)

	// SetBan stores a ban entry.
	SetBan(entry *BanEntry) error

	// DeleteBan removes a ban entry.
	DeleteBan(fingerprint string) error
}

// ScoreStore defines the interface for behavioral score storage operations.
// Implementations include local shared-data cache and Redis.
type ScoreStore interface {
	// GetScore retrieves a score entry for a fingerprint.
	// Returns the score entry and true if found, nil and false otherwise.
	GetScore(fingerprint string) (*ScoreEntry, bool)

	// SetScore stores a score entry.
	SetScore(entry *ScoreEntry) error

	// IncrScore atomically increments a score.
	// Returns the new score value.
	IncrScore(fingerprint string, increment int) (int, error)
}

// MetadataExtractor defines the interface for WAF metadata extraction.
// This allows different extraction strategies to be plugged in.
type MetadataExtractor interface {
	// Extract retrieves WAF metadata from the current request/response context.
	// Returns nil if no metadata is available.
	Extract() *CorazaMetadata
}

// FingerprintCalculator defines the interface for client fingerprint calculation.
// Different fingerprinting strategies can be implemented.
type FingerprintCalculator interface {
	// Calculate computes a fingerprint for the current request.
	// Returns the fingerprint string.
	Calculate() string
}

// =============================================================================
// Redis Client Interface
// =============================================================================

// RedisClient defines async Redis operations for ban management.
// All operations are non-blocking and use callbacks for results.
// This interface enables dependency injection and facilitates unit testing.
type RedisClient interface {
	// CheckBanAsync checks if a fingerprint is banned in Redis.
	// Callback receives (isBanned, entry) - entry may be nil if not banned.
	CheckBanAsync(fingerprint string, callback func(bool, *BanEntry))

	// SetBanAsync stores a ban entry in Redis.
	// Callback receives success status.
	SetBanAsync(entry *BanEntry, callback func(bool))

	// DeleteBanAsync removes a ban from Redis.
	// Fire-and-forget, no callback needed.
	DeleteBanAsync(fingerprint string)

	// IsConfigured returns true if Redis is configured.
	IsConfigured() bool
}

// =============================================================================
// Logger Interface
// =============================================================================

// Logger defines the interface for plugin logging.
// This allows log output to be redirected for testing.
type Logger interface {
	Debug(format string, args ...interface{})
	Info(format string, args ...interface{})
	Warn(format string, args ...interface{})
	Error(format string, args ...interface{})
}
