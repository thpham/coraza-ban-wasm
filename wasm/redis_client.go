package main

import (
	"encoding/json"
	"fmt"

	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
)

// =============================================================================
// WebdisClient - Production Redis client using Webdis HTTP API
// =============================================================================

// WebdisClient implements RedisClient using HTTP calls to Webdis.
// It uses proxywasm.DispatchHttpCall for async operations.
type WebdisClient struct {
	cluster string
	timeout uint32
	logger  Logger
}

// NewWebdisClient creates a new Webdis-based Redis client.
func NewWebdisClient(cluster string, timeout uint32, logger Logger) *WebdisClient {
	return &WebdisClient{
		cluster: cluster,
		timeout: timeout,
		logger:  logger,
	}
}

// IsConfigured returns true if Redis cluster is configured.
func (c *WebdisClient) IsConfigured() bool {
	return c.cluster != ""
}

// CheckBanAsync checks if a fingerprint is banned in Redis asynchronously.
func (c *WebdisClient) CheckBanAsync(fingerprint string, callback func(bool, *BanEntry)) {
	if !c.IsConfigured() {
		callback(false, nil)
		return
	}

	key := BanKey(fingerprint)
	path := fmt.Sprintf("/GET/%s", key)

	headers := [][2]string{
		{":method", "GET"},
		{":path", path},
		{":authority", c.cluster},
		{"accept", "application/json"},
	}

	_, err := proxywasm.DispatchHttpCall(
		c.cluster,
		headers,
		nil, // no body for GET
		nil, // no trailers
		c.timeout,
		func(numHeaders, bodySize, numTrailers int) {
			c.handleCheckBanResponse(fingerprint, bodySize, callback)
		},
	)

	if err != nil {
		c.logger.Error("failed to dispatch Redis ban check: %v", err)
		callback(false, nil)
	}
}

// handleCheckBanResponse processes the response from Redis ban check.
func (c *WebdisClient) handleCheckBanResponse(fingerprint string, bodySize int, callback func(bool, *BanEntry)) {
	// Get response body
	body, err := proxywasm.GetHttpCallResponseBody(0, bodySize)
	if err != nil {
		c.logger.Error("failed to get Redis response body: %v", err)
		callback(false, nil)
		return
	}

	// Check HTTP status
	status := getHttpCallResponseStatus()
	if status != "200" {
		c.logger.Debug("Redis returned non-200 status: %s", status)
		callback(false, nil)
		return
	}

	// Parse response
	entry, found := c.parseRedisBanResponse(body, fingerprint)
	callback(found, entry)
}

// parseRedisBanResponse parses the Redis GET response.
func (c *WebdisClient) parseRedisBanResponse(body []byte, fingerprint string) (*BanEntry, bool) {
	if len(body) == 0 {
		return nil, false
	}

	// Webdis response format: {"GET": "<value>"} or {"GET": null}
	var response map[string]interface{}
	if err := json.Unmarshal(body, &response); err != nil {
		c.logger.Error("failed to parse Redis response: %v", err)
		return nil, false
	}

	// Check if key exists
	value, ok := response["GET"]
	if !ok {
		return nil, false
	}

	// Check for null (key not found)
	if value == nil {
		return nil, false
	}

	// Parse the ban entry JSON
	valueStr, ok := value.(string)
	if !ok {
		c.logger.Error("unexpected Redis value type")
		return nil, false
	}

	entry, err := BanEntryFromJSON([]byte(valueStr))
	if err != nil {
		c.logger.Error("failed to parse ban entry from Redis: %v", err)
		return nil, false
	}

	// Check if expired
	if entry.IsExpired() {
		c.logger.Debug("ban from Redis is expired")
		// Delete expired entry from Redis
		c.DeleteBanAsync(fingerprint)
		return nil, false
	}

	return entry, true
}

// SetBanAsync stores a ban entry in Redis asynchronously.
func (c *WebdisClient) SetBanAsync(entry *BanEntry, callback func(bool)) {
	if !c.IsConfigured() {
		callback(true) // Treat as success when not configured
		return
	}

	// Serialize entry to JSON
	entryJSON, err := entry.ToJSON()
	if err != nil {
		c.logger.Error("failed to serialize ban entry: %v", err)
		callback(false)
		return
	}

	key := BanKey(entry.Fingerprint)
	// Use SETEX to set with TTL
	path := fmt.Sprintf("/SETEX/%s/%d/%s", key, entry.TTL, string(entryJSON))

	headers := [][2]string{
		{":method", "GET"}, // webdis uses GET for all commands
		{":path", path},
		{":authority", c.cluster},
		{"accept", "application/json"},
	}

	_, err = proxywasm.DispatchHttpCall(
		c.cluster,
		headers,
		nil,
		nil,
		c.timeout,
		func(numHeaders, bodySize, numTrailers int) {
			status := getHttpCallResponseStatus()
			callback(status == "200")
		},
	)

	if err != nil {
		c.logger.Error("failed to dispatch Redis ban set: %v", err)
		callback(false)
	}
}

// DeleteBanAsync removes a ban from Redis asynchronously (fire-and-forget).
func (c *WebdisClient) DeleteBanAsync(fingerprint string) {
	if !c.IsConfigured() {
		return
	}

	key := BanKey(fingerprint)
	path := fmt.Sprintf("/DEL/%s", key)

	headers := [][2]string{
		{":method", "GET"},
		{":path", path},
		{":authority", c.cluster},
		{"accept", "application/json"},
	}

	_, err := proxywasm.DispatchHttpCall(
		c.cluster,
		headers,
		nil,
		nil,
		c.timeout,
		func(numHeaders, bodySize, numTrailers int) {
			// Fire and forget
			c.logger.Debug("ban deleted from Redis for %s", fingerprint)
		},
	)

	if err != nil {
		c.logger.Error("failed to dispatch Redis ban delete: %v", err)
	}
}

// =============================================================================
// NoopRedisClient - No-operation client for testing/disabled Redis
// =============================================================================

// NoopRedisClient implements RedisClient with no-op operations.
// Use this when Redis is not configured or for unit testing.
type NoopRedisClient struct{}

// NewNoopRedisClient creates a new no-op Redis client.
func NewNoopRedisClient() *NoopRedisClient {
	return &NoopRedisClient{}
}

// IsConfigured always returns false for NoopRedisClient.
func (c *NoopRedisClient) IsConfigured() bool {
	return false
}

// CheckBanAsync immediately calls the callback with not-banned result.
func (c *NoopRedisClient) CheckBanAsync(fingerprint string, callback func(bool, *BanEntry)) {
	callback(false, nil) // Always not found
}

// SetBanAsync immediately calls the callback with success.
func (c *NoopRedisClient) SetBanAsync(entry *BanEntry, callback func(bool)) {
	callback(true) // Always succeeds
}

// DeleteBanAsync does nothing.
func (c *NoopRedisClient) DeleteBanAsync(fingerprint string) {
	// No-op
}
