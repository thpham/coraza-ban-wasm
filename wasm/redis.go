package main

import (
	"encoding/json"
	"fmt"

	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
)

// Redis HTTP API integration
// This module uses HTTP calls to communicate with Redis via an HTTP proxy
// such as webdis (https://github.com/nicolasff/webdis) or a custom adapter.
//
// Expected Redis HTTP API endpoints:
// - GET /GET/<key>       -> Returns {"GET": "<value>"}
// - GET /SETEX/<key>/<ttl>/<value> -> Returns {"SETEX": "OK"}
// - GET /DEL/<key>       -> Returns {"DEL": 1}

// redisTimeout uses the default timeout for Redis HTTP calls (milliseconds)
var redisTimeout = uint32(DefaultRedisTimeout)

// checkRedisBanAsync initiates an async check for a ban in Redis
func (ctx *httpContext) checkRedisBanAsync() {
	if ctx.config.RedisCluster == "" {
		return
	}

	key := BanKey(ctx.fingerprint)
	path := fmt.Sprintf("/GET/%s", key)

	headers := [][2]string{
		{":method", "GET"},
		{":path", path},
		{":authority", ctx.config.RedisCluster},
		{"accept", "application/json"},
	}

	// Store context for callback
	ctx.pendingRedis = true

	_, err := proxywasm.DispatchHttpCall(
		ctx.config.RedisCluster,
		headers,
		nil, // no body for GET
		nil, // no trailers
		redisTimeout,
		ctx.onRedisBanCheckResponse,
	)

	if err != nil {
		ctx.logError("failed to dispatch Redis ban check: %v", err)
		ctx.pendingRedis = false
	}
}

// onRedisBanCheckResponse handles the response from Redis ban check
func (ctx *httpContext) onRedisBanCheckResponse(numHeaders, bodySize, numTrailers int) {
	// Get response body
	body, err := proxywasm.GetHttpCallResponseBody(0, bodySize)
	if err != nil {
		ctx.logError("failed to get Redis response body: %v", err)
		ctx.handleRedisBanResponse(false, nil)
		return
	}

	// Check HTTP status
	status := getHttpCallResponseStatus()
	if status != "200" {
		ctx.logDebug("Redis returned non-200 status: %s", status)
		ctx.handleRedisBanResponse(false, nil)
		return
	}

	// Parse response
	entry, found := ctx.parseRedisBanResponse(body)
	ctx.handleRedisBanResponse(found, entry)
}

// getHttpCallResponseStatus extracts the :status from HTTP call response headers
func getHttpCallResponseStatus() string {
	headers, err := proxywasm.GetHttpCallResponseHeaders()
	if err != nil {
		return ""
	}
	for _, h := range headers {
		if h[0] == ":status" {
			return h[1]
		}
	}
	return ""
}

// parseRedisBanResponse parses the Redis GET response
func (ctx *httpContext) parseRedisBanResponse(body []byte) (*BanEntry, bool) {
	if len(body) == 0 {
		return nil, false
	}

	// Webdis response format: {"GET": "<value>"} or {"GET": null}
	var response map[string]interface{}
	if err := json.Unmarshal(body, &response); err != nil {
		ctx.logError("failed to parse Redis response: %v", err)
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
		ctx.logError("unexpected Redis value type")
		return nil, false
	}

	entry, err := BanEntryFromJSON([]byte(valueStr))
	if err != nil {
		ctx.logError("failed to parse ban entry from Redis: %v", err)
		return nil, false
	}

	// Check if expired
	if entry.IsExpired() {
		ctx.logDebug("ban from Redis is expired")
		// Optionally delete from Redis
		ctx.deleteRedisBanAsync(ctx.fingerprint)
		return nil, false
	}

	return entry, true
}

// setRedisBanAsync stores a ban entry in Redis asynchronously
func (ctx *httpContext) setRedisBanAsync(entry *BanEntry) {
	if ctx.config.RedisCluster == "" {
		return
	}

	// Serialize entry to JSON
	entryJSON, err := entry.ToJSON()
	if err != nil {
		ctx.logError("failed to serialize ban entry: %v", err)
		return
	}

	key := BanKey(entry.Fingerprint)
	// Use SETEX to set with TTL
	path := fmt.Sprintf("/SETEX/%s/%d/%s", key, entry.TTL, string(entryJSON))

	headers := [][2]string{
		{":method", "GET"}, // webdis uses GET for all commands
		{":path", path},
		{":authority", ctx.config.RedisCluster},
		{"accept", "application/json"},
	}

	_, err = proxywasm.DispatchHttpCall(
		ctx.config.RedisCluster,
		headers,
		nil,
		nil,
		redisTimeout,
		ctx.onRedisBanSetResponse,
	)

	if err != nil {
		ctx.logError("failed to dispatch Redis ban set: %v", err)
	}
}

// onRedisBanSetResponse handles the response from Redis ban set
func (ctx *httpContext) onRedisBanSetResponse(numHeaders, bodySize, numTrailers int) {
	status := getHttpCallResponseStatus()
	if status != "200" {
		ctx.handleRedisBanSetResponse(false)
		return
	}

	ctx.handleRedisBanSetResponse(true)
}

// deleteRedisBanAsync deletes a ban from Redis asynchronously
func (ctx *httpContext) deleteRedisBanAsync(fingerprint string) {
	if ctx.config.RedisCluster == "" {
		return
	}

	key := BanKey(fingerprint)
	path := fmt.Sprintf("/DEL/%s", key)

	headers := [][2]string{
		{":method", "GET"},
		{":path", path},
		{":authority", ctx.config.RedisCluster},
		{"accept", "application/json"},
	}

	_, err := proxywasm.DispatchHttpCall(
		ctx.config.RedisCluster,
		headers,
		nil,
		nil,
		redisTimeout,
		func(numHeaders, bodySize, numTrailers int) {
			// Fire and forget
			ctx.logDebug("ban deleted from Redis for %s", fingerprint)
		},
	)

	if err != nil {
		ctx.logError("failed to dispatch Redis ban delete: %v", err)
	}
}

