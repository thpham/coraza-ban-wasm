package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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

// generateCookieValue generates a random-ish cookie value for tracking.
// Note: In WASM we have limited entropy sources, so we combine multiple
// time-based values to increase unpredictability.
func generateCookieValue() string {
	// Combine multiple entropy sources available in WASM
	timestamp := time.Now().UnixNano()
	// Use prime modulo and string formatting to avoid rune conversion data loss
	input := fmt.Sprintf("%d-%d-%d", timestamp, timestamp%1000000007, timestamp%999999937)
	return sha256Hash(input)[:16] // Use first 16 chars
}
