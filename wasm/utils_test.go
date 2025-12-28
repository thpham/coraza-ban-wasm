package main

import (
	"strings"
	"testing"
)

func TestSha256Hash(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"hello", "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"},
		{"world", "486ea46224d1bb4fb680f34f7c9ad96a8f24ec88be73ea8e5a6c65260e9cb8a7"},
		{"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	}

	for _, tt := range tests {
		result := sha256Hash(tt.input)
		if result != tt.expected {
			t.Errorf("sha256Hash(%q) = %q, expected %q", tt.input, result, tt.expected)
		}
	}
}

func TestExtractIPPrefix_IPv4(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"192.168.1.100", "192.168.1"},
		{"10.0.0.1", "10.0.0"},
		{"172.16.254.1", "172.16.254"},
		{"8.8.8.8", "8.8.8"},
	}

	for _, tt := range tests {
		result := extractIPPrefix(tt.input)
		if result != tt.expected {
			t.Errorf("extractIPPrefix(%q) = %q, expected %q", tt.input, result, tt.expected)
		}
	}
}

func TestExtractIPPrefix_IPv6Mapped(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"::ffff:192.168.1.100", "192.168.1"},
		{"::ffff:10.0.0.1", "10.0.0"},
	}

	for _, tt := range tests {
		result := extractIPPrefix(tt.input)
		if result != tt.expected {
			t.Errorf("extractIPPrefix(%q) = %q, expected %q", tt.input, result, tt.expected)
		}
	}
}

func TestExtractIPPrefix_IPv6(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"2001:0db8:85a3:0000:0000:8a2e:0370:7334", "2001:0db8:85a3"},
		{"fe80:0000:0000:0000:0000:0000:0000:0001", "fe80:0000:0000"},
	}

	for _, tt := range tests {
		result := extractIPPrefix(tt.input)
		if result != tt.expected {
			t.Errorf("extractIPPrefix(%q) = %q, expected %q", tt.input, result, tt.expected)
		}
	}
}

func TestExtractClientIP(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"192.168.1.1", "192.168.1.1"},
		{"192.168.1.1, 10.0.0.1", "192.168.1.1"},
		{"192.168.1.1, 10.0.0.1, 172.16.0.1", "192.168.1.1"},
		{"  192.168.1.1  , 10.0.0.1", "192.168.1.1"},
		{"", ""},
	}

	for _, tt := range tests {
		result := extractClientIP(tt.input)
		if result != tt.expected {
			t.Errorf("extractClientIP(%q) = %q, expected %q", tt.input, result, tt.expected)
		}
	}
}

func TestParseCookie(t *testing.T) {
	tests := []struct {
		header   string
		name     string
		expected string
	}{
		{"session=abc123", "session", "abc123"},
		{"session=abc123; user=john", "session", "abc123"},
		{"session=abc123; user=john", "user", "john"},
		{"session=abc123; user=john", "missing", ""},
		{"__bm=tracking123", "__bm", "tracking123"},
		{"", "session", ""},
		{"other=value", "session", ""},
	}

	for _, tt := range tests {
		result := parseCookie(tt.header, tt.name)
		if result != tt.expected {
			t.Errorf("parseCookie(%q, %q) = %q, expected %q", tt.header, tt.name, result, tt.expected)
		}
	}
}

func TestGenerateCookieValue(t *testing.T) {
	// Generate multiple values and check they're different
	values := make(map[string]bool)
	for i := 0; i < 10; i++ {
		value := generateCookieValue()

		// Should be 16 characters (hex)
		if len(value) != 16 {
			t.Errorf("expected 16 character cookie value, got %d: %s", len(value), value)
		}

		// Should be hex characters only
		for _, c := range value {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Errorf("invalid hex character in cookie value: %c", c)
			}
		}

		values[value] = true
	}

	// With 10 attempts, we should have at least a few unique values
	// (allowing for some time-based collisions in fast loops)
	if len(values) < 3 {
		t.Error("cookie values not sufficiently unique")
	}
}

func TestBanKey(t *testing.T) {
	result := BanKey("test-fingerprint")

	if !strings.HasPrefix(result, "ban:") {
		t.Errorf("BanKey should start with 'ban:', got %s", result)
	}
	if result != "ban:test-fingerprint" {
		t.Errorf("expected 'ban:test-fingerprint', got %s", result)
	}
}

func TestScoreKey(t *testing.T) {
	result := ScoreKey("test-fingerprint")

	if !strings.HasPrefix(result, "score:") {
		t.Errorf("ScoreKey should start with 'score:', got %s", result)
	}
	if result != "score:test-fingerprint" {
		t.Errorf("expected 'score:test-fingerprint', got %s", result)
	}
}
