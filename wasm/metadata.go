package main

import (
	"encoding/json"
	"strings"

	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
)

// CorazaMetadata represents WAF decision metadata from Coraza
type CorazaMetadata struct {
	// Action is the WAF decision: "block", "deny", "drop", "log", "pass"
	Action string `json:"action"`

	// RuleID is the triggered rule identifier (e.g., "930120")
	RuleID string `json:"rule_id"`

	// Severity is the rule severity: "critical", "high", "medium", "low"
	Severity string `json:"severity"`

	// Message is the rule description or matched data
	Message string `json:"message"`

	// MatchedData contains the data that triggered the rule
	MatchedData string `json:"matched_data"`

	// Tags contains rule tags (e.g., ["OWASP_CRS", "attack-sqli"])
	Tags []string `json:"tags"`
}

// IsBlocked returns true if the WAF action is a blocking action
func (m *CorazaMetadata) IsBlocked() bool {
	switch strings.ToLower(m.Action) {
	case "block", "deny", "drop":
		return true
	default:
		return false
	}
}

// extractCorazaMetadata extracts Coraza WAF metadata from Envoy dynamic metadata
func (ctx *httpContext) extractCorazaMetadata() *CorazaMetadata {
	// Try multiple metadata paths where Coraza might store its decision
	metadataPaths := [][]string{
		// Standard Coraza filter metadata path
		{"metadata", "filter_metadata", "envoy.filters.http.wasm", "coraza"},
		// Alternative: direct Coraza metadata
		{"metadata", "filter_metadata", "coraza"},
		// Alternative: custom metadata path
		{"metadata", "filter_metadata", "envoy.filters.http.coraza"},
	}

	for _, path := range metadataPaths {
		metadata := ctx.tryExtractMetadata(path)
		if metadata != nil {
			return metadata
		}
	}

	// Try reading from response headers as fallback
	// Some Coraza configurations add headers instead of metadata
	return ctx.extractFromHeaders()
}

// tryExtractMetadata attempts to extract metadata from a specific path
func (ctx *httpContext) tryExtractMetadata(path []string) *CorazaMetadata {
	// Get the property value
	value, err := proxywasm.GetProperty(path)
	if err != nil {
		ctx.logDebug("metadata not found at path %v: %v", path, err)
		return nil
	}

	if len(value) == 0 {
		return nil
	}

	// Try to parse as JSON
	var metadata CorazaMetadata
	if err := json.Unmarshal(value, &metadata); err != nil {
		// Try parsing as a simple string format
		return ctx.parseStringMetadata(string(value))
	}

	return &metadata
}

// parseStringMetadata parses metadata from a simple string format
// Format: "action=block;rule_id=930120;severity=high"
func (ctx *httpContext) parseStringMetadata(value string) *CorazaMetadata {
	metadata := &CorazaMetadata{}

	parts := strings.Split(value, ";")
	for _, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}

		key := strings.TrimSpace(kv[0])
		val := strings.TrimSpace(kv[1])

		switch key {
		case "action":
			metadata.Action = val
		case "rule_id":
			metadata.RuleID = val
		case "severity":
			metadata.Severity = val
		case "message":
			metadata.Message = val
		case "matched_data":
			metadata.MatchedData = val
		}
	}

	if metadata.Action == "" {
		return nil
	}

	return metadata
}

// extractFromHeaders extracts Coraza metadata from response headers
func (ctx *httpContext) extractFromHeaders() *CorazaMetadata {
	// Check for Coraza-specific headers
	action, err := proxywasm.GetHttpResponseHeader("x-coraza-action")
	if err != nil || action == "" {
		return nil
	}

	metadata := &CorazaMetadata{
		Action: action,
	}

	// Extract additional headers if present
	if ruleID, err := proxywasm.GetHttpResponseHeader("x-coraza-rule-id"); err == nil {
		metadata.RuleID = ruleID
	}

	if severity, err := proxywasm.GetHttpResponseHeader("x-coraza-severity"); err == nil {
		metadata.Severity = severity
	}

	if message, err := proxywasm.GetHttpResponseHeader("x-coraza-message"); err == nil {
		metadata.Message = message
	}

	return metadata
}

// getStatusCode retrieves the HTTP response status code
func (ctx *httpContext) getStatusCode() int {
	// Get the :status pseudo-header
	status, err := proxywasm.GetHttpResponseHeader(":status")
	if err != nil {
		return 0
	}

	// Parse status code
	code := 0
	for _, c := range status {
		if c >= '0' && c <= '9' {
			code = code*10 + int(c-'0')
		}
	}

	return code
}

// isBlockedResponse checks if the response indicates a blocked request
// This is a fallback when Coraza metadata is not available
func (ctx *httpContext) isBlockedResponse() bool {
	statusCode := ctx.getStatusCode()

	// Coraza typically returns 403 for blocked requests
	if statusCode == 403 || statusCode == 406 || statusCode == 418 {
		// Check for Coraza-specific indicators in headers
		if server, err := proxywasm.GetHttpResponseHeader("server"); err == nil {
			if strings.Contains(strings.ToLower(server), "coraza") {
				return true
			}
		}

		// Check for WAF block indicator header
		if _, err := proxywasm.GetHttpResponseHeader("x-waf-block"); err == nil {
			return true
		}
	}

	return false
}
