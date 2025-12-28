package main

import (
	"encoding/json"
	"strings"

	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
)

// =============================================================================
// Metadata Service
// =============================================================================

// MetadataService implements MetadataExtractor interface.
// It extracts Coraza WAF metadata from Envoy dynamic metadata or response headers.
type MetadataService struct {
	logger Logger
}

// NewMetadataService creates a new metadata service.
func NewMetadataService(logger Logger) *MetadataService {
	return &MetadataService{
		logger: logger,
	}
}

// Extract retrieves WAF metadata from the current request/response context.
// Implements MetadataExtractor interface.
func (s *MetadataService) Extract() *CorazaMetadata {
	// Try multiple metadata paths where Coraza might store its decision
	metadataPaths := [][]string{
		{"metadata", "filter_metadata", "envoy.filters.http.wasm", "coraza"},
		{"metadata", "filter_metadata", "coraza"},
		{"metadata", "filter_metadata", "envoy.filters.http.coraza"},
	}

	for _, path := range metadataPaths {
		metadata := s.tryExtractMetadata(path)
		if metadata != nil {
			return metadata
		}
	}

	// Try reading from response headers as fallback
	return s.extractFromHeaders()
}

// tryExtractMetadata attempts to extract metadata from a specific path.
func (s *MetadataService) tryExtractMetadata(path []string) *CorazaMetadata {
	value, err := proxywasm.GetProperty(path)
	if err != nil {
		s.logger.Debug("metadata not found at path %v: %v", path, err)
		return nil
	}

	if len(value) == 0 {
		return nil
	}

	// Try to parse as JSON
	var metadata CorazaMetadata
	if err := json.Unmarshal(value, &metadata); err != nil {
		// Try parsing as a simple string format
		return s.parseStringMetadata(string(value))
	}

	return &metadata
}

// parseStringMetadata parses metadata from a simple string format.
// Format: "action=block;rule_id=930120;severity=high"
func (s *MetadataService) parseStringMetadata(value string) *CorazaMetadata {
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

// extractFromHeaders extracts Coraza metadata from response headers.
func (s *MetadataService) extractFromHeaders() *CorazaMetadata {
	action, err := proxywasm.GetHttpResponseHeader("x-coraza-action")
	if err != nil || action == "" {
		return nil
	}

	metadata := &CorazaMetadata{
		Action: action,
	}

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

// GetStatusCode retrieves the HTTP response status code.
func (s *MetadataService) GetStatusCode() int {
	status, err := proxywasm.GetHttpResponseHeader(":status")
	if err != nil {
		return 0
	}

	code := 0
	for _, c := range status {
		if c >= '0' && c <= '9' {
			code = code*10 + int(c-'0')
		}
	}

	return code
}

// IsBlockedResponse checks if the response indicates a blocked request.
// This is a fallback when Coraza metadata is not available.
func (s *MetadataService) IsBlockedResponse() bool {
	statusCode := s.GetStatusCode()

	// Coraza typically returns 403 for blocked requests
	if statusCode == 403 || statusCode == 406 || statusCode == 418 {
		if server, err := proxywasm.GetHttpResponseHeader("server"); err == nil {
			if strings.Contains(strings.ToLower(server), "coraza") {
				return true
			}
		}

		if _, err := proxywasm.GetHttpResponseHeader("x-waf-block"); err == nil {
			return true
		}
	}

	return false
}

// Compile-time interface verification
var _ MetadataExtractor = (*MetadataService)(nil)
