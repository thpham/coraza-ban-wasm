package main

import (
	"strings"

	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
)

// =============================================================================
// Fingerprint Service
// =============================================================================

// FingerprintResult holds the result of fingerprint calculation.
type FingerprintResult struct {
	Fingerprint     string
	ClientIP        string
	UserAgent       string
	JA3Fingerprint  string
	CookieValue     string
	GeneratedCookie string
}

// FingerprintService implements FingerprintCalculator interface.
// It computes client fingerprints based on various request attributes.
type FingerprintService struct {
	config *PluginConfig
	logger Logger
}

// NewFingerprintService creates a new fingerprint service.
func NewFingerprintService(config *PluginConfig, logger Logger) *FingerprintService {
	return &FingerprintService{
		config: config,
		logger: logger,
	}
}

// Calculate computes a fingerprint for the current request.
// Implements FingerprintCalculator interface.
func (s *FingerprintService) Calculate() string {
	result := s.CalculateWithDetails()
	return result.Fingerprint
}

// CalculateWithDetails computes fingerprint and returns all extracted components.
func (s *FingerprintService) CalculateWithDetails() *FingerprintResult {
	var result *FingerprintResult

	switch s.config.FingerprintMode {
	case FingerprintModeIPOnly:
		result = s.calculateIPOnly()
	case FingerprintModePartial:
		result = s.calculatePartial()
	case FingerprintModeFull:
		fallthrough
	default:
		result = s.calculateFull()
	}

	s.logger.Debug("fingerprint calculated: %s (mode=%s)", result.Fingerprint, s.config.FingerprintMode)
	return result
}

// calculateFull computes fingerprint from JA3 + UA + IP/24 + cookie.
func (s *FingerprintService) calculateFull() *FingerprintResult {
	result := &FingerprintResult{}
	var components []string

	// 1. JA3 TLS fingerprint
	ja3 := s.getJA3Fingerprint()
	if ja3 != "" {
		components = append(components, "ja3:"+ja3)
		result.JA3Fingerprint = ja3
	}

	// 2. User-Agent
	ua := s.getUserAgent()
	if ua != "" {
		components = append(components, "ua:"+ua)
		result.UserAgent = ua
	}

	// 3. Client IP prefix (/24 for IPv4)
	ip := s.getClientIP()
	if ip != "" {
		ipPrefix := extractIPPrefix(ip)
		components = append(components, "ip:"+ipPrefix)
		result.ClientIP = ip
	}

	// 4. Tracking cookie
	cookie := s.getTrackingCookie()
	if cookie != "" {
		components = append(components, "cookie:"+cookie)
		result.CookieValue = cookie
	} else if s.config.InjectCookie {
		result.GeneratedCookie = generateCookieValue()
		components = append(components, "cookie:"+result.GeneratedCookie)
	}

	// Compute final fingerprint
	if len(components) > 0 {
		combined := strings.Join(components, "|")
		result.Fingerprint = sha256Hash(combined)
	} else {
		result.Fingerprint = sha256Hash("unknown")
	}

	return result
}

// calculatePartial computes fingerprint from UA + IP/24 + cookie (no JA3).
func (s *FingerprintService) calculatePartial() *FingerprintResult {
	result := &FingerprintResult{}
	var components []string

	// 1. User-Agent
	ua := s.getUserAgent()
	if ua != "" {
		components = append(components, "ua:"+ua)
		result.UserAgent = ua
	}

	// 2. Client IP prefix
	ip := s.getClientIP()
	if ip != "" {
		ipPrefix := extractIPPrefix(ip)
		components = append(components, "ip:"+ipPrefix)
		result.ClientIP = ip
	}

	// 3. Tracking cookie
	cookie := s.getTrackingCookie()
	if cookie != "" {
		components = append(components, "cookie:"+cookie)
		result.CookieValue = cookie
	} else if s.config.InjectCookie {
		result.GeneratedCookie = generateCookieValue()
		components = append(components, "cookie:"+result.GeneratedCookie)
	}

	if len(components) > 0 {
		combined := strings.Join(components, "|")
		result.Fingerprint = sha256Hash(combined)
	} else {
		result.Fingerprint = sha256Hash("unknown")
	}

	return result
}

// calculateIPOnly computes fingerprint from IP address only.
func (s *FingerprintService) calculateIPOnly() *FingerprintResult {
	result := &FingerprintResult{}

	ip := s.getClientIP()
	if ip != "" {
		result.ClientIP = ip
		result.Fingerprint = sha256Hash("ip:" + ip)
	} else {
		result.Fingerprint = sha256Hash("unknown")
	}

	return result
}

// getJA3Fingerprint retrieves the JA3 TLS fingerprint from Envoy properties.
func (s *FingerprintService) getJA3Fingerprint() string {
	ja3Paths := [][]string{
		{"connection", "tls", "ja3"},
		{"connection", "tls", "ja3_fingerprint"},
		{"request", "tls", "ja3"},
		{"upstream", "tls", "ja3"},
	}

	for _, path := range ja3Paths {
		if value, err := proxywasm.GetProperty(path); err == nil && len(value) > 0 {
			return string(value)
		}
	}

	if ja3, err := proxywasm.GetHttpRequestHeader("x-ja3-fingerprint"); err == nil && ja3 != "" {
		return ja3
	}

	return ""
}

// getUserAgent retrieves the User-Agent header.
func (s *FingerprintService) getUserAgent() string {
	ua, err := proxywasm.GetHttpRequestHeader("user-agent")
	if err != nil {
		return ""
	}
	return ua
}

// getClientIP retrieves the client IP address.
func (s *FingerprintService) getClientIP() string {
	// Priority order for client IP extraction:

	// 1. X-Forwarded-For (leftmost IP)
	if xff, err := proxywasm.GetHttpRequestHeader("x-forwarded-for"); err == nil && xff != "" {
		return extractClientIP(xff)
	}

	// 2. X-Real-IP
	if realIP, err := proxywasm.GetHttpRequestHeader("x-real-ip"); err == nil && realIP != "" {
		return realIP
	}

	// 3. True-Client-IP (Cloudflare)
	if tcIP, err := proxywasm.GetHttpRequestHeader("true-client-ip"); err == nil && tcIP != "" {
		return tcIP
	}

	// 4. CF-Connecting-IP (Cloudflare)
	if cfIP, err := proxywasm.GetHttpRequestHeader("cf-connecting-ip"); err == nil && cfIP != "" {
		return cfIP
	}

	// 5. Source address from connection properties
	sourceAddrPaths := [][]string{
		{"source", "address"},
		{"connection", "source", "address"},
		{"downstream", "remote_address"},
	}

	for _, path := range sourceAddrPaths {
		if value, err := proxywasm.GetProperty(path); err == nil && len(value) > 0 {
			addr := string(value)
			if idx := strings.LastIndex(addr, ":"); idx > 0 {
				if strings.Count(addr, ":") > 1 {
					return addr // IPv6
				}
				return addr[:idx]
			}
			return addr
		}
	}

	return ""
}

// getTrackingCookie retrieves the tracking cookie value.
func (s *FingerprintService) getTrackingCookie() string {
	cookieHeader, err := proxywasm.GetHttpRequestHeader("cookie")
	if err != nil || cookieHeader == "" {
		return ""
	}
	return parseCookie(cookieHeader, s.config.CookieName)
}

// Compile-time interface verification
var _ FingerprintCalculator = (*FingerprintService)(nil)
