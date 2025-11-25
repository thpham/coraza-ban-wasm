package main

import (
	"strings"

	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm"
)

// calculateFingerprint computes a composite client fingerprint
func (ctx *httpContext) calculateFingerprint() {
	switch ctx.config.FingerprintMode {
	case "ip-only":
		ctx.calculateIPOnlyFingerprint()
	case "partial":
		ctx.calculatePartialFingerprint()
	case "full":
		fallthrough
	default:
		ctx.calculateFullFingerprint()
	}

	ctx.logDebug("fingerprint calculated: %s (mode=%s)", ctx.fingerprint, ctx.config.FingerprintMode)
}

// calculateFullFingerprint computes fingerprint from JA3 + UA + IP/24 + cookie
func (ctx *httpContext) calculateFullFingerprint() {
	var components []string

	// 1. JA3 TLS fingerprint
	ja3 := ctx.getJA3Fingerprint()
	if ja3 != "" {
		components = append(components, "ja3:"+ja3)
		ctx.ja3Fingerprint = ja3
	}

	// 2. User-Agent
	ua := ctx.getUserAgent()
	if ua != "" {
		components = append(components, "ua:"+ua)
		ctx.userAgent = ua
	}

	// 3. Client IP prefix (/24 for IPv4)
	ip := ctx.getClientIP()
	if ip != "" {
		ipPrefix := extractIPPrefix(ip)
		components = append(components, "ip:"+ipPrefix)
		ctx.clientIP = ip
	}

	// 4. Tracking cookie
	cookie := ctx.getTrackingCookie()
	if cookie != "" {
		components = append(components, "cookie:"+cookie)
		ctx.cookieValue = cookie
	} else if ctx.config.InjectCookie {
		// Generate a new cookie for injection
		ctx.generatedCookie = generateCookieValue()
		components = append(components, "cookie:"+ctx.generatedCookie)
	}

	// Compute final fingerprint
	if len(components) > 0 {
		combined := strings.Join(components, "|")
		ctx.fingerprint = sha256Hash(combined)
	} else {
		// Fallback to source IP only
		ctx.fingerprint = sha256Hash("unknown")
	}
}

// calculatePartialFingerprint computes fingerprint from UA + IP/24 + cookie (no JA3)
func (ctx *httpContext) calculatePartialFingerprint() {
	var components []string

	// 1. User-Agent
	ua := ctx.getUserAgent()
	if ua != "" {
		components = append(components, "ua:"+ua)
		ctx.userAgent = ua
	}

	// 2. Client IP prefix
	ip := ctx.getClientIP()
	if ip != "" {
		ipPrefix := extractIPPrefix(ip)
		components = append(components, "ip:"+ipPrefix)
		ctx.clientIP = ip
	}

	// 3. Tracking cookie
	cookie := ctx.getTrackingCookie()
	if cookie != "" {
		components = append(components, "cookie:"+cookie)
		ctx.cookieValue = cookie
	} else if ctx.config.InjectCookie {
		ctx.generatedCookie = generateCookieValue()
		components = append(components, "cookie:"+ctx.generatedCookie)
	}

	if len(components) > 0 {
		combined := strings.Join(components, "|")
		ctx.fingerprint = sha256Hash(combined)
	} else {
		ctx.fingerprint = sha256Hash("unknown")
	}
}

// calculateIPOnlyFingerprint computes fingerprint from IP address only
func (ctx *httpContext) calculateIPOnlyFingerprint() {
	ip := ctx.getClientIP()
	if ip != "" {
		ctx.clientIP = ip
		ctx.fingerprint = sha256Hash("ip:" + ip)
	} else {
		ctx.fingerprint = sha256Hash("unknown")
	}
}

// getJA3Fingerprint retrieves the JA3 TLS fingerprint from Envoy properties
func (ctx *httpContext) getJA3Fingerprint() string {
	// Try various property paths for JA3
	ja3Paths := [][]string{
		// Envoy's TLS properties
		{"connection", "tls", "ja3"},
		{"connection", "tls", "ja3_fingerprint"},
		// Alternative paths
		{"request", "tls", "ja3"},
		{"upstream", "tls", "ja3"},
	}

	for _, path := range ja3Paths {
		if value, err := proxywasm.GetProperty(path); err == nil && len(value) > 0 {
			return string(value)
		}
	}

	// Try reading from header (some setups inject JA3 as header)
	if ja3, err := proxywasm.GetHttpRequestHeader("x-ja3-fingerprint"); err == nil && ja3 != "" {
		return ja3
	}

	return ""
}

// getUserAgent retrieves the User-Agent header
func (ctx *httpContext) getUserAgent() string {
	ua, err := proxywasm.GetHttpRequestHeader("user-agent")
	if err != nil {
		return ""
	}
	return ua
}

// getClientIP retrieves the client IP address
func (ctx *httpContext) getClientIP() string {
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
			// Extract IP from address (may include port)
			addr := string(value)
			if idx := strings.LastIndex(addr, ":"); idx > 0 {
				// Check if this is IPv6 or IPv4:port
				if strings.Count(addr, ":") > 1 {
					// IPv6 address
					return addr
				}
				return addr[:idx]
			}
			return addr
		}
	}

	return ""
}

// getTrackingCookie retrieves the tracking cookie value
func (ctx *httpContext) getTrackingCookie() string {
	cookieHeader, err := proxywasm.GetHttpRequestHeader("cookie")
	if err != nil || cookieHeader == "" {
		return ""
	}

	return parseCookie(cookieHeader, ctx.config.CookieName)
}

// getRequestPath retrieves the request path
func (ctx *httpContext) getRequestPath() string {
	path, err := proxywasm.GetHttpRequestHeader(":path")
	if err != nil {
		return ""
	}

	// Strip query string
	if idx := strings.Index(path, "?"); idx > 0 {
		return path[:idx]
	}

	return path
}

// getRequestMethod retrieves the HTTP method
func (ctx *httpContext) getRequestMethod() string {
	method, err := proxywasm.GetHttpRequestHeader(":method")
	if err != nil {
		return ""
	}
	return method
}

// getRequestHost retrieves the Host header
func (ctx *httpContext) getRequestHost() string {
	// Try :authority first (HTTP/2)
	if host, err := proxywasm.GetHttpRequestHeader(":authority"); err == nil && host != "" {
		return host
	}

	// Fall back to Host header
	host, err := proxywasm.GetHttpRequestHeader("host")
	if err != nil {
		return ""
	}
	return host
}
