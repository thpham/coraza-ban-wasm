package main

import (
	"strings"

	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
)

// =============================================================================
// Request Helper Methods
// =============================================================================
// These methods provide convenient access to common request attributes.
// Note: Fingerprint calculation has been moved to FingerprintService.

// getRequestPath retrieves the request path.
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

// getRequestMethod retrieves the HTTP method.
func (ctx *httpContext) getRequestMethod() string {
	method, err := proxywasm.GetHttpRequestHeader(":method")
	if err != nil {
		return ""
	}
	return method
}

// getRequestHost retrieves the Host header.
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
