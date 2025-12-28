package main

import (
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
)

// Redis HTTP API integration helpers
// Used by WebdisClient for async HTTP-based Redis operations.

// getHttpCallResponseStatus extracts the :status from HTTP call response headers.
// This is a helper function used by WebdisClient to check response status.
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
