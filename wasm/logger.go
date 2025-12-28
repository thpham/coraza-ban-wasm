package main

import (
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
)

// =============================================================================
// Logger Implementation
// =============================================================================

// PluginLogger implements the Logger interface using proxy-wasm logging.
// It respects the configured log level to filter messages.
type PluginLogger struct {
	config    *PluginConfig
	contextID uint32
}

// NewPluginLogger creates a new logger with the given configuration.
func NewPluginLogger(config *PluginConfig, contextID uint32) *PluginLogger {
	return &PluginLogger{
		config:    config,
		contextID: contextID,
	}
}

// Debug logs a debug-level message.
func (l *PluginLogger) Debug(format string, args ...interface{}) {
	if l.config.ShouldLog(LogLevelDebug) {
		proxywasm.LogDebugf("coraza-ban-wasm[%d]: "+format, append([]interface{}{l.contextID}, args...)...)
	}
}

// Info logs an info-level message.
func (l *PluginLogger) Info(format string, args ...interface{}) {
	if l.config.ShouldLog(LogLevelInfo) {
		proxywasm.LogInfof("coraza-ban-wasm[%d]: "+format, append([]interface{}{l.contextID}, args...)...)
	}
}

// Warn logs a warning-level message.
func (l *PluginLogger) Warn(format string, args ...interface{}) {
	if l.config.ShouldLog(LogLevelWarn) {
		proxywasm.LogWarnf("coraza-ban-wasm[%d]: "+format, append([]interface{}{l.contextID}, args...)...)
	}
}

// Error logs an error-level message.
func (l *PluginLogger) Error(format string, args ...interface{}) {
	if l.config.ShouldLog(LogLevelError) {
		proxywasm.LogErrorf("coraza-ban-wasm[%d]: "+format, append([]interface{}{l.contextID}, args...)...)
	}
}

// Compile-time interface verification
var _ Logger = (*PluginLogger)(nil)
