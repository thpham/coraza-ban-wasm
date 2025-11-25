package main

import (
	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm"
	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm/types"
)

func main() {}

func init() {
	proxywasm.SetVMContext(&vmContext{})
}

// vmContext is the root context for all plugin instances in this VM
type vmContext struct {
	types.DefaultVMContext
}

// OnVMStart is called when the VM starts
func (*vmContext) OnVMStart(vmConfigurationSize int) types.OnVMStartStatus {
	proxywasm.LogInfo("coraza-ban-wasm: VM started")
	return types.OnVMStartStatusOK
}

// NewPluginContext creates a new plugin context for each plugin configuration
func (*vmContext) NewPluginContext(contextID uint32) types.PluginContext {
	return &pluginContext{
		contextID: contextID,
	}
}

// pluginContext holds the configuration for a plugin instance
type pluginContext struct {
	types.DefaultPluginContext
	contextID uint32
	config    *PluginConfig
}

// OnPluginStart is called when the plugin starts
func (ctx *pluginContext) OnPluginStart(pluginConfigurationSize int) types.OnPluginStartStatus {
	// Read plugin configuration
	data, err := proxywasm.GetPluginConfiguration()
	if err != nil && err != types.ErrorStatusNotFound {
		proxywasm.LogCriticalf("coraza-ban-wasm: failed to get plugin configuration: %v", err)
		return types.OnPluginStartStatusFailed
	}

	// Parse configuration
	config, err := ParseConfig(data)
	if err != nil {
		proxywasm.LogCriticalf("coraza-ban-wasm: failed to parse configuration: %v", err)
		return types.OnPluginStartStatusFailed
	}

	ctx.config = config

	proxywasm.LogInfof("coraza-ban-wasm: plugin started with config - "+
		"redis_cluster=%s, ban_ttl=%d, scoring=%v, fingerprint_mode=%s, dry_run=%v",
		config.RedisCluster,
		config.BanTTLDefault,
		config.ScoringEnabled,
		config.FingerprintMode,
		config.DryRun,
	)

	return types.OnPluginStartStatusOK
}

// NewHttpContext creates a new HTTP context for each request
func (ctx *pluginContext) NewHttpContext(contextID uint32) types.HttpContext {
	return &httpContext{
		contextID:     contextID,
		pluginContext: ctx,
		config:        ctx.config,
	}
}

// httpContext handles individual HTTP requests
type httpContext struct {
	types.DefaultHttpContext
	contextID     uint32
	pluginContext *pluginContext
	config        *PluginConfig

	// Request state
	fingerprint     string
	clientIP        string
	userAgent       string
	cookieValue     string
	ja3Fingerprint  string
	isBanned        bool
	pendingRedis    bool
	corazaMetadata  *CorazaMetadata
	generatedCookie string
}

// OnHttpRequestHeaders is called when request headers are received
func (ctx *httpContext) OnHttpRequestHeaders(numHeaders int, endOfStream bool) types.Action {
	ctx.logDebug("processing request headers")

	// Calculate client fingerprint
	ctx.calculateFingerprint()

	// Check if client is banned
	if ctx.checkBan() {
		return ctx.denyRequest()
	}

	// If we need to check Redis asynchronously, pause the request
	if ctx.pendingRedis {
		return types.ActionPause
	}

	return types.ActionContinue
}

// OnHttpResponseHeaders is called when response headers are received
func (ctx *httpContext) OnHttpResponseHeaders(numHeaders int, endOfStream bool) types.Action {
	ctx.logDebug("processing response headers")

	// Extract Coraza WAF metadata
	ctx.corazaMetadata = ctx.extractCorazaMetadata()

	// Check if WAF blocked the request
	if ctx.corazaMetadata != nil && ctx.corazaMetadata.IsBlocked() {
		ctx.logInfo("WAF block detected: rule=%s, severity=%s, action=%s",
			ctx.corazaMetadata.RuleID,
			ctx.corazaMetadata.Severity,
			ctx.corazaMetadata.Action,
		)

		// Issue ban for this fingerprint
		ctx.issueBan()
	}

	// Inject tracking cookie if configured
	if ctx.config.InjectCookie && ctx.generatedCookie != "" {
		ctx.injectCookie()
	}

	return types.ActionContinue
}

// OnHttpStreamDone is called when the HTTP stream is complete
func (ctx *httpContext) OnHttpStreamDone() {
	ctx.logDebug("request completed")
}

// denyRequest sends a 403 Forbidden response
func (ctx *httpContext) denyRequest() types.Action {
	if ctx.config.DryRun {
		ctx.logInfo("DRY RUN: would deny request for fingerprint %s", ctx.fingerprint)
		return types.ActionContinue
	}

	ctx.logInfo("denying request for banned fingerprint %s", ctx.fingerprint)

	headers := [][2]string{
		{"content-type", "text/plain"},
		{"x-ban-reason", "coraza-ban-wasm"},
	}

	if err := proxywasm.SendHttpResponse(
		uint32(ctx.config.BanResponseCode),
		headers,
		[]byte(ctx.config.BanResponseBody),
		-1,
	); err != nil {
		ctx.logError("failed to send deny response: %v", err)
	}

	return types.ActionContinue
}

// injectCookie adds the tracking cookie to the response
func (ctx *httpContext) injectCookie() {
	cookieValue := ctx.config.CookieName + "=" + ctx.generatedCookie + "; Path=/; HttpOnly; SameSite=Strict"
	if err := proxywasm.AddHttpResponseHeader("Set-Cookie", cookieValue); err != nil {
		ctx.logError("failed to inject cookie: %v", err)
	}
}

// Logging helpers
func (ctx *httpContext) logDebug(format string, args ...interface{}) {
	if ctx.config.ShouldLog("debug") {
		proxywasm.LogDebugf("coraza-ban-wasm[%d]: "+format, append([]interface{}{ctx.contextID}, args...)...)
	}
}

func (ctx *httpContext) logInfo(format string, args ...interface{}) {
	if ctx.config.ShouldLog("info") {
		proxywasm.LogInfof("coraza-ban-wasm[%d]: "+format, append([]interface{}{ctx.contextID}, args...)...)
	}
}

func (ctx *httpContext) logWarn(format string, args ...interface{}) {
	if ctx.config.ShouldLog("warn") {
		proxywasm.LogWarnf("coraza-ban-wasm[%d]: "+format, append([]interface{}{ctx.contextID}, args...)...)
	}
}

func (ctx *httpContext) logError(format string, args ...interface{}) {
	if ctx.config.ShouldLog("error") {
		proxywasm.LogErrorf("coraza-ban-wasm[%d]: "+format, append([]interface{}{ctx.contextID}, args...)...)
	}
}
