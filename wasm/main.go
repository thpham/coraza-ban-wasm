package main

import (
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
)

func main() {
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
	logger := NewPluginLogger(ctx.config, contextID)
	banStore := NewLocalBanStore(logger)
	scoreStore := NewLocalScoreStore(logger, ctx.config.ScoreDecaySeconds)

	return &httpContext{
		contextID:          contextID,
		pluginContext:      ctx,
		config:             ctx.config,
		logger:             logger,
		banStore:           banStore,
		scoreStore:         scoreStore,
		fingerprintService: NewFingerprintService(ctx.config, logger),
		metadataService:    NewMetadataService(logger),
		banService:         NewBanService(ctx.config, logger, banStore, scoreStore),
	}
}

// httpContext handles individual HTTP requests
type httpContext struct {
	types.DefaultHttpContext
	contextID     uint32
	pluginContext *pluginContext
	config        *PluginConfig

	// Services
	logger             Logger
	banStore           BanStore
	scoreStore         ScoreStore
	fingerprintService *FingerprintService
	metadataService    *MetadataService
	banService         *BanService

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

	// Calculate client fingerprint using the service
	result := ctx.fingerprintService.CalculateWithDetails()
	ctx.fingerprint = result.Fingerprint
	ctx.clientIP = result.ClientIP
	ctx.userAgent = result.UserAgent
	ctx.ja3Fingerprint = result.JA3Fingerprint
	ctx.cookieValue = result.CookieValue
	ctx.generatedCookie = result.GeneratedCookie

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
	// Skip if we already denied this request (client was banned)
	if ctx.isBanned {
		ctx.logDebug("skipping response processing - request was already denied as banned")
		return types.ActionContinue
	}

	statusCode := ctx.metadataService.GetStatusCode()
	ctx.logDebug("processing response headers, status=%d", statusCode)

	// Extract Coraza WAF metadata using the service
	ctx.corazaMetadata = ctx.metadataService.Extract()

	// Check if WAF blocked the request
	if ctx.corazaMetadata != nil && ctx.corazaMetadata.IsBlocked() {
		ctx.logInfo("WAF block detected: rule=%s, severity=%s, action=%s",
			ctx.corazaMetadata.RuleID,
			ctx.corazaMetadata.Severity,
			ctx.corazaMetadata.Action,
		)

		// Issue ban for this fingerprint
		ctx.issueBan()
	} else if statusCode == 403 && ctx.fingerprint != "" {
		// Fallback: if we got 403 but no metadata, assume it's a WAF block
		// This is safe because Coraza WAF is the only downstream filter that returns 403
		ctx.logInfo("WAF block detected (403 fallback), issuing ban for fingerprint=%s", ctx.fingerprint)
		ctx.corazaMetadata = &CorazaMetadata{
			Action:   "block",
			Severity: "medium",
			RuleID:   "waf-403",
		}
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

// Logging helpers - delegate to the logger interface
func (ctx *httpContext) logDebug(format string, args ...interface{}) {
	ctx.logger.Debug(format, args...)
}

func (ctx *httpContext) logInfo(format string, args ...interface{}) {
	ctx.logger.Info(format, args...)
}

func (ctx *httpContext) logWarn(format string, args ...interface{}) {
	ctx.logger.Warn(format, args...)
}

func (ctx *httpContext) logError(format string, args ...interface{}) {
	ctx.logger.Error(format, args...)
}
