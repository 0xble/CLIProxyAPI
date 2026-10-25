package management

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/util"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

const (
	latestReleaseURL       = "https://api.github.com/repos/router-for-me/CLIProxyAPI/releases/latest"
	latestReleaseUserAgent = "CLIProxyAPI"
)

func (h *Handler) GetConfig(c *gin.Context) {
	if h == nil || h.cfg == nil {
		c.JSON(200, gin.H{})
		return
	}
	h.mu.Lock()
	readOnly := h.cfg.RemoteManagement.ReadOnly
	cfg := new(*h.cfg)
	h.mu.Unlock()
	if readOnly {
		var payload any
		encoded, errMarshal := json.Marshal(cfg)
		if errMarshal != nil || json.Unmarshal(encoded, &payload) != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "encode_failed"})
			return
		}
		c.JSON(http.StatusOK, redactReadOnlyConfig(payload))
		return
	}
	c.JSON(200, cfg)
}

// isReadOnlySecretKey reports whether a config key names a credential that a
// read-only management view must never return.
func isReadOnlySecretKey(key string) bool {
	k := normalizeReadOnlyKey(key)
	switch k {
	case "api-key", "api-keys", "secret-key", "password", "token", "credential", "authorization", "github-token",
		"secret", "client-secret", "access-token", "refresh-token", "id-token", "private-key":
		return true
	}
	// Provider sections such as claude-api-key are lists of entries whose own
	// api-key field is removed above, so a "-api-key" suffix only marks a
	// secret when it holds a scalar, such as an x-api-key header value.
	return strings.HasSuffix(k, "-token") || strings.HasSuffix(k, "-secret") || strings.HasSuffix(k, "-password") ||
		strings.HasSuffix(k, "-private-key")
}

// isReadOnlySecretScalarKey reports whether a key holding a scalar value is a
// credential, extending isReadOnlySecretKey with "-api-key" header names.
func isReadOnlySecretScalarKey(key string) bool {
	return strings.HasSuffix(normalizeReadOnlyKey(key), "-api-key")
}

// normalizeReadOnlyKey lowercases a key and folds "_", "." and spaces to "-",
// because opaque plugin configs use snake_case names such as access_token.
func normalizeReadOnlyKey(key string) string {
	return strings.NewReplacer("_", "-", ".", "-", " ", "-").Replace(strings.ToLower(strings.TrimSpace(key)))
}

// isReadOnlyURLKey reports whether a scalar key holds a URL whose userinfo
// must be dropped, such as proxy-url, proxy_url or base-url.
func isReadOnlyURLKey(key string) bool {
	k := normalizeReadOnlyKey(key)
	return k == "url" || strings.HasSuffix(k, "-url")
}

// isReadOnlyUsernameKey reports whether a key names the identifier that pairs
// with a credential sibling, such as an ICE server username.
func isReadOnlyUsernameKey(key string) bool {
	k := normalizeReadOnlyKey(key)
	return k == "username" || k == "user-name" || k == "user"
}

// redactReadOnlyProxyURL drops userinfo from any URL-shaped value so embedded
// credentials stay private in read-only views. It covers hierarchical URLs
// (socks5://user:pass@host) and opaque ICE URLs (turn:user:pass@host), keeping
// the scheme and host. Other values are returned unchanged.
func redactReadOnlyProxyURL(value string) string {
	at := strings.LastIndex(value, "@")
	if at < 0 {
		return value
	}
	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err != nil {
			return ""
		}
		if parsed.User == nil {
			return value
		}
		parsed.User = nil
		return parsed.String()
	}
	scheme, rest, ok := strings.Cut(value, ":")
	if !ok || !isReadOnlyOpaqueURLScheme(scheme) || strings.Index(rest, "@") < 0 {
		return value
	}
	return scheme + ":" + rest[strings.LastIndex(rest, "@")+1:]
}

// isReadOnlyOpaqueURLScheme reports whether a scheme uses the opaque
// scheme:userinfo@host form for credentials, as ICE server URLs do.
func isReadOnlyOpaqueURLScheme(scheme string) bool {
	switch strings.ToLower(scheme) {
	case "turn", "turns", "stun", "stuns":
		return true
	}
	return false
}

func redactReadOnlyConfig(value any) any {
	switch item := value.(type) {
	case map[string]any:
		hasCredential := false
		for key := range item {
			if normalizeReadOnlyKey(key) == "credential" {
				hasCredential = true
			}
		}
		for key := range item {
			_, isScalar := item[key].(string)
			_, isMapping := item[key].(map[string]any)
			v8ProviderGroups := normalizeReadOnlyKey(key) == "api-keys" && isMapping
			switch {
			case !v8ProviderGroups && isReadOnlySecretKey(key), isScalar && isReadOnlySecretScalarKey(key), hasCredential && isReadOnlyUsernameKey(key):
				delete(item, key)
			case isScalar && isReadOnlyURLKey(key):
				item[key] = redactReadOnlyProxyURL(item[key].(string))
			default:
				item[key] = redactReadOnlyConfig(item[key])
			}
		}
	case []any:
		for index := range item {
			item[index] = redactReadOnlyConfig(item[index])
		}
	case string:
		// Userinfo can sit in any URL value, such as ice-servers urls lists,
		// so every string is checked, not only url-named keys.
		return redactReadOnlyProxyURL(item)
	}
	return value
}

type releaseInfo struct {
	TagName string `json:"tag_name"`
	Name    string `json:"name"`
}

func setLatestReleaseRequestHeaders(req *http.Request) {
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", latestReleaseUserAgent)
	if token := util.ResolveGitHubToken(); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
}

// GetLatestVersion returns the latest release version from GitHub without downloading assets.
func (h *Handler) GetLatestVersion(c *gin.Context) {
	client := &http.Client{Timeout: 10 * time.Second}
	proxyURL := ""
	if h != nil && h.cfg != nil {
		proxyURL = strings.TrimSpace(h.cfg.ProxyURL)
	}
	if proxyURL != "" {
		sdkCfg := &sdkconfig.SDKConfig{ProxyURL: proxyURL}
		util.SetProxy(sdkCfg, client)
	}

	req, err := http.NewRequestWithContext(c.Request.Context(), http.MethodGet, latestReleaseURL, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "request_create_failed", "message": err.Error()})
		return
	}
	setLatestReleaseRequestHeaders(req)

	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "request_failed", "message": err.Error()})
		return
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.WithError(errClose).Debug("failed to close latest version response body")
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		c.JSON(http.StatusBadGateway, gin.H{"error": "unexpected_status", "message": fmt.Sprintf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))})
		return
	}

	var info releaseInfo
	if errDecode := json.NewDecoder(resp.Body).Decode(&info); errDecode != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "decode_failed", "message": errDecode.Error()})
		return
	}

	version := strings.TrimSpace(info.TagName)
	if version == "" {
		version = strings.TrimSpace(info.Name)
	}
	if version == "" {
		c.JSON(http.StatusBadGateway, gin.H{"error": "invalid_response", "message": "missing release version"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"latest-version": version})
}

func WriteConfig(path string, data []byte) error {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return err
	}
	if len(doc.Content) > 0 && config.IsV8ConfigLayout(doc.Content[0]) {
		var err error
		data, _, err = config.NormalizeConfigLayout(data, true)
		if err != nil {
			return err
		}
	}
	data = config.NormalizeCommentIndentation(data)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	if _, errWrite := f.Write(data); errWrite != nil {
		_ = f.Close()
		return errWrite
	}
	if errSync := f.Sync(); errSync != nil {
		_ = f.Close()
		return errSync
	}
	return f.Close()
}

func (h *Handler) PutConfigYAML(c *gin.Context) {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_yaml", "message": "cannot read request body"})
		return
	}
	var cfg config.Config
	if err = yaml.Unmarshal(body, &cfg); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_yaml", "message": err.Error()})
		return
	}
	// Validate config using LoadConfigOptional with optional=false to enforce parsing
	tmpDir := filepath.Dir(h.configFilePath)
	tmpFile, err := os.CreateTemp(tmpDir, "config-validate-*.yaml")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "write_failed", "message": err.Error()})
		return
	}
	tempFile := tmpFile.Name()
	if _, errWrite := tmpFile.Write(body); errWrite != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tempFile)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "write_failed", "message": errWrite.Error()})
		return
	}
	if errClose := tmpFile.Close(); errClose != nil {
		_ = os.Remove(tempFile)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "write_failed", "message": errClose.Error()})
		return
	}
	defer func() {
		_ = os.Remove(tempFile)
	}()
	_, err = config.LoadConfigOptional(tempFile, false)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "invalid_config", "message": err.Error()})
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if WriteConfig(h.configFilePath, body) != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "write_failed", "message": "failed to write config"})
		return
	}
	// Reload into handler to keep memory in sync
	newCfg, err := config.LoadConfig(h.configFilePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "reload_failed", "message": err.Error()})
		return
	}
	h.cfg = newCfg
	c.JSON(http.StatusOK, gin.H{"ok": true, "changed": []string{"config"}})
}

// GetConfigYAML returns the raw config.yaml file bytes without re-encoding.
// It preserves comments and original formatting/styles.
func (h *Handler) GetConfigYAML(c *gin.Context) {
	data, err := os.ReadFile(h.configFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not_found", "message": "config file not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "read_failed", "message": err.Error()})
		return
	}
	h.mu.Lock()
	readOnly := h.cfg != nil && h.cfg.RemoteManagement.ReadOnly
	h.mu.Unlock()
	if readOnly {
		var payload any
		if errUnmarshal := yaml.Unmarshal(data, &payload); errUnmarshal != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid_config"})
			return
		}
		sanitized, errMarshal := yaml.Marshal(redactReadOnlyConfig(payload))
		if errMarshal != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "encode_failed"})
			return
		}
		data = sanitized
	}
	c.Header("Content-Type", "application/yaml; charset=utf-8")
	c.Header("Cache-Control", "no-store")
	c.Header("X-Content-Type-Options", "nosniff")
	// Write raw bytes as-is
	_, _ = c.Writer.Write(data)
}

// Debug
func (h *Handler) GetDebug(c *gin.Context) { c.JSON(200, gin.H{"debug": h.cfg.Debug}) }
func (h *Handler) PutDebug(c *gin.Context) { h.updateBoolField(c, func(v bool) { h.cfg.Debug = v }) }

// UsageStatisticsEnabled
func (h *Handler) GetUsageStatisticsEnabled(c *gin.Context) {
	c.JSON(200, gin.H{"usage-statistics-enabled": h.cfg.UsageStatisticsEnabled})
}
func (h *Handler) PutUsageStatisticsEnabled(c *gin.Context) {
	h.updateBoolField(c, func(v bool) { h.cfg.UsageStatisticsEnabled = v })
}

// UsageStatisticsEnabled
func (h *Handler) GetLoggingToFile(c *gin.Context) {
	c.JSON(200, gin.H{"logging-to-file": h.cfg.LoggingToFile})
}
func (h *Handler) PutLoggingToFile(c *gin.Context) {
	h.updateBoolField(c, func(v bool) { h.cfg.LoggingToFile = v })
}

// LogsMaxTotalSizeMB
func (h *Handler) GetLogsMaxTotalSizeMB(c *gin.Context) {
	c.JSON(200, gin.H{"logs-max-total-size-mb": h.cfg.LogsMaxTotalSizeMB})
}
func (h *Handler) PutLogsMaxTotalSizeMB(c *gin.Context) {
	var body struct {
		Value *int `json:"value"`
	}
	if errBindJSON := c.ShouldBindJSON(&body); errBindJSON != nil || body.Value == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	value := *body.Value
	if value < 0 {
		value = 0
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cfg.LogsMaxTotalSizeMB = value
	h.persistLocked(c)
}

// ErrorLogsMaxFiles
func (h *Handler) GetErrorLogsMaxFiles(c *gin.Context) {
	c.JSON(200, gin.H{"error-logs-max-files": h.cfg.ErrorLogsMaxFiles})
}
func (h *Handler) PutErrorLogsMaxFiles(c *gin.Context) {
	var body struct {
		Value *int `json:"value"`
	}
	if errBindJSON := c.ShouldBindJSON(&body); errBindJSON != nil || body.Value == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	value := *body.Value
	if value < 0 {
		value = 10
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cfg.ErrorLogsMaxFiles = value
	h.persistLocked(c)
}

// Request log
func (h *Handler) GetRequestLog(c *gin.Context) { c.JSON(200, gin.H{"request-log": h.cfg.RequestLog}) }
func (h *Handler) PutRequestLog(c *gin.Context) {
	h.updateBoolField(c, func(v bool) { h.cfg.RequestLog = v })
}

// Websocket auth
func (h *Handler) GetWebsocketAuth(c *gin.Context) {
	c.JSON(200, gin.H{"ws-auth": h.cfg.WebsocketAuth})
}
func (h *Handler) PutWebsocketAuth(c *gin.Context) {
	h.updateBoolField(c, func(v bool) { h.cfg.WebsocketAuth = v })
}

// Request retry
func (h *Handler) GetRequestRetry(c *gin.Context) {
	c.JSON(200, gin.H{"request-retry": h.cfg.RequestRetry})
}
func (h *Handler) PutRequestRetry(c *gin.Context) {
	h.updateIntField(c, func(v int) { h.cfg.RequestRetry = v })
}

// Max retry credentials
func (h *Handler) GetMaxRetryCredentials(c *gin.Context) {
	c.JSON(200, gin.H{"max-retry-credentials": h.cfg.MaxRetryCredentials})
}
func (h *Handler) PutMaxRetryCredentials(c *gin.Context) {
	h.updateIntField(c, func(v int) { h.cfg.MaxRetryCredentials = v })
}

// Max retry interval
func (h *Handler) GetMaxRetryInterval(c *gin.Context) {
	c.JSON(200, gin.H{"max-retry-interval": h.cfg.MaxRetryInterval})
}
func (h *Handler) PutMaxRetryInterval(c *gin.Context) {
	h.updateIntField(c, func(v int) { h.cfg.MaxRetryInterval = v })
}

// ForceModelPrefix
func (h *Handler) GetForceModelPrefix(c *gin.Context) {
	c.JSON(200, gin.H{"force-model-prefix": h.cfg.ForceModelPrefix})
}
func (h *Handler) PutForceModelPrefix(c *gin.Context) {
	h.updateBoolField(c, func(v bool) { h.cfg.ForceModelPrefix = v })
}

func normalizeRoutingStrategy(strategy string) (string, bool) {
	normalized := strings.ToLower(strings.TrimSpace(strategy))
	switch normalized {
	case "", "round-robin", "roundrobin", "rr":
		return "round-robin", true
	case "weighted-round-robin", "weightedroundrobin", "wrr":
		return "weighted-round-robin", true
	case "fill-first", "fillfirst", "ff":
		return "fill-first", true
	default:
		return "", false
	}
}

// RoutingStrategy
func (h *Handler) GetRoutingStrategy(c *gin.Context) {
	strategy, ok := normalizeRoutingStrategy(h.cfg.Routing.Strategy)
	if !ok {
		c.JSON(200, gin.H{"strategy": strings.TrimSpace(h.cfg.Routing.Strategy)})
		return
	}
	c.JSON(200, gin.H{"strategy": strategy})
}
func (h *Handler) PutRoutingStrategy(c *gin.Context) {
	var body struct {
		Value *string `json:"value"`
	}
	if errBindJSON := c.ShouldBindJSON(&body); errBindJSON != nil || body.Value == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	normalized, ok := normalizeRoutingStrategy(*body.Value)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid strategy"})
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cfg.Routing.Strategy = normalized
	h.persistLocked(c)
}

// Proxy URL
func (h *Handler) GetProxyURL(c *gin.Context) { c.JSON(200, gin.H{"proxy-url": h.cfg.ProxyURL}) }
func (h *Handler) PutProxyURL(c *gin.Context) {
	h.updateStringField(c, func(v string) { h.cfg.ProxyURL = v })
}
func (h *Handler) DeleteProxyURL(c *gin.Context) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cfg.ProxyURL = ""
	h.persistLocked(c)
}
