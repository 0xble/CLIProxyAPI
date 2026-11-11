package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/api/handlers/management"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

const routeWalkConfig = `config-version: 8
port: 8317
remote-management:
  secret-key: synthetic-walk-management-secret
github-token: synthetic-walk-github-token-value
proxy-url: http://walkuser:synthetic-walk-proxy-secret@proxy.example.invalid:8080
api-keys:
  - synthetic-walk-client-key-0001
  - synthetic-walk-client-key-0002
gemini-api-key:
  - api-key: synthetic-walk-gemini-key-0001
    base-url: https://gemini.example.invalid
interactions-api-key:
  - api-key: synthetic-walk-interactions-key-1
codex-api-key:
  - api-key: synthetic-walk-codex-key-00001
    base-url: https://codex.example.invalid
xai-api-key:
  - api-key: synthetic-walk-xai-key-000001
meta-api-key:
  - api-key: synthetic-walk-meta-key-00001
vertex-api-key:
  - api-key: synthetic-walk-vertex-key-0001
    base-url: https://vertex.example.invalid
claude-api-key:
  - api-key: synthetic-walk-claude-key-0001
    base-url: https://claude.example.invalid
    headers:
      X-Api-Key: synthetic-walk-claude-header-1
openai-compatibility:
  - name: walk-compat
    base-url: https://compat.example.invalid
    api-key-entries:
      - api-key: synthetic-walk-compat-key-0001
        proxy-url: socks5://compatuser:synthetic-walk-compat-proxy@proxy.example.invalid:1080
plugins:
  configs:
    sample:
      api_key: synthetic-walk-plugin-api-key-1
      proxy_url: socks5://pluginuser:synthetic-walk-plugin-proxy@proxy.example.invalid:1080
`

// routeWalkSecrets are the raw values that must never appear in a management GET.
var routeWalkSecrets = []string{
	"synthetic-walk-management-secret", "synthetic-walk-github-token-value", "synthetic-walk-proxy-secret",
	"walkuser", "synthetic-walk-client-key-0001", "synthetic-walk-client-key-0002",
	"synthetic-walk-gemini-key-0001", "synthetic-walk-interactions-key-1", "synthetic-walk-codex-key-00001",
	"synthetic-walk-xai-key-000001", "synthetic-walk-meta-key-00001", "synthetic-walk-vertex-key-0001",
	"synthetic-walk-claude-key-0001", "synthetic-walk-claude-header-1", "synthetic-walk-compat-key-0001",
	"compatuser", "synthetic-walk-compat-proxy", "synthetic-walk-plugin-api-key-1", "pluginuser",
	"synthetic-walk-plugin-proxy", "synthetic-walk-oauth-access-token", "synthetic-walk-oauth-refresh-token",
}

// routeWalkRawAllowlist is the complete set of management GET routes that may
// return raw secrets. They are deliberate operator exports of OAuth token files
// that already sit readable in the auth dir. Adding a route here is a security
// decision; every other GET route must redact.
var routeWalkRawAllowlist = map[string]string{
	"/v8/management/credentials/download": "raw OAuth token file export",
	"/v0/management/auth-files/download":  "legacy alias of credentials/download",
}

// routeWalkSkip lists GET routes that are not exercised because they reach the
// network or start an OAuth flow and never read configuration.
var routeWalkSkip = map[string]string{
	"/v0/management/latest-version":        "GitHub release lookup",
	"/v8/management/server/latest-version": "GitHub release lookup",
	"/v0/management/plugin-store":          "remote plugin catalog",
	"/v8/management/plugins/store":         "remote plugin catalog",
}

func TestManagementGETRoutesNeverReturnRawSecrets(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	gin.SetMode(gin.TestMode)
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(routeWalkConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.ParseConfigBytes([]byte(routeWalkConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.AuthDir = filepath.Join(dir, "auth")
	cfg.Plugins.Dir = filepath.Join(dir, "plugins")
	for _, d := range []string{cfg.AuthDir, cfg.Plugins.Dir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	token := `{"type":"codex","email":"walk@example.invalid","access_token":"synthetic-walk-oauth-access-token","refresh_token":"synthetic-walk-oauth-refresh-token"}`
	if err := os.WriteFile(filepath.Join(cfg.AuthDir, "walk.json"), []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []struct {
		name     string
		readOnly bool
	}{{"full-access", false}, {"read-only", true}} {
		t.Run(mode.name, func(t *testing.T) {
			cfg.RemoteManagement.ReadOnly = mode.readOnly
			h := management.NewHandler(cfg, path, nil)
			h.SetLocalPassword("synthetic-walk-access-password")
			s := &Server{cfg: cfg, engine: gin.New(), mgmt: h}
			s.managementRoutesEnabled.Store(true)
			s.registerManagementRoutes()

			walked := 0
			for _, route := range s.engine.Routes() {
				if route.Method != http.MethodGet || !(strings.HasPrefix(route.Path, "/v0/management") || strings.HasPrefix(route.Path, "/v8/management")) {
					continue
				}
				if _, skip := routeWalkSkip[route.Path]; skip {
					continue
				}
				url := route.Path
				for _, param := range []string{":id", ":name", ":channel", ":provider", ":state"} {
					url = strings.ReplaceAll(url, param, "sample")
				}
				if strings.Contains(url, ":") {
					t.Errorf("route %s has a parameter the walk does not fill", route.Path)
					continue
				}
				if strings.Contains(url, "download") {
					url += "?name=walk.json"
				}
				walked++
				req := httptest.NewRequest(http.MethodGet, url, nil)
				req.RemoteAddr = "127.0.0.1:1234"
				req.Header.Set("Authorization", "Bearer synthetic-walk-access-password")
				rec := httptest.NewRecorder()
				s.engine.ServeHTTP(rec, req)
				if _, allowed := routeWalkRawAllowlist[route.Path]; allowed {
					continue
				}
				body := rec.Body.String()
				for _, secret := range routeWalkSecrets {
					if strings.Contains(body, secret) {
						t.Errorf("GET %s (status %d) leaked synthetic secret %q", route.Path, rec.Code, secret)
					}
				}
			}
			if walked < 40 {
				t.Errorf("walked only %d GET routes; route registration changed", walked)
			}
			for allowed := range routeWalkRawAllowlist {
				found := false
				for _, route := range s.engine.Routes() {
					if route.Path == allowed {
						found = true
					}
				}
				if !found {
					t.Errorf("allowlisted route %s no longer exists; remove it from the allowlist", allowed)
				}
			}
		})
	}
}
