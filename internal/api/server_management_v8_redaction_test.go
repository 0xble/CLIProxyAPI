package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/api/handlers/management"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"gopkg.in/yaml.v3"
)

func TestManagementV8ConfigReadOnlyRedaction(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	gin.SetMode(gin.TestMode)
	const raw = `# Keep safe configuration comment
config-version: 8
port: 8317
remote-management:
  secret-key: synthetic-management-secret
github-token: synthetic-github-secret
proxy-url: http://proxyuser:synthetic-proxy-secret@proxy.example.invalid:8080
api-keys: [synthetic-client-secret]
claude-api-key:
  - api-key: synthetic-provider-secret
    base-url: https://provider.example.invalid
openai-compatibility:
  - name: safe-compat-name
    base-url: https://compat.example.invalid
    headers:
      Authorization: Bearer synthetic-header-secret
      X-Api-Key: synthetic-xapikey-secret
oauth:
  providers:
    codex:
      live-media-relay:
        ice-servers:
          - urls: [turn:turn.example.invalid:3478]
            username: synthetic-ice-user
            credential: synthetic-ice-secret
routing:
  strategy: weighted-round-robin
plugins:
  configs:
    sample:
      password: synthetic-password-secret
      nested:
        - token: synthetic-token-secret
          label: safe-plugin-label
`
	secrets := []string{
		"synthetic-management-secret", "synthetic-client-secret", "synthetic-provider-secret",
		"synthetic-password-secret", "synthetic-token-secret", "synthetic-github-secret",
		"synthetic-proxy-secret", "synthetic-header-secret", "synthetic-xapikey-secret",
	}
	// Full-access JSON already strips ICE credentials, so these are only
	// asserted absent for read-only access.
	readOnlyHidden := []string{"synthetic-ice-user", "synthetic-ice-secret"}
	for _, mode := range []struct {
		name     string
		readOnly bool
	}{
		{"read-only", true},
		{"full-access", false},
	} {
		t.Run(mode.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
				t.Fatal(err)
			}
			cfg := &config.Config{RemoteManagement: config.RemoteManagement{
				ReadOnly:  mode.readOnly,
				SecretKey: "synthetic-management-secret",
			}}
			cfg.AuthDir = t.TempDir()
			cfg.Plugins.Dir = t.TempDir()
			h := management.NewHandler(cfg, path, nil)
			h.SetLocalPassword("synthetic-access-password")
			s := &Server{cfg: cfg, engine: gin.New(), mgmt: h}
			s.managementRoutesEnabled.Store(true)
			s.registerManagementRoutes()
			for _, endpoint := range []struct {
				path, contentType string
				yaml              bool
			}{
				{"/v8/management/config.yaml", "application/yaml; charset=utf-8", true},
				{"/v8/management/config", "application/json; charset=utf-8", false},
			} {
				t.Run(endpoint.path, func(t *testing.T) {
					req := httptest.NewRequest(http.MethodGet, endpoint.path, nil)
					req.RemoteAddr = "127.0.0.1:1234"
					req.Header.Set("Authorization", "Bearer synthetic-access-password")
					response := httptest.NewRecorder()
					s.engine.ServeHTTP(response, req)
					if response.Code != http.StatusOK {
						t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
					}
					if got := response.Header().Get("Content-Type"); got != endpoint.contentType {
						t.Errorf("Content-Type=%q, want %q", got, endpoint.contentType)
					}
					if got := response.Header().Get("Cache-Control"); got != "no-store" {
						t.Errorf("Cache-Control=%q, want no-store", got)
					}
					if got, want := response.Header().Get("ETag"), `"`+config.ComputeSourceHash([]byte(raw))+`"`; got != want {
						t.Errorf("ETag=%q, want source ETag %q", got, want)
					}
					body := response.Body.String()
					for _, secret := range secrets {
						if strings.Contains(body, secret) == mode.readOnly {
							t.Errorf("secret %q presence does not match read-only=%v", secret, mode.readOnly)
						}
					}
					if mode.readOnly {
						for _, secret := range readOnlyHidden {
							if strings.Contains(body, secret) {
								t.Errorf("read-only response leaked %q", secret)
							}
						}
					}
					for _, safe := range []string{"weighted-round-robin", "safe-plugin-label", "proxy.example.invalid", "turn.example.invalid"} {
						if !strings.Contains(body, safe) {
							t.Errorf("response lost safe metadata %q", safe)
						}
					}
					var decoded map[string]any
					if endpoint.yaml {
						if err := yaml.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
							t.Fatalf("invalid YAML response: %v", err)
						}
						if !strings.Contains(body, "# Keep safe configuration comment") {
							t.Error("YAML response lost safe comment")
						}
						if !mode.readOnly {
							normalized, _, err := config.NormalizeConfigLayout([]byte(raw), true)
							if err != nil {
								t.Fatal(err)
							}
							if body != string(normalized) {
								t.Error("full-access YAML response changed normalized bytes")
							}
						}
					} else if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
						t.Fatalf("invalid JSON response: %v", err)
					}
					if decoded["server"] == nil || decoded["routing"] == nil {
						t.Error("response lost safe configuration sections")
					}
					persisted, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					if string(persisted) != raw {
						t.Error("GET changed persisted configuration")
					}
				})
			}
		})
	}
}
