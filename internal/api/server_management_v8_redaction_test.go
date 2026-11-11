package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/api/handlers/management"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"gopkg.in/yaml.v3"
)

func TestManagementConfigAlwaysRedactsSecrets(t *testing.T) {
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
          - urls: [turn:turn.example.invalid:3478, "turn:iceurluser:synthetic-ice-url-secret@turn.example.invalid:3479"]
            username: synthetic-ice-user
            credential: synthetic-ice-secret
routing:
  strategy: weighted-round-robin
plugins:
  configs:
    sample:
      password: synthetic-password-secret
      access_token: synthetic-snake-access-secret
      refresh_token: synthetic-snake-refresh-secret
      api_key: synthetic-snake-apikey-secret
      client_secret: synthetic-snake-client-secret
      proxy_url: socks5://plugin-user:synthetic-snake-proxy-secret@proxy.example.invalid:1080
      relay:
        credential: synthetic-snake-relay-secret
        user_name: synthetic-snake-relay-user
      nested:
        - token: synthetic-token-secret
          label: safe-plugin-label
`
	secrets := []string{
		"synthetic-management-secret", "synthetic-client-secret", "synthetic-provider-secret",
		"synthetic-password-secret", "synthetic-token-secret", "synthetic-github-secret",
		"synthetic-proxy-secret", "synthetic-header-secret", "synthetic-xapikey-secret",
		"synthetic-snake-access-secret", "synthetic-snake-refresh-secret", "synthetic-snake-apikey-secret",
		"synthetic-snake-client-secret",
		"synthetic-snake-proxy-secret", "synthetic-snake-relay-secret",
		"synthetic-ice-url-secret",
	}
	secrets = append(secrets, "synthetic-ice-user", "synthetic-ice-secret", "synthetic-snake-relay-user", "plugin-user", "iceurluser", "proxyuser")
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
			cfg, err := config.ParseConfigBytes([]byte(raw))
			if err != nil {
				t.Fatal(err)
			}
			cfg.RemoteManagement.ReadOnly = mode.readOnly
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
				{"/v0/management/config", "application/json; charset=utf-8", false},
				{"/v0/management/config.yaml", "application/yaml; charset=utf-8", true},
			} {
				if mode.readOnly && endpoint.path == "/v0/management/config.yaml" {
					// The legacy YAML path is intentionally outside the read-only allowlist.
					continue
				}
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
					if got := response.Header().Get("Cache-Control"); endpoint.path != "/v0/management/config" && got != "no-store" {
						t.Errorf("Cache-Control=%q, want no-store", got)
					}
					if strings.HasPrefix(endpoint.path, "/v8/") {
						if got, want := response.Header().Get("ETag"), `"`+config.ComputeSourceHash([]byte(raw))+`"`; got != want {
							t.Errorf("ETag=%q, want source ETag %q", got, want)
						}
					}
					body := response.Body.String()
					for _, secret := range secrets {
						if strings.Contains(body, secret) {
							t.Errorf("response leaked synthetic secret %q", secret)
						}
					}
					for _, safe := range []string{"weighted-round-robin", "safe-plugin-label", "proxy.example.invalid", "provider.example.invalid", "turn.example.invalid"} {
						if safe == "safe-plugin-label" && endpoint.path == "/v0/management/config" {
							// The legacy typed JSON view omits plugin configuration entirely.
							continue
						}
						if !strings.Contains(body, safe) {
							t.Errorf("response lost safe metadata %q", safe)
						}
					}
					var decoded map[string]any
					if endpoint.yaml {
						if err := yaml.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
							t.Fatalf("invalid YAML response: %v", err)
						}
						if strings.HasPrefix(endpoint.path, "/v8/") && !strings.Contains(body, "# Keep safe configuration comment") {
							t.Error("YAML response lost safe comment")
						}
					} else if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
						t.Fatalf("invalid JSON response: %v", err)
					}
					if decoded["routing"] == nil || (strings.HasPrefix(endpoint.path, "/v8/") && decoded["server"] == nil) {
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
			if !mode.readOnly {
				for _, endpoint := range []struct {
					path string
					want int
				}{
					{"/v8/management/config/api-keys/claude", http.StatusOK},
					{"/v8/management/config/oauth/providers/codex/live-media-relay/ice-servers", http.StatusOK},
					{"/v8/management/config/plugins/configs/sample/password", http.StatusNotFound},
				} {
					req := httptest.NewRequest(http.MethodGet, endpoint.path, nil)
					req.RemoteAddr = "127.0.0.1:1234"
					req.Header.Set("Authorization", "Bearer synthetic-access-password")
					response := httptest.NewRecorder()
					s.engine.ServeHTTP(response, req)
					if response.Code != endpoint.want {
						t.Fatalf("config subtree GET status=%d, want %d", response.Code, endpoint.want)
					}
					for _, secret := range secrets {
						if strings.Contains(response.Body.String(), secret) {
							t.Errorf("config subtree leaked synthetic secret %q", secret)
						}
					}
				}
			}
		})
	}
}

func TestManagementRedactedCredentialsAllowWritableCooldownReset(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	gin.SetMode(gin.TestMode)
	for _, readOnly := range []bool{true, false} {
		name := "full-access"
		if readOnly {
			name = "read-only"
		}
		t.Run(name, func(t *testing.T) {
			cfg := &config.Config{AuthDir: t.TempDir(), RemoteManagement: config.RemoteManagement{ReadOnly: readOnly, SecretKey: "synthetic-management-secret"}}
			cfg.Plugins.Dir = t.TempDir()
			manager := coreauth.NewManager(nil, nil, nil)
			deadline := time.Now().Add(time.Hour)
			for _, id := range []string{"target", "sibling"} {
				auth := &coreauth.Auth{
					ID: id, FileName: id + ".json", Provider: "claude", Status: coreauth.StatusError,
					Attributes:  map[string]string{"path": filepath.Join(cfg.AuthDir, id+".json")},
					Unavailable: true, NextRetryAfter: deadline,
					Quota: coreauth.QuotaState{Exceeded: true, NextRecoverAt: deadline},
					ModelStates: map[string]*coreauth.ModelState{"test-model": {
						Status: coreauth.StatusError, Unavailable: true, NextRetryAfter: deadline,
						Quota: coreauth.QuotaState{Exceeded: true, NextRecoverAt: deadline},
					}},
					Metadata: map[string]any{"access_token": "synthetic-access-token", "refresh_token": "synthetic-refresh-token"},
				}
				if _, err := manager.Register(context.Background(), auth); err != nil {
					t.Fatal(err)
				}
			}
			h := management.NewHandler(cfg, filepath.Join(t.TempDir(), "config.yaml"), manager)
			h.SetLocalPassword("synthetic-access-password")
			s := &Server{cfg: cfg, engine: gin.New(), mgmt: h}
			s.managementRoutesEnabled.Store(true)
			s.registerManagementRoutes()
			request := func(method, path, body string) *httptest.ResponseRecorder {
				t.Helper()
				req := httptest.NewRequest(method, path, strings.NewReader(body))
				req.RemoteAddr = "127.0.0.1:1234"
				req.Header.Set("Authorization", "Bearer synthetic-access-password")
				req.Header.Set("Content-Type", "application/json")
				response := httptest.NewRecorder()
				s.engine.ServeHTTP(response, req)
				return response
			}
			for _, path := range []string{"/v8/management/credentials", "/v0/management/auth-files"} {
				response := request(http.MethodGet, path, "")
				if response.Code != http.StatusOK {
					t.Fatalf("credential GET status=%d", response.Code)
				}
				for _, secret := range []string{"synthetic-access-token", "synthetic-refresh-token"} {
					if strings.Contains(response.Body.String(), secret) {
						t.Error("credential view leaked synthetic token")
					}
				}
				var payload struct {
					Files []struct {
						AuthIndex string `json:"auth_index"`
					} `json:"files"`
				}
				if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
					t.Fatal(err)
				}
				if len(payload.Files) != 2 {
					t.Fatalf("credential view has %d entries, want 2", len(payload.Files))
				}
				for _, file := range payload.Files {
					if file.AuthIndex == "" {
						t.Error("credential view lost auth index")
					}
				}
			}
			target, _ := manager.GetByID("target")
			response := request(http.MethodPost, "/v8/management/routing/cooldown/reset", `{"auth_index":"`+target.EnsureIndex()+`"}`)
			wantStatus := http.StatusOK
			if readOnly {
				wantStatus = http.StatusMethodNotAllowed
			}
			if response.Code != wantStatus {
				t.Fatalf("cooldown reset status=%d, want %d", response.Code, wantStatus)
			}
			target, _ = manager.GetByID("target")
			model := target.ModelStates["test-model"]
			if model == nil {
				t.Fatal("reset removed model state")
			}
			if target.Unavailable != readOnly || target.Quota.Exceeded != readOnly || target.NextRetryAfter.IsZero() == readOnly ||
				model.Unavailable != readOnly || model.Quota.Exceeded != readOnly || model.NextRetryAfter.IsZero() == readOnly {
				t.Error("cooldown reset did not respect write access")
			}
			sibling, _ := manager.GetByID("sibling")
			if !sibling.Unavailable || !sibling.Quota.Exceeded || !sibling.NextRetryAfter.Equal(deadline) {
				t.Error("target reset changed sibling cooldown")
			}
		})
	}
}
