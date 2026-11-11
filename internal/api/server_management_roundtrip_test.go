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
)

const roundTripConfig = `config-version: 8
port: 8317
proxy-url: http://rtuser:synthetic-rt-proxy-secret@proxy.example.invalid:8080
api-keys:
  - synthetic-rt-client-key-0001
  - synthetic-rt-client-key-0002
claude-api-key:
  - api-key: synthetic-rt-claude-key-0001
    base-url: https://one.example.invalid
  - api-key: synthetic-rt-claude-key-0002
    base-url: https://two.example.invalid
`

type roundTripEnv struct {
	t    *testing.T
	s    *Server
	cfg  *config.Config
	path string
}

func newRoundTripEnv(t *testing.T) *roundTripEnv {
	t.Helper()
	t.Setenv("MANAGEMENT_PASSWORD", "synthetic-rt-access")
	gin.SetMode(gin.TestMode)
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(roundTripConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.ParseConfigBytes([]byte(roundTripConfig))
	if err != nil {
		t.Fatal(err)
	}
	cfg.AuthDir = t.TempDir()
	cfg.Plugins.Dir = t.TempDir()
	h := management.NewHandler(cfg, path, nil)
	h.SetLocalPassword("synthetic-rt-access")
	s := &Server{cfg: cfg, engine: gin.New(), mgmt: h}
	s.managementRoutesEnabled.Store(true)
	s.registerManagementRoutes()
	return &roundTripEnv{t: t, s: s, cfg: cfg, path: path}
}

func (e *roundTripEnv) do(method, url, body string) *httptest.ResponseRecorder {
	e.t.Helper()
	req := httptest.NewRequest(method, url, strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Authorization", "Bearer synthetic-rt-access")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.s.engine.ServeHTTP(rec, req)
	return rec
}

func (e *roundTripEnv) persisted() string {
	e.t.Helper()
	data, err := os.ReadFile(e.path)
	if err != nil {
		e.t.Fatal(err)
	}
	return string(data)
}

func TestManagementRoundTripKeepsListSiblings(t *testing.T) {
	e := newRoundTripEnv(t)
	rec := e.do(http.MethodGet, "/v0/management/claude-api-key", "")
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "synthetic-rt-claude-key") {
		t.Fatalf("GET status=%d body=%s", rec.Code, rec.Body.String())
	}
	var got struct {
		Items []map[string]any `json:"claude-api-key"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || len(got.Items) != 2 {
		t.Fatalf("decode: %v %s", err, rec.Body.String())
	}
	if mask, _ := got.Items[0]["api-key"].(string); !strings.HasPrefix(mask, "***") || !strings.HasSuffix(mask, "0001") {
		t.Fatalf("mask hint=%q", mask)
	}
	// Panel edit: change the second entry's base-url, resend the whole list masked.
	got.Items[1]["base-url"] = "https://edited.example.invalid"
	body, _ := json.Marshal(got.Items)
	if rec = e.do(http.MethodPut, "/v0/management/claude-api-key", string(body)); rec.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s", rec.Code, rec.Body.String())
	}
	saved := e.persisted()
	for _, want := range []string{"synthetic-rt-claude-key-0001", "synthetic-rt-claude-key-0002", "edited.example.invalid"} {
		if !strings.Contains(saved, want) {
			t.Errorf("round trip lost %q", want)
		}
	}
	// An explicit new value replaces the stored one.
	got.Items[0]["api-key"] = "synthetic-rt-claude-key-NEW1"
	body, _ = json.Marshal(got.Items)
	if rec = e.do(http.MethodPut, "/v0/management/claude-api-key", string(body)); rec.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s", rec.Code, rec.Body.String())
	}
	saved = e.persisted()
	if strings.Contains(saved, "synthetic-rt-claude-key-0001") || !strings.Contains(saved, "synthetic-rt-claude-key-NEW1") || !strings.Contains(saved, "synthetic-rt-claude-key-0002") {
		t.Error("explicit replacement did not replace exactly one key")
	}
	// An explicit removal still removes the entry.
	rec = e.do(http.MethodPut, "/v0/management/claude-api-key", `[{"api-key":"`+"synthetic-rt-claude-key-NEW1"+`","base-url":"https://one.example.invalid"}]`)
	if rec.Code != http.StatusOK || strings.Contains(e.persisted(), "synthetic-rt-claude-key-0002") {
		t.Errorf("explicit removal failed: status=%d", rec.Code)
	}
}

func TestManagementRoundTripOmittedSecretIsRestored(t *testing.T) {
	e := newRoundTripEnv(t)
	body := `[{"base-url":"https://one.example.invalid"},{"base-url":"https://two.example.invalid"}]`
	if rec := e.do(http.MethodPut, "/v0/management/claude-api-key", body); rec.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s", rec.Code, rec.Body.String())
	}
	saved := e.persisted()
	if !strings.Contains(saved, "synthetic-rt-claude-key-0001") || !strings.Contains(saved, "synthetic-rt-claude-key-0002") {
		t.Error("omitted api-key fields were not restored")
	}
}

func TestManagementWritesNeverEmptyAccessKeysUnlessExplicit(t *testing.T) {
	// Each request is the shape a masked or lossy client sends. None may leave
	// the access api-keys empty, because an empty list opens the proxy to all.
	for name, request := range map[string]struct{ method, url, body string }{
		"masked list PUT":      {http.MethodPut, "/v0/management/api-keys", `["***0001","***0002"]`},
		"masked items PUT":     {http.MethodPut, "/v0/management/api-keys", `{"items":["***0001","***0002"]}`},
		"masked patch":         {http.MethodPatch, "/v0/management/api-keys", `{"index":0,"value":"***0001"}`},
		"yaml omit api-keys":   {http.MethodPut, "/v0/management/config.yaml", "config-version: 8\nport: 8317\n"},
		"yaml masked api-keys": {http.MethodPut, "/v0/management/config.yaml", "config-version: 8\nport: 8317\napi-keys: ['***0001', '***0002']\n"},
	} {
		t.Run(name, func(t *testing.T) {
			e := newRoundTripEnv(t)
			// Stored keys are 28 characters, so their masks end in the last 4.
			e.do(request.method, request.url, request.body)
			saved := e.persisted()
			if strings.Contains(saved, "'***") || strings.Contains(saved, "\"***") || strings.Contains(saved, "- '***") {
				t.Errorf("mask was persisted as a key")
			}
			if !strings.Contains(saved, "synthetic-rt-client-key-0001") || !strings.Contains(saved, "synthetic-rt-client-key-0002") {
				t.Errorf("access api-keys were lost:\n%s", saved)
			}
		})
	}
	t.Run("explicit empty list is honoured", func(t *testing.T) {
		e := newRoundTripEnv(t)
		e.do(http.MethodPut, "/v0/management/api-keys", `{"items":[]}`)
		// The legacy handler rejects an empty items envelope; a bare empty array
		// is the explicit request and must be honoured.
		if rec := e.do(http.MethodPut, "/v0/management/api-keys", `[]`); rec.Code != http.StatusOK {
			t.Fatalf("status=%d", rec.Code)
		}
		if strings.Contains(e.persisted(), "synthetic-rt-client-key-0001") {
			t.Error("explicit empty list did not clear the keys")
		}
	})
}

func TestManagementYAMLRoundTripKeepsEverySecret(t *testing.T) {
	e := newRoundTripEnv(t)
	for _, base := range []string{"/v0/management/config.yaml", "/v8/management/config.yaml"} {
		rec := e.do(http.MethodGet, base, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s status=%d", base, rec.Code)
		}
		redacted := rec.Body.String()
		if strings.Contains(redacted, "synthetic-rt-") {
			t.Fatalf("GET %s leaked a secret", base)
		}
		req := httptest.NewRequest(http.MethodPut, base, strings.NewReader(redacted))
		req.RemoteAddr = "127.0.0.1:1234"
		req.Header.Set("Authorization", "Bearer synthetic-rt-access")
		req.Header.Set("Content-Type", "application/yaml")
		if base == "/v8/management/config.yaml" {
			req.Header.Set("If-Match", rec.Header().Get("ETag"))
		}
		put := httptest.NewRecorder()
		e.s.engine.ServeHTTP(put, req)
		if put.Code != http.StatusOK {
			t.Fatalf("PUT %s status=%d body=%s", base, put.Code, put.Body.String())
		}
		saved := e.persisted()
		for _, want := range []string{"synthetic-rt-client-key-0001", "synthetic-rt-client-key-0002", "synthetic-rt-claude-key-0001", "synthetic-rt-claude-key-0002", "synthetic-rt-proxy-secret", "rtuser"} {
			if !strings.Contains(saved, want) {
				t.Errorf("YAML round trip via %s lost %q", base, want)
			}
		}
	}
}

func TestManagementMaskedProxyURLKeepsUserinfo(t *testing.T) {
	e := newRoundTripEnv(t)
	rec := e.do(http.MethodGet, "/v0/management/proxy-url", "")
	var got map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	masked := got["proxy-url"]
	if strings.Contains(masked, "synthetic-rt-proxy-secret") || strings.Contains(masked, "rtuser") || !strings.Contains(masked, "proxy.example.invalid:8080") {
		t.Fatalf("masked proxy-url=%q", masked)
	}
	// This is what the TUI does when the operator saves the field unchanged.
	body, _ := json.Marshal(map[string]string{"value": masked})
	if rec = e.do(http.MethodPut, "/v0/management/proxy-url", string(body)); rec.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s", rec.Code, rec.Body.String())
	}
	if saved := e.persisted(); !strings.Contains(saved, "rtuser:synthetic-rt-proxy-secret@proxy.example.invalid:8080") {
		t.Error("masked proxy-url PUT dropped the stored userinfo")
	}
	// A different host must not inherit the old credentials.
	bad, _ := json.Marshal(map[string]string{"value": strings.Replace(masked, "proxy.example.invalid", "other.example.invalid", 1)})
	e.do(http.MethodPut, "/v0/management/proxy-url", string(bad))
	if strings.Contains(e.persisted(), "other.example.invalid") && !strings.Contains(e.persisted(), "synthetic-rt-proxy-secret") {
		t.Error("host change lost credentials without carrying them")
	}
}
