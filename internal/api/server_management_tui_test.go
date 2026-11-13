package api

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/api/handlers/management"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/tui"
)

// The TUI rewrites access.api-keys as a whole list, while this server redacts
// reads. These tests drive the real TUI client against the real redacting
// management handler so mask restoration is exercised end to end.
func newTUIManagementServer(t *testing.T, keys ...string) (*tui.Client, string) {
	t.Helper()
	t.Setenv("MANAGEMENT_PASSWORD", "synthetic-tui-access")
	gin.SetMode(gin.TestMode)
	var b strings.Builder
	b.WriteString("config-version: 8\nport: 8317\napi-keys:\n")
	for _, key := range keys {
		b.WriteString("  - " + key + "\n")
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.ParseConfigBytes([]byte(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	cfg.AuthDir = t.TempDir()
	cfg.Plugins.Dir = t.TempDir()
	h := management.NewHandler(cfg, path, nil)
	h.SetLocalPassword("synthetic-tui-access")
	s := &Server{cfg: cfg, engine: gin.New(), mgmt: h}
	s.managementRoutesEnabled.Store(true)
	s.registerManagementRoutes()
	srv := httptest.NewServer(s.engine)
	t.Cleanup(srv.Close)
	return tui.NewClientWithBaseURL(srv.URL, "synthetic-tui-access"), path
}

func persistedConfig(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestTUIAPIKeyMutationsRefuseCollidingMasks(t *testing.T) {
	const first, second = "synthetic-tui-alpha-key-1234", "synthetic-tui-bravo-key-1234"
	for name, mutate := range map[string]func(*tui.Client) error{
		"delete first":  func(c *tui.Client) error { return c.DeleteAPIKey(0, "***1234") },
		"delete second": func(c *tui.Client) error { return c.DeleteAPIKey(1, "***1234") },
		"edit first":    func(c *tui.Client) error { return c.EditAPIKey(0, "synthetic-tui-new-key-9999", "***1234") },
	} {
		t.Run(name, func(t *testing.T) {
			client, path := newTUIManagementServer(t, first, second)
			before := persistedConfig(t, path)
			if err := mutate(client); err == nil || !strings.Contains(err.Error(), "indistinguishable") {
				t.Fatalf("mutation error = %v, want ambiguous-mask refusal", err)
			}
			if after := persistedConfig(t, path); after != before {
				t.Fatalf("config changed despite refusal:\n%s", after)
			}
		})
	}
}

func TestTUIAPIKeyMutationsKeepTheRightKeyWhenMasksDiffer(t *testing.T) {
	const first, second = "synthetic-tui-alpha-key-0001", "synthetic-tui-bravo-key-0002"

	client, path := newTUIManagementServer(t, first, second)
	if err := client.DeleteAPIKey(0, "***0001"); err != nil {
		t.Fatalf("DeleteAPIKey: %v", err)
	}
	if got := persistedConfig(t, path); strings.Contains(got, first) || !strings.Contains(got, second) {
		t.Fatalf("delete removed the wrong key:\n%s", got)
	}

	client, path = newTUIManagementServer(t, first, second)
	if err := client.EditAPIKey(1, "synthetic-tui-charlie-key-0003", "***0002"); err != nil {
		t.Fatalf("EditAPIKey: %v", err)
	}
	if got := persistedConfig(t, path); !strings.Contains(got, first) || strings.Contains(got, second) || !strings.Contains(got, "synthetic-tui-charlie-key-0003") {
		t.Fatalf("edit changed the wrong key:\n%s", got)
	}
}
