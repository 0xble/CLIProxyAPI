package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MoeForge/moego/ojson"
	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/api/handlers/management"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"golang.org/x/crypto/bcrypt"
)

func TestManagementV8ClearCodexCreditPark(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	const route = "/v8/management/credentials/credit-park/clear"
	const password = "synthetic-management-password"
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{AuthDir: t.TempDir()}
	cfg.RemoteManagement.SecretKey = string(hash)
	manager := coreauth.NewManager(nil, nil, nil)
	store := coreauth.NewFileCooldownStateStore(t.TempDir())
	manager.SetCooldownStateStore(store)
	key := func(id string) *coreauth.Auth {
		return &coreauth.Auth{ID: id, Provider: "codex", Status: coreauth.StatusActive, Attributes: map[string]string{
			coreauth.AttributeAPIKey: "dummy-" + id, coreauth.AttributeCodexCreditResetDay: "31",
		}}
	}
	target, sibling, noOptIn, oauth, other, disabled := key("target"), key("sibling"), key("no-opt-in"), key("oauth"), key("other"), key("disabled")
	delete(noOptIn.Attributes, coreauth.AttributeCodexCreditResetDay)
	delete(oauth.Attributes, coreauth.AttributeAPIKey)
	oauth.Metadata = map[string]any{"access_token": "dummy-oauth-token"}
	other.Provider = "xai"
	disabled.Disabled = true
	register := func(m *coreauth.Manager, a *coreauth.Auth) {
		t.Helper()
		if _, err := m.Register(t.Context(), a.Clone()); err != nil {
			t.Fatal(err)
		}
	}
	for _, a := range []*coreauth.Auth{target, sibling, noOptIn, oauth, other, disabled} {
		register(manager, a)
	}
	manager.MarkResult(t.Context(), coreauth.Result{AuthID: target.ID, Provider: "codex", Model: "held", Error: &coreauth.Error{
		Code: coreauth.ErrorCodeForceCooldown, HTTPStatus: http.StatusUnauthorized,
	}})
	for _, a := range []*coreauth.Auth{target, sibling} {
		manager.MarkResult(t.Context(), coreauth.Result{AuthID: a.ID, Provider: "codex", Model: "exhausted", Error: &coreauth.Error{
			Code: coreauth.CodexCreditParkReason, HTTPStatus: http.StatusTooManyRequests,
		}})
	}
	before, _ := manager.GetByID(target.ID)
	held := before.ModelStates["held"]
	if held == nil || !held.NextRetryAfter.After(time.Now()) || before.CodexCreditParkedUntil(time.Now()).IsZero() {
		t.Fatal("fixture did not create both the hard hold and the credit park")
	}
	body := func(a *coreauth.Auth) string {
		return `{"auth_index":"` + a.EnsureIndex() + `"}`
	}
	newRouter := func(cfg *config.Config) http.Handler {
		h := management.NewHandlerWithoutConfigFilePath(cfg, manager)
		s := &Server{cfg: cfg, engine: gin.New(), mgmt: h}
		s.managementRoutesEnabled.Store(true)
		s.registerManagementRoutes()
		return s.engine
	}
	request := func(router http.Handler, path, payload, addr, auth string, want int) []byte {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(payload))
		req.RemoteAddr = addr
		if auth != "" {
			req.Header.Set("Authorization", "Bearer "+auth)
		}
		response := httptest.NewRecorder()
		router.ServeHTTP(response, req)
		if response.Code != want {
			t.Fatalf("%s: status=%d, want %d, body=%s", path, response.Code, want, response.Body.String())
		}
		return response.Body.Bytes()
	}
	const local = "127.0.0.1:1234"
	router := newRouter(cfg)
	request(router, route, body(target), local, "", http.StatusUnauthorized)
	request(router, route, body(target), "192.0.2.1:1234", password, http.StatusForbidden)
	readOnly := cfg.CloneForRuntime()
	readOnly.RemoteManagement.ReadOnly = true
	request(newRouter(readOnly), route, body(target), local, password, http.StatusMethodNotAllowed)
	home := cfg.CloneForRuntime()
	home.Home.Enabled = true
	request(newRouter(home), route, body(target), local, password, http.StatusNotFound)
	request(router, "/v0/management/auth-files/credit-park/clear", body(target), local, password, http.StatusNotFound)
	for _, payload := range []string{`{`, `{}`, `{"auth_index":42}`} {
		request(router, route, payload, local, password, http.StatusBadRequest)
	}
	request(router, route, `{"auth_index":"unknown"}`, local, password, http.StatusNotFound)
	duplicate := key("same-key-different-proxy")
	duplicate.Attributes[coreauth.AttributeAPIKey] = target.Attributes[coreauth.AttributeAPIKey]
	duplicate.ProxyURL = "http://127.0.0.1:1"
	register(manager, duplicate)
	request(router, route, body(target), local, password, http.StatusConflict)
	manager.Remove(t.Context(), duplicate.ID)
	for _, a := range []*coreauth.Auth{noOptIn, oauth, other, disabled} {
		request(router, route, body(a), local, password, http.StatusConflict)
	}
	latest, _ := manager.GetByID(target.ID)
	if !latest.CodexCreditParkedUntil(time.Now()).Equal(before.CodexCreditParkedUntil(time.Now())) {
		t.Fatal("a rejected request changed the target park")
	}
	for _, wantCleared := range []bool{true, false} {
		response := request(router, route, body(target), local, password, http.StatusOK)
		cleared := ojson.GetBytesNoCopy(response, "cleared")
		if !cleared.Exists() || cleared.Bool() != wantCleared || ojson.GetBytesNoCopy(response, "auth_index").String() != target.Index {
			t.Fatalf("unexpected clear response: %s", response)
		}
		if strings.Contains(string(response), "dummy-") || strings.Contains(string(response), "auth_id") {
			t.Fatal("clear response exposed credential internals")
		}
	}
	checkState := func(m *coreauth.Manager) {
		t.Helper()
		a, _ := m.GetByID(target.ID)
		b, _ := m.GetByID(sibling.ID)
		if !a.CodexCreditParkedUntil(time.Now()).IsZero() || b.CodexCreditParkedUntil(time.Now()).IsZero() {
			t.Fatal("clear did not remove only the target's park")
		}
		if state := a.ModelStates["held"]; state == nil || !state.NextRetryAfter.Equal(held.NextRetryAfter) || state.LastError == nil || state.LastError.Code != coreauth.ErrorCodeForceCooldown {
			t.Fatal("clear changed the target's unrelated hard hold")
		}
	}
	checkState(manager)
	restarted := coreauth.NewManager(nil, nil, nil)
	restarted.SetCooldownStateStore(store)
	register(restarted, target)
	register(restarted, sibling)
	if err := restarted.RestoreCooldownStates(t.Context()); err != nil {
		t.Fatal(err)
	}
	checkState(restarted)
}
