package management

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/watcher/synthesizer"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestV8CredentialsShowsCodexCreditPark(t *testing.T) {
	manager := coreauth.NewManager(nil, nil, nil)
	const secret = "dummy-codex-credit-park-secret"
	cfg := &config.Config{CodexKey: []config.CodexKey{{APIKey: secret, BaseURL: "https://api.openai.com/v1", Priority: 30, CreditResetDay: 31}}}
	auths, err := synthesizer.NewConfigSynthesizer().Synthesize(&synthesizer.SynthesisContext{Config: cfg, Now: time.Now(), IDGenerator: synthesizer.NewStableIDGenerator()})
	if err != nil || len(auths) != 1 {
		t.Fatalf("synthesize opted-in key: %d auths, %v", len(auths), err)
	}
	a, err := manager.Register(t.Context(), auths[0])
	if err != nil {
		t.Fatal(err)
	}
	const upstreamDetail = "private-upstream-billing-detail"
	manager.MarkResult(t.Context(), coreauth.Result{AuthID: a.ID, Provider: "codex", Model: "model-a", Error: &coreauth.Error{
		HTTPStatus: 429, Message: `{"error":{"code":"credit_balance_exhausted","message":"` + upstreamDetail + `"}}`,
	}})
	router := newV8AndV0AuthRouter(NewHandlerWithoutConfigFilePath(cfg, manager))
	for _, suffix := range []string{"", "?page_size=1"} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v8/management/credentials"+suffix, nil))
		body := rec.Body.Bytes()
		if rec.Code != 200 || ojson.GetBytesNoCopy(body, "files.0.credit_reset_day").Int() != 31 ||
			ojson.GetBytesNoCopy(body, "files.0.credit_park_reason").String() != coreauth.CodexCreditParkReason ||
			ojson.GetBytesNoCopy(body, "files.0.cooldowns.0.scope").String() != "credential" ||
			ojson.GetBytesNoCopy(body, "files.0.priority").Int() != 30 ||
			!ojson.GetBytesNoCopy(body, "files.0.unavailable").Bool() {
			t.Fatalf("unexpected v8 credentials reply: HTTP %d, %s", rec.Code, body)
		}
		until, err := time.Parse(time.RFC3339Nano, ojson.GetBytesNoCopy(body, "files.0.credit_parked_until").String())
		if err != nil || !until.After(time.Now()) || until.Hour() != 0 {
			t.Fatalf("unexpected UTC deadline: %s (%v)", until, err)
		}
		if strings.Contains(string(body), secret) || strings.Contains(string(body), upstreamDetail) {
			t.Fatal("v8 credentials reply exposed key or upstream billing details")
		}
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v0/management/auth-files", nil))
	if rec.Code != 200 || strings.Contains(rec.Body.String(), a.ID) {
		t.Fatal("legacy list unexpectedly changed its visibility of config keys")
	}
}
