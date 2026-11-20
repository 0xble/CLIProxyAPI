package auth

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
)

func TestCodexOverloadCooldownScope(t *testing.T) {
	oldDisabled := quotaCooldownDisabled.Swap(false)
	oldTransient := transientErrorCooldownSeconds.Swap(60)
	t.Cleanup(func() {
		quotaCooldownDisabled.Store(oldDisabled)
		transientErrorCooldownSeconds.Store(oldTransient)
	})
	long, short := 303*time.Second, 12*time.Second
	const overload = `{"error":{"code":"server_is_overloaded"}}`
	for _, tc := range []struct {
		name, provider, model, code, body string
		status                            int
		hint                              *time.Duration
		disabled                          bool
		force, want                       time.Duration
	}{
		{name: "codex 502", provider: "codex", model: "test-model", body: overload, status: http.StatusBadGateway, hint: &long, want: 30 * time.Second},
		{name: "codex 503", provider: "codex", model: "test-model", body: overload, status: http.StatusServiceUnavailable, hint: &long, want: 30 * time.Second},
		{name: "short hint", provider: "codex", model: "test-model", body: overload, status: http.StatusBadGateway, hint: &short, want: short},
		{name: "no hint", provider: "codex", model: "test-model", body: overload, status: http.StatusBadGateway, want: 30 * time.Second},
		{name: "auth-wide", provider: "codex", code: "server_is_overloaded", status: http.StatusBadGateway, hint: &long, want: 30 * time.Second},
		{name: "other provider", provider: "claude", model: "test-model", body: overload, status: http.StatusBadGateway, hint: &long, want: long},
		{name: "generic 502", provider: "codex", model: "test-model", body: `{"error":{"code":"bad_gateway","message":"server_is_overloaded"}}`, status: http.StatusBadGateway, hint: &long, want: long},
		{name: "429 unchanged", provider: "codex", model: "test-model", body: overload, status: http.StatusTooManyRequests, hint: &long, want: long},
		{name: "cooling disabled", provider: "codex", model: "test-model", body: overload, status: http.StatusBadGateway, hint: &long, disabled: true},
		{name: "forced cooldown", provider: "codex", model: "test-model", code: ErrorCodeForceCooldown, body: overload, status: http.StatusBadGateway, hint: &long, force: time.Hour, want: time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			SetQuotaCooldownDisabled(tc.disabled)
			m := NewManager(nil, nil, nil)
			ctx := context.Background()
			if _, err := m.Register(ctx, &Auth{ID: "routing-risk-overload", Provider: tc.provider, Status: StatusActive}); err != nil {
				t.Fatal(err)
			}
			before := time.Now()
			m.MarkResult(ctx, Result{AuthID: "routing-risk-overload", Provider: tc.provider, Model: tc.model, Error: &Error{HTTPStatus: tc.status, Code: tc.code, Message: tc.body}, RetryAfter: tc.hint, Cooldown: tc.force})
			after := time.Now()
			updated, _ := m.GetByID("routing-risk-overload")
			deadline := updated.NextRetryAfter
			if tc.model != "" {
				state := updated.ModelStates[tc.model]
				if state == nil {
					t.Fatal("no model state")
				}
				deadline = state.NextRetryAfter
			}
			if tc.want == 0 {
				if !deadline.IsZero() {
					t.Fatalf("deadline = %v; cooling is disabled", deadline)
				}
			} else if deadline.Before(before.Add(tc.want)) || deadline.After(after.Add(tc.want)) {
				t.Fatalf("cooldown = %v, want %v", deadline.Sub(before), tc.want)
			}
		})
	}
}

func TestLegacyCodexModelWarnsOnlyForAPIKeyRoutes(t *testing.T) {
	const legacy, replacement = "gpt-6-astra", "gpt-6.2-astra"
	for _, tc := range []struct {
		name, model, oauthModel                                           string
		stream, disabledOAuth, coolingOAuth, wantWarning, wantReplacement bool
	}{
		{name: "paid only", model: legacy, wantWarning: true},
		{name: "stream with suffix", model: legacy + "(high)", oauthModel: replacement, stream: true, wantWarning: true, wantReplacement: true},
		{name: "mixed route", model: legacy, oauthModel: legacy},
		{name: "temporarily cooling OAuth is still a configured route", model: legacy, oauthModel: legacy, coolingOAuth: true},
		{name: "disabled OAuth is not a configured route", model: legacy, oauthModel: legacy, disabledOAuth: true, wantWarning: true},
		{name: "legitimate API-key-only model", model: "api-only-custom-model"},
		{name: "current model is not legacy", model: replacement},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			m := NewManager(nil, nil, nil)
			m.RegisterExecutor(&customStreamMockExecutor{identifier: "codex", streamFn: func(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
				return successStreamResult(), nil
			}})
			reg := registry.GetGlobalRegistry()
			register := func(a *Auth, model string) {
				reg.RegisterClient(a.ID, a.Provider, []*registry.ModelInfo{{ID: model}})
				t.Cleanup(func() { reg.UnregisterClient(a.ID) })
				if _, err := m.Register(ctx, a); err != nil {
					t.Fatal(err)
				}
			}
			paidModel := tc.model
			if tc.stream {
				paidModel = legacy
			}
			register(&Auth{ID: "routing-risk-api-key", Provider: "codex", Status: StatusActive, Attributes: map[string]string{AttributeAuthKind: AuthKindAPIKey, "priority": "10"}}, paidModel)
			if tc.oauthModel != "" {
				a := &Auth{ID: "routing-risk-oauth", Provider: "codex", Status: StatusActive, Disabled: tc.disabledOAuth, Attributes: map[string]string{AttributeAuthKind: AuthKindOAuth}}
				if tc.coolingOAuth {
					a.ModelStates = map[string]*ModelState{tc.oauthModel: {Unavailable: true, Status: StatusError, NextRetryAfter: time.Now().Add(time.Hour)}}
				}
				register(a, tc.oauthModel)
			}
			logger := log.StandardLogger()
			prevHooks := logger.ReplaceHooks(make(log.LevelHooks))
			t.Cleanup(func() { logger.ReplaceHooks(prevHooks) })
			hook := logtest.NewLocal(logger)
			request := cliproxyexecutor.Request{Model: tc.model}
			for range 2 {
				if tc.stream {
					result, err := m.ExecuteStream(ctx, []string{"codex"}, request, cliproxyexecutor.Options{})
					if err != nil {
						t.Fatal(err)
					}
					for chunk := range result.Chunks {
						if chunk.Err != nil {
							t.Fatal(chunk.Err)
						}
					}
				} else {
					if _, err := m.Execute(ctx, []string{"codex"}, request, cliproxyexecutor.Options{}); err != nil {
						t.Fatal(err)
					}
				}
			}
			warnings := 0
			for _, entry := range hook.AllEntries() {
				if entry.Level != log.WarnLevel || entry.Data["model"] != legacy {
					continue
				}
				warnings++
				if got := entry.Data["replacement_model"]; tc.wantReplacement && got != replacement || !tc.wantReplacement && got != nil {
					t.Errorf("replacement_model = %v, want advertised replacement: %v", got, tc.wantReplacement)
				}
			}
			if tc.wantWarning && warnings != 1 || !tc.wantWarning && warnings != 0 {
				t.Fatalf("warnings = %d, want one: %v", warnings, tc.wantWarning)
			}
		})
	}
}
