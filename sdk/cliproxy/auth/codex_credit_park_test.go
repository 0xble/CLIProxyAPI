package auth

import (
	"context"
	"math"
	"net/http"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestNextCreditReset_CreditExhausted(t *testing.T) {
	for _, tc := range []struct {
		now, want string
		day       int
	}{
		{"2026-02-01T01:00:00+02:00", "2026-02-01T00:00:00Z", 1},
		{"2026-02-01T00:00:00Z", "2026-03-01T00:00:00Z", 1},
		{"2026-01-31T00:00:00Z", "2026-02-28T00:00:00Z", 31},
		{"2028-02-01T00:00:00Z", "2028-02-29T00:00:00Z", 31},
		{"2026-12-31T09:00:00Z", "2027-01-31T00:00:00Z", 31},
	} {
		now, err := time.Parse(time.RFC3339, tc.now)
		if err != nil {
			t.Fatal(err)
		}
		if got := nextCreditReset(now, tc.day).Format(time.RFC3339); got != tc.want {
			t.Errorf("nextCreditReset(%s, %d) = %s, want %s", tc.now, tc.day, got, tc.want)
		}
	}
}

func newCreditParkAuth(id, priority string) *Auth {
	return &Auth{ID: id, Provider: "codex", Status: StatusActive, Attributes: map[string]string{
		AttributeAPIKey: "dummy-" + id, "priority": priority, AttributeCodexCreditResetDay: "31",
	}}
}

const creditParkTestBody = `{"error":{"type":"insufficient_quota","code":"credit_balance_exhausted","message":"Upstream billing details"}}`

func TestCodexCreditPark_CreditExhaustedRoutingAndRestart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	key := newCreditParkAuth(t.Name()+"-key", "20")
	fallback := &Auth{ID: t.Name() + "-fallback", Provider: "codex", Status: StatusActive}
	models := []*registry.ModelInfo{{ID: "park-model-a"}, {ID: "park-model-b"}}
	for _, a := range []*Auth{key, fallback} {
		registry.GetGlobalRegistry().RegisterClient(a.ID, "codex", models)
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(a.ID) })
	}
	newManager := func() (*Manager, *[]string) {
		m := NewManager(nil, nil, nil)
		m.SetRetryConfig(0, 0, 0)
		m.SetCooldownStateStore(NewFileCooldownStateStore(dir))
		for _, a := range []*Auth{key, fallback} {
			if _, err := m.Register(ctx, a.Clone()); err != nil {
				t.Fatal(err)
			}
		}
		var attempts []string
		m.RegisterExecutor(&customStreamMockExecutor{identifier: "codex", streamFn: func(_ context.Context, a *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
			attempts = append(attempts, a.ID)
			if a.ID == key.ID {
				return nil, customStatusError{code: http.StatusTooManyRequests, msg: creditParkTestBody}
			}
			return successStreamResult(), nil
		}})
		return m, &attempts
	}
	execute := func(m *Manager, model string) {
		t.Helper()
		result, err := m.ExecuteStream(ctx, []string{"codex"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{})
		if err != nil || result == nil {
			t.Fatalf("execute %s: %v", model, err)
		}
		for chunk := range result.Chunks {
			if chunk.Err != nil {
				t.Fatal(chunk.Err)
			}
		}
	}
	m, order := newManager()
	execute(m, models[0].ID)
	execute(m, models[1].ID)
	if len(*order) != 3 || (*order)[0] != key.ID || (*order)[1] != fallback.ID || (*order)[2] != fallback.ID {
		t.Fatalf("attempts = %v; expected key then fallback, then only fallback for another model", *order)
	}
	parked, _ := m.GetByID(key.ID)
	until := parked.CodexCreditParkedUntil(time.Now())
	if until.IsZero() || len(parked.ModelStates) != 0 || parked.Quota.Exceeded {
		t.Fatalf("expected a separate park, got %+v", parked)
	}
	views := CooldownSnapshotForAuth(parked, time.Now())
	if len(views) != 1 || views[0].Scope != "credential" || views[0].Reason != CodexCreditParkReason || !views[0].RetryAt.Equal(until) {
		t.Fatalf("park view = %+v", views)
	}
	if blocked, _, _ := isAuthBlockedForModel(parked, models[1].ID, until); blocked {
		t.Fatal("key did not become selectable at the reset boundary")
	}
	m.MarkResult(ctx, Result{AuthID: key.ID, Provider: "codex", Model: models[0].ID, Success: true})
	if latest, _ := m.GetByID(key.ID); !latest.CodexCreditParkedUntil(time.Now()).Equal(until) {
		t.Fatal("late success erased the park")
	}
	if _, err := m.Update(ctx, key.Clone()); err != nil {
		t.Fatal(err)
	}
	if latest, _ := m.GetByID(key.ID); !latest.CodexCreditParkedUntil(time.Now()).Equal(until) {
		t.Fatal("reloading an unchanged key erased the park")
	}
	m, order = newManager()
	if err := m.RestoreCooldownStates(ctx); err != nil {
		t.Fatal(err)
	}
	execute(m, models[1].ID)
	if len(*order) != 1 || (*order)[0] != fallback.ID {
		t.Fatalf("after restart attempts = %v, expected fallback only", *order)
	}
	reloaded, _ := m.GetByID(key.ID)
	if !reloaded.CodexCreditParkedUntil(time.Now()).Equal(until) {
		t.Fatal("restart changed the park deadline")
	}
	if m.ApplyVerifiedCodexCreditBalance(reloaded, 2, parked.creditPark.ObservedAt) ||
		m.ApplyVerifiedCodexCreditBalance(reloaded, math.NaN(), time.Now()) ||
		m.ApplyVerifiedCodexCreditBalance(reloaded, 0, time.Now()) {
		t.Fatal("accepted stale or nonpositive balance")
	}
	wrongCredential := reloaded.Clone()
	wrongCredential.CredentialVersion++
	if m.ApplyVerifiedCodexCreditBalance(wrongCredential, 2, time.Now()) {
		t.Fatal("accepted verified balance for the wrong credential version")
	}
	if !m.ApplyVerifiedCodexCreditBalance(reloaded, 2, time.Now()) {
		t.Fatal("did not accept the later positive balance")
	}
	m, _ = newManager()
	if err := m.RestoreCooldownStates(ctx); err != nil {
		t.Fatal(err)
	}
	if latest, _ := m.GetByID(key.ID); !latest.CodexCreditParkedUntil(time.Now()).IsZero() {
		t.Fatal("cleared park reappeared on restart")
	}
}

func TestCodexCreditPark_CreditExhaustedRequiresExplicitBillingAndOptIn(t *testing.T) {
	for _, tc := range []struct {
		name, provider, day, body string
		oauth, want               bool
	}{
		{"billing", "codex", "1", creditParkTestBody, false, true},
		{"type only", "codex", "1", `{"error":{"type":"insufficient_quota"}}`, false, true},
		{"ordinary 429", "codex", "1", `{"error":{"code":"rate_limit_exceeded"}}`, false, false},
		{"matching prose", "codex", "1", `{"error":{"message":"insufficient_quota credit_balance_exhausted"}}`, false, false},
		{"OAuth", "codex", "1", creditParkTestBody, true, false},
		{"other provider", "xai", "1", creditParkTestBody, false, false},
		{"no reset day", "codex", "", creditParkTestBody, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := newCreditParkAuth(tc.name, "10")
			a.Provider = tc.provider
			a.Attributes[AttributeCodexCreditResetDay] = tc.day
			if tc.oauth {
				delete(a.Attributes, AttributeAPIKey)
				a.Metadata = map[string]any{"access_token": "dummy-oauth", "refresh_token": "dummy-refresh"}
			}
			m := NewManager(nil, nil, nil)
			ctx := context.Background()
			if _, err := m.Register(ctx, a); err != nil {
				t.Fatal(err)
			}
			m.MarkResult(ctx, Result{AuthID: a.ID, Provider: a.Provider, Model: "a", Error: &Error{HTTPStatus: 429, Message: tc.body}})
			current, _ := m.GetByID(a.ID)
			if got := !current.CodexCreditParkedUntil(time.Now()).IsZero(); got != tc.want {
				t.Fatalf("parked = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCodexCreditPark_CreditExhaustedReloadFences(t *testing.T) {
	ctx := t.Context()
	for _, tc := range []struct {
		name string
		edit func(*Auth)
	}{
		{"reset changed", func(a *Auth) { a.Attributes[AttributeCodexCreditResetDay] = "2" }},
		{"opt out", func(a *Auth) { delete(a.Attributes, AttributeCodexCreditResetDay) }},
		{"key replaced", func(a *Auth) { a.Attributes[AttributeAPIKey] = "replacement-key" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewManager(nil, nil, nil)
			key := newCreditParkAuth(t.Name(), "10")
			if _, err := m.Register(ctx, key.Clone()); err != nil {
				t.Fatal(err)
			}
			m.MarkResult(ctx, Result{AuthID: key.ID, Provider: "codex", Model: "a", Error: &Error{HTTPStatus: 429, Message: creditParkTestBody}})
			records := m.cooldownStateRecordsSnapshot()
			if len(records) != 1 {
				t.Fatalf("expected one park record, got %d", len(records))
			}
			tc.edit(key)
			if _, err := m.Update(ctx, key.Clone()); err != nil {
				t.Fatal(err)
			}
			if latest, _ := m.GetByID(key.ID); !latest.CodexCreditParkedUntil(time.Now()).IsZero() {
				t.Fatal("changing reset policy or replacing credential kept the park")
			}
			dir := t.TempDir()
			store := NewFileCooldownStateStore(dir)
			if err := store.Save(ctx, records); err != nil {
				t.Fatal(err)
			}
			restarted := NewManager(nil, nil, nil)
			restarted.SetCooldownStateStore(store)
			if _, err := restarted.Register(ctx, key.Clone()); err != nil {
				t.Fatal(err)
			}
			if err := restarted.RestoreCooldownStates(ctx); err != nil {
				t.Fatal(err)
			}
			if latest, _ := restarted.GetByID(key.ID); !latest.CodexCreditParkedUntil(time.Now()).IsZero() {
				t.Fatal("restarted with an incompatible park")
			}
		})
	}
}
