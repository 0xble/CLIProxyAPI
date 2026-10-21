package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func quotaTestPolicy() QuotaGuardPolicy {
	return QuotaGuardPolicy{Provider: "claude", AuthFile: "lpg.json", Window: QuotaGuardWindow7Day, MaxUsedPercent: 50, AllowWithinReset: 2 * time.Hour}
}

func TestEvaluateQuotaPolicyAllRules(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	policy := quotaTestPolicy()
	cases := []struct {
		name    string
		reading *QuotaReading
		want    QuotaDecision
	}{
		{"below threshold", &QuotaReading{UsedPercent: 49.99, ResetAt: now.Add(24 * time.Hour), ObservedAt: now}, QuotaDecisionEligible},
		{"threshold outside window", &QuotaReading{UsedPercent: 50, ResetAt: now.Add(2*time.Hour + time.Minute), ObservedAt: now}, QuotaDecisionExcluded},
		{"threshold inside window", &QuotaReading{UsedPercent: 50, ResetAt: now.Add(2 * time.Hour), ObservedAt: now}, QuotaDecisionEligible},
		{"over threshold inside window", &QuotaReading{UsedPercent: 99, ResetAt: now.Add(time.Hour), ObservedAt: now}, QuotaDecisionEligible},
		{"reset recovery", &QuotaReading{UsedPercent: 49.5, ResetAt: now.Add(24 * time.Hour), ObservedAt: now}, QuotaDecisionEligible},
		{"missing", nil, QuotaDecisionUnknown},
		{"invalid percent", &QuotaReading{UsedPercent: 101, ResetAt: now.Add(time.Hour), ObservedAt: now}, QuotaDecisionUnknown},
		{"invalid reset", &QuotaReading{UsedPercent: 10, ObservedAt: now}, QuotaDecisionUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := EvaluateQuotaPolicy(policy, tc.reading, now)
			if got != tc.want {
				t.Fatalf("decision = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestQuotaGuardPollAndSelection(t *testing.T) {
	now := time.Now().UTC()
	reading := QuotaReading{UsedPercent: 68, ResetAt: now.Add(24 * time.Hour)}
	guard := NewQuotaGuardForTest(QuotaGuardConfig{Mode: QuotaGuardModeActive, MaxAge: 15 * time.Minute, Policies: []QuotaGuardPolicy{quotaTestPolicy()}}, func(context.Context, *Auth) (QuotaReading, error) { return reading, nil })
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.SetQuotaGuard(guard)
	if _, err := manager.Register(context.Background(), &Auth{ID: "lpg-auth", FileName: "lpg.json", Provider: "claude", Status: StatusActive}); err != nil {
		t.Fatal(err)
	}
	if err := guard.PollOnce(context.Background(), manager); err != nil {
		t.Fatal(err)
	}
	selected, err := (&RoundRobinSelector{}).Pick(context.Background(), "claude", "claude-sonnet", cliproxyexecutor.Options{}, manager.List())
	if err == nil || selected != nil {
		t.Fatalf("selected excluded auth: selected=%v err=%v", selected, err)
	}
	if !manager.List()[0].quotaGuard.IsBlocked(manager.List()[0], now) {
		t.Fatal("expected active guard block")
	}
}

func TestQuotaGuardShadowUnconfiguredStaleAndCachedError(t *testing.T) {
	now := time.Now().UTC()
	policy := quotaTestPolicy()
	shadow := NewQuotaGuardForTest(QuotaGuardConfig{Mode: QuotaGuardModeShadow, MaxAge: time.Minute, Policies: []QuotaGuardPolicy{policy}}, func(context.Context, *Auth) (QuotaReading, error) {
		return QuotaReading{UsedPercent: 90, ResetAt: now.Add(time.Hour)}, nil
	})
	auth := &Auth{ID: "lpg", FileName: "lpg.json", Provider: "claude"}
	shadow.Attach(auth)
	if err := shadow.PollOnce(context.Background(), mustManager(auth)); err != nil {
		t.Fatal(err)
	}
	if shadow.IsBlocked(auth, now) {
		t.Fatal("shadow mode blocked routing")
	}
	other := &Auth{ID: "other", FileName: "other.json", Provider: "claude", quotaGuard: shadow}
	if shadow.IsBlocked(other, now) {
		t.Fatal("unconfigured auth changed")
	}
	active := NewQuotaGuardForTest(QuotaGuardConfig{Mode: QuotaGuardModeActive, MaxAge: time.Minute, Policies: []QuotaGuardPolicy{policy}}, func(context.Context, *Auth) (QuotaReading, error) {
		return QuotaReading{}, errors.New("provider unavailable")
	})
	active.Attach(auth)
	active.states[auth.ID] = QuotaGuardState{AuthID: auth.ID, Decision: QuotaDecisionEligible, ObservedAt: now}
	if err := active.PollOnce(context.Background(), mustManager(auth)); err != nil {
		t.Fatal(err)
	}
	if active.IsBlocked(auth, now) {
		t.Fatal("fresh cached eligible decision was not retained")
	}
	active.states[auth.ID] = QuotaGuardState{AuthID: auth.ID, Decision: QuotaDecisionEligible, ObservedAt: now.Add(-2 * time.Minute)}
	if !active.IsBlocked(auth, now) {
		t.Fatal("stale quota did not fail closed")
	}
}

func mustManager(auth *Auth) *Manager {
	m := NewManager(nil, &RoundRobinSelector{}, nil)
	_, _ = m.Register(context.Background(), auth)
	return m
}

type quotaTestHTTPClient struct {
	request *http.Request
	body    string
}

func (c *quotaTestHTTPClient) Do(req *http.Request) (*http.Response, error) {
	c.request = req
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(c.body)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

func TestQuotaGuardManagerSnapshotsSurviveUpdateAndClone(t *testing.T) {
	guard := NewQuotaGuardForTest(QuotaGuardConfig{Mode: QuotaGuardModeActive, Policies: []QuotaGuardPolicy{quotaTestPolicy()}}, nil)
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.SetQuotaGuard(guard)
	auth := &Auth{ID: "lpg", FileName: "lpg.json", Provider: "claude", Status: StatusActive}
	registered, errRegister := manager.Register(context.Background(), auth)
	if errRegister != nil {
		t.Fatal(errRegister)
	}
	if registered.quotaGuard != guard {
		t.Fatal("register result lost manager-owned quota guard")
	}
	listed := manager.List()
	if len(listed) != 1 || listed[0].quotaGuard != guard {
		t.Fatal("List result lost manager-owned quota guard")
	}
	updated := listed[0].Clone()
	updated.Label = "updated"
	if _, errUpdate := manager.Update(context.Background(), updated); errUpdate != nil {
		t.Fatal(errUpdate)
	}
	current, ok := manager.GetByID("lpg")
	if !ok || current.quotaGuard != guard {
		t.Fatal("Update/GetByID lost manager-owned quota guard")
	}
}

func TestQuotaGuardStatePersistenceAndLoad(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "quota", "state.json")
	guard := NewQuotaGuardForTest(QuotaGuardConfig{Mode: QuotaGuardModeActive, StateFile: statePath, Policies: []QuotaGuardPolicy{quotaTestPolicy()}}, nil)
	used := 88.0
	reset := time.Now().UTC().Add(time.Hour)
	guard.states["lpg"] = QuotaGuardState{AuthID: "lpg", Decision: QuotaDecisionExcluded, UsedPercent: &used, ResetAt: &reset, ObservedAt: time.Now().UTC()}
	if errPersist := guard.persistState(); errPersist != nil {
		t.Fatal(errPersist)
	}
	info, errStat := os.Stat(statePath)
	if errStat != nil {
		t.Fatal(errStat)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("state mode = %o, want 600", got)
	}
	data, errRead := os.ReadFile(statePath)
	if errRead != nil {
		t.Fatal(errRead)
	}
	var persisted map[string]QuotaGuardState
	if errDecode := json.Unmarshal(data, &persisted); errDecode != nil {
		t.Fatal(errDecode)
	}
	if persisted["lpg"].Decision != QuotaDecisionExcluded {
		t.Fatalf("persisted decision = %q", persisted["lpg"].Decision)
	}
	loaded := NewQuotaGuard(internalconfig.QuotaGuardConfig{
		Mode:      QuotaGuardModeActive,
		StateFile: statePath,
		Policies:  []internalconfig.QuotaGuardPolicy{{ID: " LPG ", Provider: " CLAUDE ", AuthFile: " lpg.json ", Window: " SEVEN_DAY ", MaxUsedPercent: 50, AllowWithinReset: "2h"}},
	})
	state, ok := loaded.StateSnapshot()["lpg"]
	if !ok || state.Decision != QuotaDecisionExcluded {
		t.Fatalf("loaded state = %#v, ok=%v", state, ok)
	}
}

func TestValidateQuotaGuardConfigRejectsInvalidAndNormalizesMatching(t *testing.T) {
	invalid := []internalconfig.QuotaGuardConfig{
		{Mode: "bogus"},
		{PollInterval: "not-a-duration"},
		{Policies: []internalconfig.QuotaGuardPolicy{{ID: "id", MaxUsedPercent: 0}}},
		{Policies: []internalconfig.QuotaGuardPolicy{{ID: "id", MaxUsedPercent: 50}, {ID: " ID ", MaxUsedPercent: 60}}},
	}
	for _, cfg := range invalid {
		if err := ValidateQuotaGuardConfig(cfg); err == nil {
			t.Fatalf("ValidateQuotaGuardConfig(%#v) accepted invalid config", cfg)
		}
	}
	guard, errNew := NewQuotaGuardWithHTTPClient(internalconfig.QuotaGuardConfig{
		Mode:     " ACTIVE ",
		Policies: []internalconfig.QuotaGuardPolicy{{ID: " LPG ", Provider: " CLAUDE ", AuthFile: "lpg.json", Window: " SEVEN_DAY ", MaxUsedPercent: 50}},
	}, nil)
	if errNew != nil {
		t.Fatal(errNew)
	}
	if _, ok := guard.PolicyFor(&Auth{ID: "lpg", Provider: "claude", FileName: "./lpg.json"}); !ok {
		t.Fatal("normalized policy did not match normalized auth metadata")
	}
}

func TestFetchClaudeQuotaUsesInjectedHTTPClient(t *testing.T) {
	client := &quotaTestHTTPClient{body: `{"seven_day":{"utilization":73.5,"resets_at":"2026-10-15T12:00:00Z"}}`}
	auth := &Auth{Provider: "claude", Metadata: map[string]any{"access_token": "test-token"}}
	reading, errFetch := fetchClaudeQuotaWithClient(context.Background(), auth, client)
	if errFetch != nil {
		t.Fatal(errFetch)
	}
	if client.request == nil || client.request.URL.String() != "https://api.anthropic.com/api/oauth/usage" || client.request.Header.Get("Authorization") != "Bearer test-token" {
		t.Fatalf("unexpected injected request: %#v", client.request)
	}
	if reading.UsedPercent != 73.5 || reading.ResetAt.IsZero() {
		t.Fatalf("reading = %#v", reading)
	}
}
