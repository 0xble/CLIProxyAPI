package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func quotaTestPolicy() QuotaGuardPolicy {
	return QuotaGuardPolicy{ID: "lpg", Provider: "claude", AuthFile: "lpg.json", Window: QuotaGuardWindow7Day, MaxUsedPercent: 50, AllowWithinReset: 2 * time.Hour}
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
