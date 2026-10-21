package auth

import (
	"context"
	"net/http"
	"strconv"
	"testing"
	"time"

	internallogging "github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func lpgReservePolicyMetadata() map[string]any {
	return map[string]any{
		MetadataQuotaGuard: map[string]any{"reserve_percent": float64(25), "reset_window": "24h", "final_reserve_percent": float64(5)},
	}
}

func TestEvaluateQuotaReserve(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	policy := QuotaReservePolicy{ReservePercent: 25, ResetWindow: 24 * time.Hour, FinalReservePercent: 5}
	cases := []struct {
		name      string
		used      float64
		resetIn   time.Duration
		excluded  bool
		reason    string
		recheckIn time.Duration
	}{
		{"plenty remaining", 40, 5 * 24 * time.Hour, false, "above_reserve", 0},
		{"exactly at reserve", 75, 5 * 24 * time.Hour, false, "above_reserve", 0},
		{"below reserve far from reset", 75.5, 3 * 24 * time.Hour, true, "below_reserve", 2 * 24 * time.Hour},
		{"just outside reset window", 80, 24*time.Hour + time.Minute, true, "below_reserve", time.Minute},
		{"inside reset window", 90, 24 * time.Hour, false, "within_reset_window", 0},
		{"at final reserve inside window", 95, time.Hour, false, "within_reset_window", 0},
		{"below final reserve inside window", 96, time.Hour, true, "below_final_reserve", time.Hour},
		{"below final reserve outside window waits for reset", 97, 3 * 24 * time.Hour, true, "below_reserve", 3 * 24 * time.Hour},
		{"reset already passed lifts guard", 100, -time.Minute, false, "weekly_window_reset", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := EvaluateQuotaReserve(policy, WeeklyQuotaReading{UsedPercent: tc.used, ResetAt: now.Add(tc.resetIn)}, now)
			if got.Excluded != tc.excluded || got.Reason != tc.reason {
				t.Fatalf("decision = %+v, want excluded=%v reason=%s", got, tc.excluded, tc.reason)
			}
			if tc.excluded && !got.RecheckAt.Equal(now.Add(tc.recheckIn)) {
				t.Fatalf("recheck = %s, want %s", got.RecheckAt, now.Add(tc.recheckIn))
			}
		})
	}
}

func TestParseQuotaReservePolicy(t *testing.T) {
	if _, ok, err := ParseQuotaReservePolicy(map[string]any{"type": "claude"}); ok || err != nil {
		t.Fatalf("absent policy: ok=%v err=%v", ok, err)
	}
	policy, ok, err := ParseQuotaReservePolicy(lpgReservePolicyMetadata())
	if !ok || err != nil || policy.ReservePercent != 25 || policy.ResetWindow != 24*time.Hour || policy.FinalReservePercent != 5 {
		t.Fatalf("policy = %+v ok=%v err=%v", policy, ok, err)
	}
	invalid := []map[string]any{
		{"reserve_percent": 25, "reset_window": "24h"},
		{"reserve_percent": 120, "reset_window": "24h", "final_reserve_percent": 5},
		{"reserve_percent": 25, "reset_window": "soon", "final_reserve_percent": 5},
		{"reserve_percent": 10, "reset_window": "24h", "final_reserve_percent": 20},
	}
	for _, fields := range invalid {
		if err := ValidateQuotaReservePolicy(map[string]any{MetadataQuotaGuard: fields}); err == nil {
			t.Fatalf("accepted invalid policy %v", fields)
		}
	}
	if err := ValidateQuotaReservePolicy(map[string]any{MetadataQuotaGuard: "on"}); err == nil {
		t.Fatal("accepted non-object policy")
	}
}

func TestWeeklyQuotaReadingFromProviderSignals(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	reset := now.Add(48 * time.Hour)
	claude := QuotaState{ObservedAt: now, Signals: map[string]string{
		"Anthropic-Ratelimit-Unified-7d-Utilization": "0.8",
		"Anthropic-Ratelimit-Unified-7d-Reset":       strconv.FormatInt(reset.Unix(), 10),
	}}
	got, ok := weeklyQuotaReading("claude", claude, now)
	if !ok || got.UsedPercent < 79.99 || got.UsedPercent > 80.01 || !got.ResetAt.Equal(reset) {
		t.Fatalf("claude reading = %+v ok=%v", got, ok)
	}
	codex := QuotaState{ObservedAt: now, Signals: map[string]string{
		"X-Codex-Primary-Window-Minutes":        "300",
		"X-Codex-Primary-Used-Percent":          "99",
		"X-Codex-Secondary-Window-Minutes":      "10080",
		"X-Codex-Secondary-Used-Percent":        "62",
		"X-Codex-Secondary-Reset-After-Seconds": "3600",
	}}
	got, ok = weeklyQuotaReading("codex", codex, now)
	if !ok || got.UsedPercent != 62 || !got.ResetAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("codex reading = %+v ok=%v", got, ok)
	}
	if _, ok := weeklyQuotaReading("codex", QuotaState{Signals: map[string]string{"X-Codex-Primary-Window-Minutes": "300", "X-Codex-Primary-Used-Percent": "99"}}, now); ok {
		t.Fatal("session window must not be read as weekly")
	}
}

func claudeWeeklyHeaders(utilization string, reset time.Time) http.Header {
	headers := http.Header{}
	headers.Set("Anthropic-Ratelimit-Unified-7d-Utilization", utilization)
	headers.Set("Anthropic-Ratelimit-Unified-7d-Reset", strconv.FormatInt(reset.Unix(), 10))
	headers.Set("Anthropic-Ratelimit-Unified-7d-Status", "allowed")
	return headers
}

func TestQuotaReserveGuardRoutesAroundDrainedCredential(t *testing.T) {
	ctx := context.Background()
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.RegisterExecutor(schedulerProviderTestExecutor{provider: "claude"})
	model := "quota-reserve-guard-model"
	guarded := &Auth{ID: "lpg-claude", Provider: "claude", Metadata: lpgReservePolicyMetadata()}
	backup := &Auth{ID: "other-claude", Provider: "claude"}
	for _, auth := range []*Auth{guarded, backup} {
		if _, err := manager.Register(ctx, auth); err != nil {
			t.Fatal(err)
		}
	}
	registerSchedulerModels(t, "claude", model, guarded.ID, backup.ID)
	manager.RefreshSchedulerEntry(guarded.ID)
	manager.RefreshSchedulerEntry(backup.ID)

	// No quota data yet: the guarded credential stays eligible.
	seen := map[string]bool{}
	for i := 0; i < 4; i++ {
		picked, _, err := manager.pickNext(ctx, "claude", model, cliproxyexecutor.Options{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		seen[picked.ID] = true
	}
	if !seen[guarded.ID] {
		t.Fatal("guarded credential with unknown quota was not routable")
	}

	// A response reports 80% weekly used with the reset 3 days out: excluded.
	markWithHeaders(ctx, manager, guarded.ID, model, claudeWeeklyHeaders("0.80", time.Now().Add(72*time.Hour)))
	for i := 0; i < 4; i++ {
		picked, _, err := manager.pickNext(ctx, "claude", model, cliproxyexecutor.Options{}, nil)
		if err != nil {
			t.Fatalf("fall-through pick failed: %v", err)
		}
		if picked.ID != backup.ID {
			t.Fatalf("picked %s, want fall-through to %s", picked.ID, backup.ID)
		}
	}

	// Inside the final 24h the guarded credential may be used down to 5%.
	markWithHeaders(ctx, manager, guarded.ID, model, claudeWeeklyHeaders("0.90", time.Now().Add(6*time.Hour)))
	seen = map[string]bool{}
	for i := 0; i < 4; i++ {
		picked, _, err := manager.pickNext(ctx, "claude", model, cliproxyexecutor.Options{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		seen[picked.ID] = true
	}
	if !seen[guarded.ID] {
		t.Fatal("guarded credential not eligible inside reset window")
	}
}

func TestQuotaReserveGuardLiftsAtWeeklyReset(t *testing.T) {
	ctx := context.Background()
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.RegisterExecutor(schedulerProviderTestExecutor{provider: "claude"})
	model := "quota-reserve-reset-model"
	guarded := &Auth{ID: "lpg-claude-reset", Provider: "claude", Metadata: lpgReservePolicyMetadata()}
	if _, err := manager.Register(ctx, guarded); err != nil {
		t.Fatal(err)
	}
	registerSchedulerModels(t, "claude", model, guarded.ID)
	manager.RefreshSchedulerEntry(guarded.ID)
	markWithHeaders(ctx, manager, guarded.ID, model, claudeWeeklyHeaders("0.99", time.Now().Add(1500*time.Millisecond)))
	if _, _, err := manager.pickNext(ctx, "claude", model, cliproxyexecutor.Options{}, nil); err == nil {
		t.Fatal("drained sole credential was routable before reset")
	}
	time.Sleep(2 * time.Second)
	picked, _, err := manager.pickNext(ctx, "claude", model, cliproxyexecutor.Options{}, nil)
	if err != nil || picked.ID != guarded.ID {
		t.Fatalf("guard did not lift at reset: picked=%v err=%v", picked, err)
	}
}

func TestQuotaReserveGuardRebindsSessionAffinity(t *testing.T) {
	now := time.Now()
	bound := &Auth{ID: "lpg", Provider: "claude", Status: StatusActive, Attributes: map[string]string{"priority": "10"}, Metadata: lpgReservePolicyMetadata()}
	backup := &Auth{ID: "backup", Provider: "claude", Status: StatusActive}
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{Fallback: &FillFirstSelector{}, TTL: time.Hour, RebindOn: SessionAffinityRebindOnQuota})
	defer selector.Stop()
	opts := cliproxyexecutor.Options{Headers: http.Header{"X-Session-Id": []string{"reserve-session"}}}
	first, err := selector.Pick(context.Background(), "claude", "claude-sonnet", opts, []*Auth{bound, backup})
	if err != nil || first.ID != "lpg" {
		t.Fatalf("initial pick = %v err=%v, want lpg", first, err)
	}
	bound.Quota.ObserveResponseHeadersForProvider("claude", claudeWeeklyHeaders("0.85", now.Add(72*time.Hour)), now)
	second, err := selector.Pick(context.Background(), "claude", "claude-sonnet", opts, []*Auth{bound, backup})
	if err != nil || second.ID != "backup" {
		t.Fatalf("bound session not rebound off drained credential: %v err=%v", second, err)
	}
}

func TestUnguardedCredentialIgnoresWeeklyUsage(t *testing.T) {
	now := time.Now()
	auth := &Auth{ID: "plain", Provider: "claude"}
	auth.Quota.ObserveResponseHeadersForProvider("claude", claudeWeeklyHeaders("0.99", now.Add(72*time.Hour)), now)
	if blocked, _, _ := isAuthBlockedForModel(auth, "", now); blocked {
		t.Fatal("credential without quota_guard was excluded")
	}
}

func markWithHeaders(ctx context.Context, manager *Manager, authID, model string, headers http.Header) {
	ctx = internallogging.WithFreshResponseHeadersHolder(ctx)
	internallogging.SetResponseHeaders(ctx, headers)
	manager.MarkResult(ctx, Result{AuthID: authID, Provider: "claude", Model: model, Success: true})
}
