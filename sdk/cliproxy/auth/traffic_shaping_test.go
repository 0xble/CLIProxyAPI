package auth

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	executor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func shapedAuth(id string, night bool) *Auth {
	return &Auth{ID: id, Provider: "claude", Status: StatusActive, Metadata: map[string]any{MetadataQuotaGuard: map[string]any{
		"reserve_percent": 15, "reset_window": "24h", "final_reserve_percent": 5,
		"traffic_shaping": map[string]any{"requests_per_hour": 1, "active_sessions": 1, "night": night},
	}}}
}

type trafficTestClock struct {
	now    time.Time
	waited time.Duration
	cancel context.CancelFunc
}

func (c *trafficTestClock) Now() time.Time { return c.now }
func (c *trafficTestClock) Wait(ctx context.Context, d time.Duration) error {
	if c.cancel != nil {
		c.cancel()
		return ctx.Err()
	}
	c.now = c.now.Add(d)
	c.waited += d
	return nil
}

func TestTrafficShapingSelectionLadder(t *testing.T) {
	ctx := context.Background()
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{Fallback: &FillFirstSelector{}, TTL: time.Hour})
	defer selector.Stop()
	m := NewManager(nil, selector, nil)
	m.RegisterExecutor(schedulerProviderTestExecutor{provider: "claude"})
	clock := &trafficTestClock{now: time.Now()}
	m.SetContinuityClockForTest(clock)
	a, b := shapedAuth("traffic-a", false), shapedAuth("traffic-b", false)
	const model = "traffic-shaping-test-model"
	for _, auth := range []*Auth{a, b} {
		if _, err := m.Register(ctx, auth); err != nil {
			t.Fatal(err)
		}
	}
	registerSchedulerModels(t, "claude", model, a.ID, b.ID)
	opts := executor.Options{Headers: http.Header{"X-Session-Id": {"sticky"}}}
	ctx, opts = m.consumeTrafficClass(ctx, opts)
	pick := func(want string) {
		t.Helper()
		got, _, _, err := m.pickWithTraffic(ctx, []string{"claude"}, model, opts, nil)
		if err != nil || got == nil || got.ID != want {
			t.Fatalf("pick = %v, %v; want %s", got, err, want)
		}
	}
	pick(a.ID)
	pick(b.ID)
	pick(b.ID) // both capped: preserve the affinity established by the second pick.
	bg, bgOpts := m.consumeTrafficClass(context.Background(), executor.Options{Headers: http.Header{requestClassHeader: {"background"}}})
	_, _, _, err := m.pickWithTraffic(bg, []string{"claude"}, model, bgOpts, nil)
	var deferred *trafficDeferred
	if !errors.As(err, &deferred) || clock.waited != time.Minute || SafeResponseHeaders(err).Get("Retry-After") != "3540" {
		t.Fatalf("want one minute of wait and trusted deferral, waited=%s err=%v headers=%v", clock.waited, err, SafeResponseHeaders(err))
	}
	cancelCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clock.cancel = cancel
	cancelCtx, bgOpts = m.consumeTrafficClass(cancelCtx, executor.Options{Headers: http.Header{requestClassHeader: {"background"}}})
	if _, _, _, err = m.pickWithTraffic(cancelCtx, []string{"claude"}, model, bgOpts, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("wait ignored cancellation: %v", err)
	}
	clock.cancel = nil
	clock.now = clock.now.Add(59 * time.Minute)
	m.Remove(ctx, a.ID)
	pick(b.ID) // cap recovers at the rolling-hour boundary.
	pick(b.ID) // a sole account is not a soft failure for interactive turns.
	m.mu.Lock()
	m.auths[b.ID].credentialRetryAfter = time.Now().Add(time.Hour)
	m.mu.Unlock()
	if _, _, _, err = m.pickWithTraffic(ctx, []string{"claude"}, model, opts, nil); err == nil {
		t.Fatal("interactive override bypassed a hard cooldown")
	}
}

func TestTrafficShapingSchedule(t *testing.T) {
	for _, day := range []time.Time{time.Date(2026, 3, 8, 0, 0, 0, 0, trafficZone), time.Date(2026, 11, 1, 0, 0, 0, 0, trafficZone)} {
		m := NewManager(nil, &FillFirstSelector{}, nil)
		a, b := shapedAuth("a", true), shapedAuth("b", true)
		m.auths[a.ID], m.auths[b.ID] = a, b
		id, dawn, err := trafficDate(day)
		if err != nil || dawn.In(trafficZone).Hour() != 7 {
			t.Fatalf("bad DST boundary: %v %v", dawn, err)
		}
		night, rest := m.trafficNight(id, day)
		sleeper, working := a, b
		if night == a.ID {
			sleeper, working = b, a
		}
		if rest != night {
			t.Fatal("night account does not get morning rest")
		}
		p, _ := trafficPolicyFor(sleeper)
		if d := m.trafficDecision(sleeper, p, "new", false, true, day, id, dawn, night, rest); d.until.Before(dawn) {
			t.Fatalf("night sleep missing: %+v", d)
		}
		if d := m.trafficDecision(sleeper, p, "bound", true, true, day, id, dawn, night, rest); !d.until.IsZero() {
			t.Fatalf("sleep blocked a binding: %+v", d)
		}
		if d := m.trafficDecision(working, p, "new", false, true, dawn, id, dawn, night, rest); !d.until.Equal(dawn.Add(6 * time.Hour)) {
			t.Fatalf("night account did not rest: %+v", d)
		}
		release := dawn.Add(trafficJitter(sleeper.ID, id))
		if d := m.trafficDecision(sleeper, p, "new", false, true, dawn, id, dawn, night, rest); !d.until.Equal(release) || !release.After(dawn) || release.After(dawn.Add(30*time.Minute)) {
			t.Fatalf("bad dawn pacing: %+v", d)
		}
		if d := m.trafficDecision(sleeper, p, "new", false, true, release, id, dawn, night, rest); !d.until.IsZero() {
			t.Fatalf("dawn pacing did not lift: %+v", d)
		}
		sleeper.Quota.ObserveResponseHeadersForProvider("claude", claudeWeeklyHeaders("0.5", day.Add(12*time.Hour)), day)
		if d := m.trafficDecision(sleeper, p, "new", false, true, day, id, dawn, night, rest); !d.until.IsZero() {
			t.Fatalf("near reset incorrectly slept: %+v", d)
		}
		nextDay := day.AddDate(0, 0, 1)
		id, _, _ = trafficDate(nextDay)
		if next, _ := m.trafficNight(id, nextDay); next == night {
			t.Fatal("night account did not rotate")
		}
	}
}

func TestTrafficShapingReserveAndHysteresis(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	m := NewManager(nil, &FillFirstSelector{}, nil)
	a := shapedAuth("a", false)
	p, _ := trafficPolicyFor(a)
	decide := func(at, reset time.Time, used string, bg bool) bool {
		t.Helper()
		a.Quota.ObserveResponseHeadersForProvider("claude", claudeWeeklyHeaders(used, reset), at)
		return !m.trafficDecision(a, p, "", false, bg, at, 0, time.Time{}, "", "").until.IsZero()
	}
	reset := now.Add(48 * time.Hour)
	if !decide(now, reset, "0.86", true) || !decide(now, reset, "0.84", true) || decide(now, reset, "0.82", true) {
		t.Fatal("reserve must latch below 15% and re-admit at 17%")
	}
	if decide(reset.Add(-10*time.Hour), reset, "0.93", true) {
		t.Fatal("reserve did not drop to 5% near reset")
	}
	if !decide(reset.Add(-time.Hour), reset, "0.98", true) || decide(reset.Add(-time.Hour), reset, "0.98", false) {
		t.Fatal("final 5% must be reserved for interactive traffic")
	}
	if decide(reset, reset, "0.98", true) || decide(now, reset, "invalid", true) {
		t.Fatal("stale or unknown quota must not block")
	}
	if trafficWeight(a, now) != 1 {
		t.Fatal("unknown quota not neutral")
	}
	_ = decide(now, now.Add(time.Hour), "0.2", false)
	near := trafficWeight(a, now)
	_ = decide(now, now.Add(72*time.Hour), "0.2", false)
	far := trafficWeight(a, now)
	_ = decide(now, now.Add(72*time.Hour), "0.8", false)
	if near <= far || far <= trafficWeight(a, now) {
		t.Fatal("weight must favor remaining quota and nearer reset")
	}
}

func TestTrafficShapingHeaderAndPolicyValidation(t *testing.T) {
	m := NewManager(nil, &FillFirstSelector{}, nil)
	headers := http.Header{"x-hermes-request-class": {" background "}, "X-Keep": {"ok"}}
	ctx, opts := m.consumeTrafficClass(context.Background(), executor.Options{Headers: headers})
	if len(opts.Headers) != 1 || opts.Headers.Get("X-Keep") != "ok" || len(headers) != 2 || !ctx.Value(trafficRequestKey{}).(*trafficRequest).background {
		t.Fatalf("incorrect header consumption: %v", opts.Headers)
	}
	headers[requestClassHeader] = []string{"interactive"}
	ctx, opts = m.consumeTrafficClass(context.Background(), executor.Options{Headers: headers})
	if ctx.Value(trafficRequestKey{}).(*trafficRequest).background || len(opts.Headers) != 1 {
		t.Fatal("duplicate private header was not stripped or failed closed")
	}
	auth := shapedAuth("bad", false)
	auth.Metadata[MetadataQuotaGuard].(map[string]any)["traffic_shaping"] = map[string]any{"night": "yes"}
	if ValidateQuotaReservePolicy(auth.Metadata) == nil {
		t.Fatal("malformed schedule was not detected")
	}
	if _, ok := trafficPolicyFor(auth); ok {
		t.Fatal("malformed schedule did not fall back to original policy")
	}
}

func TestTrafficShapingSessionCapDoesNotBlockExistingBinding(t *testing.T) {
	now := time.Now()
	a := shapedAuth("a", false)
	p, _ := trafficPolicyFor(a)
	m := NewManager(nil, &FillFirstSelector{}, nil)
	m.trafficAccountFor(a.ID).sessions["existing"] = now
	if d := m.trafficDecision(a, p, "new", false, true, now, 0, time.Time{}, "", ""); !d.until.Equal(now.Add(trafficIdle)) {
		t.Fatalf("new session should wait: %+v", d)
	}
	if d := m.trafficDecision(a, p, "existing", true, true, now, 0, time.Time{}, "", ""); !d.until.IsZero() {
		t.Fatalf("existing session should continue: %+v", d)
	}
}
