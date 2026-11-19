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
	for _, rebind := range []string{"always", "never"} {
		t.Run(rebind, func(t *testing.T) { testTrafficShapingSelectionLadder(t, rebind) })
	}
}

func testTrafficShapingSelectionLadder(t *testing.T, rebind string) {
	ctx := context.Background()
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{Fallback: &FillFirstSelector{}, TTL: time.Hour, RebindOn: rebind})
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
	ctx, opts = m.consumeTrafficClass(ctx, opts, false)
	pick := func(want string) string {
		t.Helper()
		got, _, _, err := m.pickWithTraffic(ctx, []string{"claude"}, model, opts, nil)
		if err != nil || got == nil {
			t.Fatalf("pick failed: %v", err)
		}
		if want != "" && got.ID != want {
			t.Fatalf("pick = %s; want %s", got.ID, want)
		}
		return got.ID
	}
	first := pick("")
	second := a.ID
	if first == a.ID {
		second = b.ID
	}
	m.mu.Lock()
	m.auths[first].Quota.ObserveResponseHeadersForProvider("claude", claudeWeeklyHeaders("0.90", clock.now.Add(48*time.Hour)), clock.now)
	m.mu.Unlock()
	pick(first) // An existing binding survives both the hourly cap and weekly reserve.
	newCtx, newOpts := m.consumeTrafficClass(context.Background(), executor.Options{Headers: http.Header{"X-Session-Id": {"new"}}}, false)
	if got, _, _, err := m.pickWithTraffic(newCtx, []string{"claude"}, model, newOpts, nil); err != nil || got.ID != second {
		t.Fatalf("new binding must prefer the account within its limits: got %v, err %v", got, err)
	}
	bg, bgOpts := m.consumeTrafficClass(context.Background(), executor.Options{Headers: http.Header{requestClassHeader: {"background"}}}, false)
	_, _, _, err := m.pickWithTraffic(bg, []string{"claude"}, model, bgOpts, nil)
	var deferred *trafficDeferred
	if !errors.As(err, &deferred) || clock.waited != time.Minute || SafeResponseHeaders(err).Get("Retry-After") != "3540" {
		t.Fatalf("want one minute of wait and trusted deferral, waited=%s err=%v headers=%v", clock.waited, err, SafeResponseHeaders(err))
	}
	cancelCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clock.cancel = cancel
	cancelCtx, bgOpts = m.consumeTrafficClass(cancelCtx, executor.Options{Headers: http.Header{requestClassHeader: {"background"}}}, false)
	if _, _, _, err = m.pickWithTraffic(cancelCtx, []string{"claude"}, model, bgOpts, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("wait ignored cancellation: %v", err)
	}
	clock.cancel = nil
	clock.now = clock.now.Add(59 * time.Minute)
	m.Remove(ctx, second)
	pick(first) // A sole account in reserve is not a soft failure for interactive turns.
	m.mu.Lock()
	m.auths[first].credentialRetryAfter = time.Now().Add(time.Hour)
	m.mu.Unlock()
	if _, _, _, err = m.pickWithTraffic(ctx, []string{"claude"}, model, opts, nil); err == nil {
		t.Fatal("interactive override bypassed a hard cooldown")
	}
}

func TestTrafficShapingBackgroundPreservesBinding(t *testing.T) {
	for _, rebind := range []string{"any", "never"} {
		t.Run(rebind, func(t *testing.T) {
			selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{Fallback: &FillFirstSelector{}, TTL: time.Hour, RebindOn: rebind})
			defer selector.Stop()
			m, clock, pick := newTrafficSelectionTest(t, selector)
			a, b := shapedAuth("a", false), shapedAuth("b", false)
			if got, err := pick("interactive", a); err != nil || got == nil || got.ID != a.ID {
				t.Fatalf("initial pick = %v, %v; want %s", got, err, a.ID)
			}
			if got, err := pick("background", b); got != nil || !isRequestStopError(err) || SafeResponseHeaders(err).Get("Retry-After") != "3540" || clock.waited != time.Minute {
				t.Fatalf("background pick = %v, %v, headers %v, waited %v; want policy deferral", got, err, SafeResponseHeaders(err), clock.waited)
			}
			if got, status := m.LookupSessionAffinity("mixed", "traffic-tier-test-model", "sticky"); status != "bound" || got == nil || got.ID != a.ID {
				t.Fatalf("binding = %v, %s; want %s", got, status, a.ID)
			}
			if got, err := pick("interactive"); err != nil || got == nil || got.ID != a.ID {
				t.Fatalf("interactive pick after deferral = %v, %v; want %s", got, err, a.ID)
			}
			// The cached account can be in a lower tier (e.g. after a higher
			// tier recovers from a hard cooldown); soft limits must not move it.
			higher := shapedAuth("higher", false)
			higher.Attributes = map[string]string{"priority": "10"}
			if got, err := pick("background", higher); got != nil || !isRequestStopError(err) || SafeResponseHeaders(err).Get("Retry-After") != "3540" {
				t.Fatalf("background lower-tier binding = %v, %v, headers %v; want policy deferral", got, err, SafeResponseHeaders(err))
			}
			if got, err := pick("interactive"); err != nil || got == nil || got.ID != a.ID {
				t.Fatalf("interactive lower-tier binding = %v, %v; want %s", got, err, a.ID)
			}
		})
	}
}

func TestTrafficShapingSoftLimitsStayInPriorityTier(t *testing.T) {
	for _, affinity := range []bool{false, true} {
		name := "plain"
		var selector Selector = &FillFirstSelector{}
		if affinity {
			name = "affinity"
			sticky := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{Fallback: selector, RebindOn: "any"})
			defer sticky.Stop()
			selector = sticky
		}
		t.Run(name, func(t *testing.T) {
			m, clock, pick := newTrafficSelectionTest(t, selector)
			subscription := shapedAuth("subscription", false)
			subscription.Attributes = map[string]string{"priority": "10"}
			paid := &Auth{ID: "paid", Provider: "claude", Status: StatusActive, Attributes: map[string]string{"api_key": "test-key"}}
			if _, err := pick("", subscription, paid); err != nil {
				t.Fatal(err)
			}
			if got, err := pick(""); err != nil || got == nil || got.ID != subscription.ID {
				t.Fatalf("unbound interactive pick = %v, %v; want subscription override", got, err)
			}
			if got, err := pick("background"); got != nil || !isRequestStopError(err) || SafeResponseHeaders(err).Get("Retry-After") != "3540" || clock.waited != time.Minute {
				t.Fatalf("background pick = %v, %v, headers %v, waited %v; want policy deferral", got, err, SafeResponseHeaders(err), clock.waited)
			}
			m.mu.Lock()
			m.auths[paid.ID].credentialRetryAfter = time.Now().Add(5 * time.Minute)
			m.mu.Unlock()
			if _, err := pick("background"); SafeResponseHeaders(err).Get("Retry-After") != "3480" {
				t.Fatalf("background retry followed a lower tier cooldown: %v, headers %v", err, SafeResponseHeaders(err))
			}
			m.mu.Lock()
			m.auths[subscription.ID].credentialRetryAfter = clock.now.Add(time.Hour)
			m.auths[paid.ID].credentialRetryAfter = time.Time{}
			m.mu.Unlock()
			if got, err := pick("background"); err != nil || got == nil || got.ID != paid.ID {
				t.Fatalf("hard cooldown pick = %v, %v; want lower tier fallback", got, err)
			}
		})
	}
}

// The empty class denotes an interactive request with no affinity identity.
func newTrafficSelectionTest(t *testing.T, selector Selector) (*Manager, *trafficTestClock, func(class string, register ...*Auth) (*Auth, error)) {
	t.Helper()
	m := NewManager(nil, selector, nil)
	m.RegisterExecutor(schedulerProviderTestExecutor{provider: "claude"})
	clock := &trafficTestClock{now: time.Now()}
	m.SetContinuityClockForTest(clock)
	const model = "traffic-tier-test-model"
	return m, clock, func(class string, register ...*Auth) (*Auth, error) {
		t.Helper()
		for _, a := range register {
			if _, err := m.Register(context.Background(), a); err != nil {
				t.Fatal(err)
			}
			registerSchedulerModels(t, "claude", model, a.ID)
		}
		opts := executor.Options{Headers: http.Header{}}
		if class != "" {
			opts.Headers.Set(requestClassHeader, class)
			opts.Headers.Set("X-Session-Id", "sticky")
		}
		ctx, opts := m.consumeTrafficClass(context.Background(), opts, false)
		a, _, _, err := m.pickWithTraffic(ctx, []string{"claude"}, model, opts, nil)
		return a, err
	}
}

func TestTrafficShapingNoDaySleepWithoutNightDuty(t *testing.T) {
	m := NewManager(nil, &FillFirstSelector{}, nil)
	a := shapedAuth("first-daytime-pick", true)
	m.auths[a.ID] = a
	now := time.Date(2026, 11, 18, 8, 0, 0, 0, trafficZone)
	ctx := context.Background()
	day, dawn, err := trafficDate(now)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, rest := m.trafficNight(ctx, day, now, dawn); rest != "" {
			t.Fatalf("account %q assigned daytime sleep without night duty", rest)
		}
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
		night, rest := m.trafficNight(context.Background(), id, day, dawn)
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
		for _, at := range []time.Time{day, dawn} {
			if d := m.trafficDecision(sleeper, p, "new", false, true, at, id, dawn, night, rest); !d.until.IsZero() {
				t.Fatalf("near reset incorrectly slept at %v: %+v", at, d)
			}
		}
		nextDay := day.AddDate(0, 0, 1)
		id, dawn, _ = trafficDate(nextDay)
		if next, _ := m.trafficNight(context.Background(), id, nextDay, dawn); next == night {
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
	ctx, opts := m.consumeTrafficClass(context.Background(), executor.Options{Headers: headers}, false)
	if len(opts.Headers) != 1 || opts.Headers.Get("X-Keep") != "ok" || len(headers) != 2 || !ctx.Value(trafficRequestKey{}).(*trafficRequest).background {
		t.Fatalf("incorrect header consumption: %v", opts.Headers)
	}
	headers[requestClassHeader] = []string{"interactive"}
	ctx, opts = m.consumeTrafficClass(context.Background(), executor.Options{Headers: headers}, false)
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

func TestTrafficShapingAllAsleepAndNightAtCap(t *testing.T) {
	m := NewManager(nil, &FillFirstSelector{}, nil)
	now := time.Date(2026, 11, 18, 1, 0, 0, 0, trafficZone)
	duty, sleeper := shapedAuth("duty", true), shapedAuth("sleeper", true)
	m.auths[duty.ID], m.auths[sleeper.ID] = duty, sleeper
	duty.Quota.ObserveResponseHeadersForProvider("claude", claudeWeeklyHeaders("0.2", now.Add(25*time.Hour)), now)
	m.trafficAccountFor(duty.ID).starts = []time.Time{now}
	opts := executor.Options{Headers: http.Header{"X-Session-Id": {"new"}}}
	ctx, _ := m.consumeTrafficClass(context.Background(), opts, false)
	for _, candidates := range [][]*Auth{{sleeper}, {duty, sleeper}} {
		p := &trafficPick{opts: opts, now: now, request: &trafficRequest{background: true}}
		_, err := m.shapeTraffic(ctx, p, candidates, "test-model")
		var deferred *trafficDeferred
		if !errors.As(err, &deferred) {
			t.Fatalf("asleep or capped background candidates must be deferred: %v", err)
		}
		p.request.background = false
		got, err := m.shapeTraffic(ctx, p, candidates, "test-model")
		if err != nil || len(got) != len(candidates) {
			t.Fatalf("interactive request must be able to wake a hard-eligible sleeper: %v", err)
		}
	}
}

func TestTrafficShapingNightSkipsHardBlockedDuty(t *testing.T) {
	m := NewManager(nil, &FillFirstSelector{}, nil)
	now := time.Date(2026, 11, 18, 1, 0, 0, 0, trafficZone)
	first, second := shapedAuth("first", true), shapedAuth("second", true)
	m.auths[first.ID], m.auths[second.ID] = first, second
	first.Quota.ObserveResponseHeadersForProvider("claude", claudeWeeklyHeaders("0.2", now.Add(25*time.Hour)), now)
	first.credentialRetryAfter = now.Add(time.Hour)
	ctx, _ := m.consumeTrafficClass(context.Background(), executor.Options{}, false)
	day, dawn, _ := trafficDate(now)
	if duty, _ := m.trafficNight(ctx, day, now, dawn); duty != second.ID {
		t.Fatalf("duty = %q, want %q", duty, second.ID)
	}
	first.credentialRetryAfter = time.Time{}
	second.credentialRetryAfter = now.Add(time.Hour)
	if duty, _ := m.trafficNight(ctx, day, now, dawn); duty != first.ID {
		t.Fatalf("replacement duty = %q, want %q", duty, first.ID)
	}
}

func TestTrafficShapingCountDoesNotChargeBudget(t *testing.T) {
	ctx := context.Background()
	m := NewManager(nil, &FillFirstSelector{}, nil)
	m.RegisterExecutor(schedulerProviderTestExecutor{provider: "claude"})
	a := shapedAuth("count-account", false)
	if _, err := m.Register(ctx, a); err != nil {
		t.Fatal(err)
	}
	clock := &trafficTestClock{now: time.Now()}
	m.SetContinuityClockForTest(clock)
	const model = "traffic-shaping-count-test-model"
	registerSchedulerModels(t, "claude", model, a.ID)
	req := executor.Request{Model: model}
	if _, err := m.ExecuteCount(ctx, []string{"claude"}, req, executor.Options{Headers: http.Header{"X-Session-Id": {"count-session"}}}); err != nil {
		t.Fatal(err)
	}
	opts := executor.Options{Headers: http.Header{requestClassHeader: {"background"}, "X-Session-Id": {"generation-session"}}}
	if _, err := m.Execute(ctx, []string{"claude"}, req, opts); err != nil || clock.waited != 0 {
		t.Fatalf("count consumed generation budget: waited %s, err %v", clock.waited, err)
	}
	usage := m.traffic.accounts[a.ID]
	if len(usage.starts) != 1 || len(usage.sessions) != 1 || usage.sessions["count-session"].After(time.Time{}) {
		t.Fatalf("traffic accounting includes count_tokens: %+v", usage)
	}
}

type trafficCaptureExecutor struct {
	schedulerProviderTestExecutor
	headers http.Header
}

func (e *trafficCaptureExecutor) Execute(_ context.Context, _ *Auth, _ executor.Request, opts executor.Options) (executor.Response, error) {
	e.headers = opts.Headers.Clone()
	return executor.Response{}, nil
}

func TestTrafficShapingExecutionDoesNotForwardClass(t *testing.T) {
	ctx := context.Background()
	m := NewManager(nil, &FillFirstSelector{}, nil)
	e := &trafficCaptureExecutor{schedulerProviderTestExecutor: schedulerProviderTestExecutor{provider: "claude"}}
	m.RegisterExecutor(e)
	a := shapedAuth("header-account", false)
	if _, err := m.Register(ctx, a); err != nil {
		t.Fatal(err)
	}
	const model = "traffic-shaping-header-test-model"
	registerSchedulerModels(t, "claude", model, a.ID)
	opts := executor.Options{Headers: http.Header{requestClassHeader: {"background"}, "X-Keep": {"value"}}}
	_, err := m.Execute(ctx, []string{"claude"}, executor.Request{Model: model}, opts)
	if err != nil || e.headers.Get(requestClassHeader) != "" || e.headers.Get("X-Keep") != "value" || opts.Headers.Get(requestClassHeader) != "background" {
		t.Fatalf("header containment failed: %v", err)
	}
}
