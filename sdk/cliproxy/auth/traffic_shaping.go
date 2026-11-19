package auth

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"math/rand/v2"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	log "github.com/sirupsen/logrus"
)

const (
	requestClassHeader = "X-Hermes-Request-Class"
	trafficIdle        = 15 * time.Minute
	trafficWait        = time.Minute
	maxTrafficRequests = 10000
)

// trafficPolicy is opt-in for Claude credentials with a valid quota_guard.
// The original guard remains unchanged for credentials without traffic_shaping.
type trafficPolicy struct {
	requests, sessions int
	night              bool
	reserve            QuotaReservePolicy
}

func parseTrafficPolicy(metadata map[string]any) (trafficPolicy, bool, error) {
	fields, _ := metadata[MetadataQuotaGuard].(map[string]any)
	raw := fields["traffic_shaping"]
	if raw == nil {
		return trafficPolicy{}, false, nil
	}
	settings, ok := raw.(map[string]any)
	if !ok {
		return trafficPolicy{}, false, fmt.Errorf("quota_guard.traffic_shaping must be an object")
	}
	var p trafficPolicy
	for key, value := range settings {
		switch key {
		case "requests_per_hour", "active_sessions":
			n, err := strconv.Atoi(fmt.Sprint(value))
			if err != nil || n < 1 || n > maxTrafficRequests {
				return p, false, fmt.Errorf("quota_guard.traffic_shaping.%s must be an integer from 1 to %d", key, maxTrafficRequests)
			}
			if key == "requests_per_hour" {
				p.requests = n
			} else {
				p.sessions = n
			}
		case "night":
			p.night, ok = value.(bool)
			if !ok {
				return p, false, fmt.Errorf("quota_guard.traffic_shaping.night must be boolean")
			}
		default:
			return p, false, fmt.Errorf("quota_guard.traffic_shaping contains an unknown field")
		}
	}
	reserve, _, err := ParseQuotaReservePolicy(metadata)
	if err != nil {
		return p, false, err
	}
	p.reserve = reserve
	return p, true, nil
}

func trafficPolicyFor(a *Auth) (trafficPolicy, bool) {
	if a == nil || !strings.EqualFold(a.Provider, "claude") || a.AuthKind() == AuthKindAPIKey {
		return trafficPolicy{}, false
	}
	p, ok, _ := parseTrafficPolicy(a.Metadata)
	return p, ok
}

type trafficRequestKey struct{}
type trafficRequest struct {
	background bool
	countOnly  bool
	waited     time.Duration
	enabled    bool
}

// Remove the hop-local hint even if no credential opts in. Treat duplicate and
// invalid hints as interactive. Do not mutate caller-owned headers.
func (m *Manager) consumeTrafficClass(ctx context.Context, opts cliproxyexecutor.Options, countOnly bool) (context.Context, cliproxyexecutor.Options) {
	var values []string
	cloned := false
	for key, headers := range opts.Headers {
		if !strings.EqualFold(key, requestClassHeader) {
			continue
		}
		if !cloned {
			opts.Headers = opts.Headers.Clone()
			cloned = true
		}
		values = append(values, headers...)
		delete(opts.Headers, key)
	}
	request := &trafficRequest{background: len(values) == 1 && strings.EqualFold(strings.TrimSpace(values[0]), "background"), enabled: !m.HomeEnabled(), countOnly: countOnly}
	return context.WithValue(ctx, trafficRequestKey{}, request), opts
}

// On the local execution path, opt-in accounts use the soft reserve instead of
// the original hard selector gate. All other hard gates still run normally.
func isLegacyReserveExcludedForRequest(ctx context.Context, auth *Auth, now time.Time) (bool, time.Time) {
	if ctx != nil {
		if request, _ := ctx.Value(trafficRequestKey{}).(*trafficRequest); request != nil && request.enabled {
			if _, ok := trafficPolicyFor(auth); ok {
				return false, time.Time{}
			}
		}
	}
	return isQuotaReserveExcluded(auth, now)
}

type trafficAccount struct {
	starts   []time.Time
	sessions map[string]time.Time
	reserves [2]reserveLatch
}
type reserveLatch struct {
	floor float64
	reset time.Time
}
type trafficShapingState struct {
	accounts     map[string]*trafficAccount
	day          int
	night        string
	daytimeSleep string
}

// DST-safe: form civil boundaries in the target IANA zone, not midnight + hours.
// Embed the zone data so small containers without tzdata can still evaluate it.
func trafficDate(now time.Time) (day int, dawn time.Time, err error) {
	if trafficZoneErr != nil {
		return 0, time.Time{}, trafficZoneErr
	}
	local := now.In(trafficZone)
	y, m, d := local.Date()
	return int(time.Date(y, m, d, 0, 0, 0, 0, time.UTC).Unix() / 86400), time.Date(y, m, d, 7, 0, 0, 0, trafficZone), nil
}

var trafficZone, trafficZoneErr = time.LoadLocation("America/Los_Angeles")

// Called under m.mu (registered auth snapshot) and trafficMu (runtime state).
func (m *Manager) trafficNight(ctx context.Context, day int, now, dawn time.Time) (night, rest string) {
	state := &m.traffic
	blocked, _, _ := authAvailabilityForRequest(ctx, m.auths[state.night], "", now)
	if state.day == day && (!blocked || !now.Before(dawn)) {
		return state.night, state.daytimeSleep
	}
	var ids []string
	var best string
	var reset time.Time
	for id, a := range m.auths {
		p, ok := trafficPolicyFor(a)
		if !ok || !p.night {
			continue
		}
		if blocked, _, _ := authAvailabilityForRequest(ctx, a, "", now); blocked {
			continue
		}
		ids = append(ids, id)
		if id == state.night {
			continue
		}
		r, known := weeklyQuotaReading(a.Provider, a.Quota, now)
		if known && r.ResetAt.After(now) && r.UsedPercent < 100 && (reset.IsZero() || r.ResetAt.Before(reset) || (r.ResetAt.Equal(reset) && id < best)) {
			best, reset = id, r.ResetAt
		}
	}
	if len(ids) == 0 {
		return "", ""
	}
	sort.Strings(ids)
	if best == "" {
		i := (day%len(ids) + len(ids)) % len(ids)
		best = ids[i]
		if len(ids) > 1 && best == state.night {
			best = ids[(i+1)%len(ids)]
		}
	}
	rest = best // rest following the night shift ending this morning
	state.day, state.night, state.daytimeSleep = day, best, rest
	return best, rest
}

func trafficJitter(id string, day int) time.Duration {
	h := fnv.New32a()
	_, _ = h.Write([]byte(id + ":" + strconv.Itoa(day)))
	return time.Duration(1+h.Sum32()%1800) * time.Second
}

// A soft decision is deliberately separate from hard availability, so the
// ladder can't resurrect a disabled, cooled, excluded or unsupported auth.
type trafficDecision struct {
	until   time.Time
	reasons []string
}

func (d *trafficDecision) delay(reason string, until time.Time) {
	d.reasons = append(d.reasons, reason)
	if until.After(d.until) {
		d.until = until
	}
}

func (m *Manager) trafficDecision(a *Auth, p trafficPolicy, session string, pinned, background bool, now time.Time, day int, dawn time.Time, night, rest string) trafficDecision {
	var d trafficDecision
	// A soft limit must not turn an interactive binding into a failover.
	if pinned && !background {
		return d
	}
	if usage := m.traffic.accounts[a.ID]; usage != nil {
		if p.requests > 0 {
			first := sort.Search(len(usage.starts), func(i int) bool { return usage.starts[i].Add(time.Hour).After(now) })
			if len(usage.starts)-first >= p.requests {
				d.delay("hourly_cap", usage.starts[len(usage.starts)-p.requests].Add(time.Hour))
			}
		}
		if p.sessions > 0 && !pinned && session != "" && !usage.sessions[session].Add(trafficIdle).After(now) {
			active := 0
			var earliest time.Time
			for _, last := range usage.sessions {
				end := last.Add(trafficIdle)
				if end.After(now) {
					active++
					if earliest.IsZero() || end.Before(earliest) {
						earliest = end
					}
				}
			}
			if active >= p.sessions {
				d.delay("session_cap", earliest)
			}
		}
	}
	r, known := weeklyQuotaReading(a.Provider, a.Quota, now)
	remaining, toReset := 100-r.UsedPercent, r.ResetAt.Sub(now)
	near := known && toReset > 0 && toReset <= 24*time.Hour && remaining > 0
	usage := m.trafficAccountFor(a.ID)
	index := 0
	if background {
		index = 1
	}
	if known && toReset > 0 {
		floor := p.reserve.ReservePercent
		recheck := r.ResetAt
		if remaining >= p.reserve.FinalReservePercent {
			recheck = r.ResetAt.Add(-p.reserve.ResetWindow)
		} else if !background && remaining > 0 {
			recheck = r.ResetAt.Add(-6 * time.Hour)
		}
		if toReset <= p.reserve.ResetWindow {
			floor = p.reserve.FinalReservePercent
		}
		if !background && toReset <= 6*time.Hour {
			floor = 0
		}
		if background {
			floor = max(floor, 5)
			if remaining < 5 {
				recheck = r.ResetAt
			}
		}
		latch := usage.reserves[index]
		threshold := floor
		if floor > 0 && latch.floor == floor && latch.reset.Equal(r.ResetAt) {
			threshold = min(100, floor+2)
		}
		if remaining < threshold {
			usage.reserves[index] = reserveLatch{floor: floor, reset: r.ResetAt}
			if !recheck.After(now) {
				recheck = r.ResetAt
			}
			if !background && toReset > 6*time.Hour {
				recheck = minDeadline(recheck, r.ResetAt.Add(-6*time.Hour))
			}
			d.delay("weekly_reserve", recheck)
		} else {
			usage.reserves[index] = reserveLatch{}
		}
	} else {
		usage.reserves[index] = reserveLatch{}
	}
	if p.night && !dawn.IsZero() && !pinned && !near {
		if now.Before(dawn) && a.ID != night {
			d.delay("night_sleep", dawn)
		}
		if !now.Before(dawn) && now.Before(dawn.Add(6*time.Hour)) && a.ID == rest {
			d.delay("day_sleep", dawn.Add(6*time.Hour))
		}
	}
	if p.night && background && !pinned && !near && !dawn.IsZero() && a.ID != night {
		release := dawn.Add(trafficJitter(a.ID, day))
		if now.Before(release) {
			d.delay("dawn_pacing", release)
		}
	}
	return d
}

type trafficDeferred struct {
	until time.Time
	now   time.Time
}

func (e *trafficDeferred) Error() string {
	return "background request deferred by account traffic policy"
}
func (e *trafficDeferred) IsRequestStop() bool { return true }
func (e *trafficDeferred) StatusCode() int     { return http.StatusServiceUnavailable }
func (e *trafficDeferred) SafeResponseHeaders() http.Header {
	retry := max(1, int((e.until.Sub(e.now)+time.Second-1)/time.Second))
	return http.Header{"Retry-After": {strconv.Itoa(retry)}}
}

type trafficPickKey struct{}
type trafficPick struct {
	opts    cliproxyexecutor.Options
	request *trafficRequest
	now     time.Time
	bound   string
}

// Called after hard availability and before priority tiers are built.
func (m *Manager) shapeTraffic(ctx context.Context, options *trafficPick, candidates []*Auth, model string) ([]*Auth, error) {
	hasPolicy := false
	for _, a := range candidates {
		if _, ok := trafficPolicyFor(a); ok {
			hasPolicy = true
			break
		}
	}
	if !hasPolicy {
		return candidates, nil
	}
	background := options.request.background
	bound := pinnedAuthIDFromMetadata(options.opts.Metadata)
	session := CanonicalSessionID(options.opts.Headers, options.opts.OriginalRequest, options.opts.Metadata)
	if bound == "" {
		if affinity, ok := m.selector.(*SessionAffinitySelector); ok {
			bound, _ = affinity.boundAuthForRequest(nil, selectionArgForSelector(affinity, model), options.opts)
		}
	}
	options.bound = bound
	now := options.now
	day, dawn, err := trafficDate(now)
	if err != nil {
		log.WithError(err).Warn("account traffic schedule unavailable; ignoring sleep policy")
	}
	m.trafficMu.Lock()
	defer m.trafficMu.Unlock()
	var night, rest string
	if err == nil {
		night, rest = m.trafficNight(ctx, day, now, dawn)
	}
	var eligible []*Auth
	var next time.Time
	for _, a := range candidates {
		if p, ok := trafficPolicyFor(a); ok {
			d := m.trafficDecision(a, p, session, a.ID == bound, background, now, day, dawn, night, rest)
			if len(d.reasons) > 0 {
				if next.IsZero() || d.until.Before(next) {
					next = d.until
				}
				log.WithFields(log.Fields{"provider": a.Provider, "reasons": d.reasons, "eligible_at": d.until, "background": background}).Debug("account traffic preference deferred a candidate")
				continue
			}
		}
		eligible = append(eligible, a)
	}
	if len(eligible) > 0 {
		return eligible, nil
	}
	if !background {
		log.WithField("candidate_count", len(candidates)).Debug("interactive request overriding account traffic preference")
		return candidates, nil
	}
	return nil, &trafficDeferred{until: next, now: now}
}

func minDeadline(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// Prefer ample weekly quota and accounts close to reset. Use a bounded
// multiplier so existing operator weights keep their meaning. Unknown
// quota is neutral, and this never changes configured priority tiers.
func trafficWeight(auth *Auth, now time.Time) float64 {
	reading, known := weeklyQuotaReading(auth.Provider, auth.Quota, now)
	if !known || !reading.ResetAt.After(now) {
		return 1
	}
	remaining := (100 - reading.UsedPercent) / 100
	urgency := 1 - min(1, max(0, reading.ResetAt.Sub(now).Hours()/168))
	return 0.5 + remaining*(1+urgency)
}

func weightedTrafficCandidates(ctx context.Context, auths []*Auth) []*Auth {
	if ctx == nil {
		return auths
	}
	p, _ := ctx.Value(trafficPickKey{}).(*trafficPick)
	if p == nil || len(auths) < 2 {
		return auths
	}
	for _, a := range auths {
		if a.ID == p.bound || !strings.EqualFold(a.Provider, "claude") {
			return auths
		}
	}
	tier := highestPriorityAuths(auths)
	total := 0.0
	weights := make([]float64, len(tier))
	optedIn := false
	for i, a := range tier {
		weight := 1.0
		if _, ok := trafficPolicyFor(a); ok {
			weight = trafficWeight(a, p.now)
			optedIn = true
		}
		weights[i] = weight * float64(max(1, authWeight(a)))
		total += weights[i]
	}
	if !optedIn {
		return auths
	}
	draw := rand.Float64() * total
	for i, w := range weights {
		if draw < w {
			return tier[i : i+1]
		}
		draw -= w
	}
	return tier[len(tier)-1:]
}

// trafficAccountFor is called under trafficMu.
func (m *Manager) trafficAccountFor(id string) *trafficAccount {
	if m.traffic.accounts == nil {
		m.traffic.accounts = make(map[string]*trafficAccount)
	}
	a := m.traffic.accounts[id]
	if a == nil {
		a = &trafficAccount{sessions: make(map[string]time.Time)}
		m.traffic.accounts[id] = a
	}
	return a
}

func (m *Manager) recordTrafficPick(auth *Auth, opts cliproxyexecutor.Options, now time.Time) {
	if _, ok := trafficPolicyFor(auth); !ok {
		return
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if current := m.auths[auth.ID]; current == nil || current.RegistrationEpoch != auth.RegistrationEpoch {
		return
	}
	m.trafficMu.Lock()
	defer m.trafficMu.Unlock()
	a := m.trafficAccountFor(auth.ID)
	first := sort.Search(len(a.starts), func(i int) bool { return a.starts[i].Add(time.Hour).After(now) })
	first = max(first, len(a.starts)-maxTrafficRequests+1)
	if first > 0 {
		a.starts = append(a.starts[:0], a.starts[first:]...)
	}
	a.starts = append(a.starts, now)
	for session, last := range a.sessions {
		if !last.Add(trafficIdle).After(now) {
			delete(a.sessions, session)
		}
	}
	if session := CanonicalSessionID(opts.Headers, opts.OriginalRequest, opts.Metadata); session != "" && (len(a.sessions) < maxTrafficRequests || !a.sessions[session].IsZero()) {
		a.sessions[session] = now
	}
}

func (m *Manager) pickWithTraffic(ctx context.Context, providers []string, model string, opts cliproxyexecutor.Options, tried map[string]struct{}) (*Auth, ProviderExecutor, string, error) {
	request, _ := ctx.Value(trafficRequestKey{}).(*trafficRequest)
	if request == nil || !request.enabled || !m.hasTrafficPolicy(providers) {
		return m.pickNextMixed(ctx, providers, model, opts, tried)
	}
	opts.EnsureMetadata()
	for {
		if err := ctx.Err(); err != nil {
			return nil, nil, "", err
		}
		clock := m.getContinuityClock()
		// Check and count together: a burst must not all observe the same headroom.
		m.trafficPickMu.Lock()
		pickCtx := context.WithValue(ctx, trafficPickKey{}, &trafficPick{opts: opts, request: request, now: clock.Now()})
		selected, executor, provider, err := m.pickNextMixedLegacy(pickCtx, providers, model, opts, tried)
		if err == nil && !request.countOnly {
			m.recordTrafficPick(selected, opts, clock.Now())
		}
		m.trafficPickMu.Unlock()
		var deferred *trafficDeferred
		if !errors.As(err, &deferred) {
			return selected, executor, provider, err
		}
		delay := min(deferred.until.Sub(clock.Now()), trafficWait-request.waited)
		if delay <= 0 {
			log.WithField("eligible_at", deferred.until).Debug("background request deferred after account traffic wait")
			return nil, nil, "", deferred
		}
		request.waited += delay
		if errWait := clock.Wait(ctx, delay); errWait != nil {
			return nil, nil, "", errWait
		}
	}
}

func (m *Manager) hasTrafficPolicy(providers []string) bool {
	if !slices.Contains(providers, "claude") {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, a := range m.auths {
		if _, ok := trafficPolicyFor(a); ok {
			return true
		}
	}
	return false
}
