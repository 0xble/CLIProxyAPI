package auth

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// MetadataQuotaGuard is the auth-file key that opts one credential into the
// weekly reserve guard. Credentials without it are never affected.
//
//	"quota_guard": {"reserve_percent": 25, "reset_window": "24h", "final_reserve_percent": 5}
//
// The credential is routable while at least reserve_percent of its weekly
// window remains. Inside reset_window before the weekly reset it stays
// routable down to final_reserve_percent. Once the reset time passes the guard
// lifts until a fresh response reports the new window.
const MetadataQuotaGuard = "quota_guard"

const weeklyWindowMinutes = 7 * 24 * 60

// QuotaReservePolicy is the parsed per-credential guard configuration.
type QuotaReservePolicy struct {
	ReservePercent      float64
	ResetWindow         time.Duration
	FinalReservePercent float64
}

// WeeklyQuotaReading is the weekly window state taken from passive response headers.
type WeeklyQuotaReading struct {
	UsedPercent float64
	ResetAt     time.Time
}

// QuotaReserveDecision explains whether the guard allows routing and, when it
// does not, when it should be evaluated again.
type QuotaReserveDecision struct {
	Excluded  bool
	Reason    string
	Remaining float64
	ResetAt   time.Time
	// RecheckAt is when an excluded credential may become eligible without new
	// quota data: the start of the reset window, or the reset itself.
	RecheckAt time.Time
}

// ParseQuotaReservePolicy reads the opt-in policy from auth metadata. It
// returns ok=false when the credential has not opted in.
func ParseQuotaReservePolicy(metadata map[string]any) (QuotaReservePolicy, bool, error) {
	raw, exists := metadata[MetadataQuotaGuard]
	if !exists || raw == nil {
		return QuotaReservePolicy{}, false, nil
	}
	fields, ok := raw.(map[string]any)
	if !ok {
		return QuotaReservePolicy{}, false, fmt.Errorf("%s must be an object", MetadataQuotaGuard)
	}
	reserve, errReserve := quotaPercentField(fields, "reserve_percent")
	if errReserve != nil {
		return QuotaReservePolicy{}, false, errReserve
	}
	final, errFinal := quotaPercentField(fields, "final_reserve_percent")
	if errFinal != nil {
		return QuotaReservePolicy{}, false, errFinal
	}
	if final > reserve {
		return QuotaReservePolicy{}, false, fmt.Errorf("%s.final_reserve_percent must not exceed reserve_percent", MetadataQuotaGuard)
	}
	windowRaw, _ := fields["reset_window"].(string)
	window, errWindow := time.ParseDuration(strings.TrimSpace(windowRaw))
	if errWindow != nil || window < 0 {
		return QuotaReservePolicy{}, false, fmt.Errorf("%s.reset_window must be a non-negative duration such as \"24h\"", MetadataQuotaGuard)
	}
	return QuotaReservePolicy{ReservePercent: reserve, ResetWindow: window, FinalReservePercent: final}, true, nil
}

// ValidateQuotaReservePolicy rejects malformed opt-in metadata at load and write time.
func ValidateQuotaReservePolicy(metadata map[string]any) error {
	_, _, err := ParseQuotaReservePolicy(metadata)
	return err
}

func quotaPercentField(fields map[string]any, name string) (float64, error) {
	var value float64
	switch typed := fields[name].(type) {
	case float64:
		value = typed
	case int:
		value = float64(typed)
	case int64:
		value = float64(typed)
	case string:
		parsed, errParse := strconv.ParseFloat(strings.TrimSpace(typed), 64)
		if errParse != nil {
			return 0, fmt.Errorf("%s.%s must be a number", MetadataQuotaGuard, name)
		}
		value = parsed
	default:
		return 0, fmt.Errorf("%s.%s is required", MetadataQuotaGuard, name)
	}
	if math.IsNaN(value) || value < 0 || value > 100 {
		return 0, fmt.Errorf("%s.%s must be between 0 and 100", MetadataQuotaGuard, name)
	}
	return value, nil
}

// weeklyQuotaReading extracts the weekly window from the last passive quota
// snapshot. Claude reports a 0-1 utilization fraction; Codex reports a 0-100
// percentage on whichever of the primary/secondary windows spans 7 days.
func weeklyQuotaReading(provider string, quota QuotaState, now time.Time) (WeeklyQuotaReading, bool) {
	signals := quota.Signals
	if len(signals) == 0 {
		return WeeklyQuotaReading{}, false
	}
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "claude":
		used, okUsed := parseQuotaFloat(signals["Anthropic-Ratelimit-Unified-7d-Utilization"])
		reset, okReset := parseQuotaUnix(signals["Anthropic-Ratelimit-Unified-7d-Reset"])
		if !okUsed || !okReset || used < 0 || used > 1.5 {
			return WeeklyQuotaReading{}, false
		}
		return WeeklyQuotaReading{UsedPercent: math.Min(used*100, 100), ResetAt: reset}, true
	case "codex":
		for _, window := range []string{"Primary", "Secondary"} {
			prefix := "X-Codex-" + window + "-"
			minutes, okMinutes := parseQuotaFloat(signals[prefix+"Window-Minutes"])
			if !okMinutes || minutes < weeklyWindowMinutes {
				continue
			}
			used, okUsed := parseQuotaFloat(signals[prefix+"Used-Percent"])
			if !okUsed || used < 0 {
				return WeeklyQuotaReading{}, false
			}
			reset, okReset := parseQuotaUnix(signals[prefix+"Reset-At"])
			if !okReset {
				seconds, okAfter := parseQuotaFloat(signals[prefix+"Reset-After-Seconds"])
				if !okAfter || quota.ObservedAt.IsZero() {
					return WeeklyQuotaReading{}, false
				}
				reset = quota.ObservedAt.Add(time.Duration(seconds * float64(time.Second)))
			}
			return WeeklyQuotaReading{UsedPercent: math.Min(used, 100), ResetAt: reset}, true
		}
	}
	return WeeklyQuotaReading{}, false
}

func parseQuotaFloat(raw string) (float64, bool) {
	value, errParse := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if errParse != nil || math.IsNaN(value) || math.IsInf(value, 0) {
		return 0, false
	}
	return value, true
}

func parseQuotaUnix(raw string) (time.Time, bool) {
	value, ok := parseQuotaFloat(raw)
	if !ok || value <= 0 {
		return time.Time{}, false
	}
	return time.Unix(int64(value), 0), true
}

// EvaluateQuotaReserve applies the policy to one reading.
func EvaluateQuotaReserve(policy QuotaReservePolicy, reading WeeklyQuotaReading, now time.Time) QuotaReserveDecision {
	remaining := 100 - reading.UsedPercent
	decision := QuotaReserveDecision{Remaining: remaining, ResetAt: reading.ResetAt}
	if !reading.ResetAt.After(now) {
		decision.Reason = "weekly_window_reset"
		return decision
	}
	if remaining >= policy.ReservePercent {
		decision.Reason = "above_reserve"
		return decision
	}
	windowStart := reading.ResetAt.Add(-policy.ResetWindow)
	if !now.Before(windowStart) {
		if remaining >= policy.FinalReservePercent {
			decision.Reason = "within_reset_window"
			return decision
		}
		decision.Excluded = true
		decision.Reason = "below_final_reserve"
		decision.RecheckAt = reading.ResetAt
		return decision
	}
	decision.Excluded = true
	decision.Reason = "below_reserve"
	decision.RecheckAt = windowStart
	if remaining < policy.FinalReservePercent {
		decision.RecheckAt = reading.ResetAt
	}
	return decision
}

// quotaReserveDecisionForAuth evaluates an opted-in credential. Missing or
// unparseable quota data leaves the credential eligible: the guard never
// fabricates a reading, and the first response will supply one.
func quotaReserveDecisionForAuth(auth *Auth, now time.Time) (QuotaReserveDecision, bool) {
	if auth == nil {
		return QuotaReserveDecision{}, false
	}
	policy, ok, errPolicy := ParseQuotaReservePolicy(auth.Metadata)
	if !ok || errPolicy != nil {
		return QuotaReserveDecision{}, false
	}
	reading, okReading := weeklyQuotaReading(auth.Provider, auth.Quota, now)
	if !okReading {
		return QuotaReserveDecision{Reason: "weekly_quota_unknown"}, true
	}
	return EvaluateQuotaReserve(policy, reading, now), true
}

// logQuotaReserveTransition records when a fresh observation moves an opted-in
// credential into or out of the guard, so skips are visible without per-request noise.
func logQuotaReserveTransition(auth *Auth, wasExcluded bool, now time.Time) {
	decision, ok := quotaReserveDecisionForAuth(auth, now)
	if !ok || decision.Excluded == wasExcluded {
		return
	}
	fields := log.Fields{
		"auth_id":          auth.ID,
		"provider":         auth.Provider,
		"reason":           decision.Reason,
		"weekly_remaining": fmt.Sprintf("%.1f%%", decision.Remaining),
	}
	if !decision.ResetAt.IsZero() {
		fields["weekly_reset_at"] = decision.ResetAt.UTC().Format(time.RFC3339)
	}
	if decision.Excluded {
		fields["guard_recheck_at"] = decision.RecheckAt.UTC().Format(time.RFC3339)
		log.WithFields(fields).Info("quota guard: excluding credential from routing")
		return
	}
	log.WithFields(fields).Info("quota guard: credential eligible again")
}

// isQuotaReserveExcluded reports whether the guard removes the credential from
// routing, and when it should be rechecked.
func isQuotaReserveExcluded(auth *Auth, now time.Time) (bool, time.Time) {
	decision, ok := quotaReserveDecisionForAuth(auth, now)
	if !ok || !decision.Excluded {
		return false, time.Time{}
	}
	return true, decision.RecheckAt
}
