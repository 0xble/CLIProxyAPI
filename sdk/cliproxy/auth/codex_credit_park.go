package auth

import (
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/MoeForge/moego/ojson"
	log "github.com/sirupsen/logrus"
)

const (
	AttributeCodexCreditResetDay = "codex_credit_reset_day"
	CodexCreditParkReason        = "credit_balance_exhausted"
)

type creditParkState struct {
	Grant      string    `json:"grant"`
	ResetDay   int       `json:"reset_day"`
	ObservedAt time.Time `json:"observed_at"`
	Until      time.Time `json:"until"`
}

func equalCreditPark(a, b *creditParkState) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Grant == b.Grant && a.ResetDay == b.ResetDay && a.ObservedAt.Equal(b.ObservedAt) && a.Until.Equal(b.Until)
}

// CodexCreditResetDay returns the configured UTC reset day, or zero without opt-in.
func (a *Auth) CodexCreditResetDay() int {
	if a == nil || !strings.EqualFold(a.Provider, "codex") || authAttribute(a, AttributeCodexCreditResetDay) == "" || a.AuthKind() != AuthKindAPIKey || authAttribute(a, AttributeAPIKey) == "" || authHasOAuthMetadata(a) {
		return 0
	}
	day, err := strconv.Atoi(authAttribute(a, AttributeCodexCreditResetDay))
	if err != nil || day < 1 || day > 31 {
		return 0
	}
	return day
}

// CodexCreditParkedUntil reports a currently active credential-wide credit park.
func (a *Auth) CodexCreditParkedUntil(now time.Time) time.Time {
	if day := a.CodexCreditResetDay(); day != 0 && a.creditPark.ResetDay == day && a.creditPark.Until.After(now) {
		return a.creditPark.Until
	}
	return time.Time{}
}

func nextCreditReset(now time.Time, day int) time.Time {
	year, month, _ := now.UTC().Date()
	reset := func(month time.Month) time.Time {
		lastDay := time.Date(year, month+1, 0, 0, 0, 0, 0, time.UTC).Day()
		return time.Date(year, month, min(day, lastDay), 0, 0, 0, 0, time.UTC)
	}
	if until := reset(month); until.After(now) {
		return until
	}
	return reset(month + 1)
}

func (a *Auth) parkOnCreditExhaustion(result Result, now time.Time) (matched, started bool) {
	if result.Success || a.Disabled || a.Status == StatusDisabled || !strings.EqualFold(result.Provider, "codex") || !codexAPIKeyExhausted(result.Error) {
		return false, false
	}
	day := a.CodexCreditResetDay()
	if day == 0 {
		return false, false
	}
	if a.CodexCreditParkedUntil(now).IsZero() {
		a.creditPark = creditParkState{Grant: AuthGrantFingerprint(a), ResetDay: day, ObservedAt: now.UTC(), Until: nextCreditReset(now, day)}
		return true, true
	}
	return true, false
}

func codexAPIKeyExhausted(err *Error) bool {
	if err == nil || (err.HTTPStatus != http.StatusTooManyRequests && err.HTTPStatus != http.StatusPaymentRequired && err.HTTPStatus != http.StatusForbidden && err.HTTPStatus != http.StatusBadRequest) {
		return false
	}
	isExhausted := func(code string) bool {
		return code == CodexCreditParkReason || code == "insufficient_quota"
	}
	if isExhausted(err.Code) {
		return true
	}
	for _, path := range []string{"error.code", "error.type"} {
		if isExhausted(ojson.GetBytesNoCopy([]byte(err.Message), path).String()) {
			return true
		}
	}
	return false
}

// ApplyVerifiedCodexCreditBalance releases an active park after a trusted balance
// reader observes a positive, spendable balance for this exact credential. Pass
// the auth snapshot used by the reader and its observation time, not request
// headers or inferred quota. No upstream request is made here.
func (m *Manager) ApplyVerifiedCodexCreditBalance(snapshot *Auth, balance float64, observedAt time.Time) bool {
	if m == nil || snapshot == nil || !(balance > 0) || math.IsInf(balance, 0) || observedAt.IsZero() {
		return false
	}
	releaseMutation := m.lockAuthMutation(snapshot.ID)
	defer releaseMutation()
	m.mu.Lock()
	now := time.Now()
	a := m.auths[snapshot.ID]
	if a.CodexCreditParkedUntil(now).IsZero() || a.Disabled || a.Status == StatusDisabled ||
		a.RegistrationEpoch != snapshot.RegistrationEpoch || a.CredentialVersion != snapshot.CredentialVersion ||
		!observedAt.After(a.creditPark.ObservedAt) || observedAt.After(now) {
		m.mu.Unlock()
		return false
	}
	// Retain the observation watermark in memory so an in-flight state load
	// cannot resurrect the older park after it has been cleared.
	a.creditPark = creditParkState{ObservedAt: observedAt}
	a.Generation++
	a.UpdatedAt = now
	released := a.Clone()
	m.mu.Unlock()
	releaseMutation()
	if m.scheduler != nil {
		m.scheduler.upsertAuthResult(released, nil, true)
	}
	m.persistCooldownStates(nil)
	m.projectAuthModels(released, now)
	log.WithField("auth_id", released.ID).Info("Codex API key unparked after verified credit balance")
	return true
}
