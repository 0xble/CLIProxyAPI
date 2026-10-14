package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	log "github.com/sirupsen/logrus"
)

const (
	QuotaGuardModeOff    = "off"
	QuotaGuardModeShadow = "shadow"
	QuotaGuardModeActive = "active"
	QuotaGuardWindow7Day = "seven_day"
)

type QuotaGuardPolicy struct {
	ID               string
	Provider         string
	AuthFile         string
	Window           string
	MaxUsedPercent   float64
	AllowWithinReset time.Duration
}

type QuotaGuardConfig struct {
	Mode         string
	PollInterval time.Duration
	MaxAge       time.Duration
	StateFile    string
	Policies     []QuotaGuardPolicy
}

type QuotaReading struct {
	UsedPercent float64   `json:"used_percent"`
	ResetAt     time.Time `json:"reset_at"`
	ObservedAt  time.Time `json:"observed_at"`
}

type QuotaDecision string

const (
	QuotaDecisionUnknown  QuotaDecision = "unknown"
	QuotaDecisionEligible QuotaDecision = "eligible"
	QuotaDecisionExcluded QuotaDecision = "excluded"
)

type QuotaGuardState struct {
	AuthID      string        `json:"auth_id"`
	AuthFile    string        `json:"auth_file"`
	Provider    string        `json:"provider"`
	Decision    QuotaDecision `json:"decision"`
	Reason      string        `json:"reason"`
	UsedPercent *float64      `json:"used_percent,omitempty"`
	ResetAt     *time.Time    `json:"reset_at,omitempty"`
	ObservedAt  time.Time     `json:"observed_at,omitempty"`
	CheckedAt   time.Time     `json:"checked_at"`
	Error       string        `json:"error,omitempty"`
}

type quotaFetcher func(context.Context, *Auth) (QuotaReading, error)

type QuotaGuard struct {
	mu      sync.RWMutex
	config  QuotaGuardConfig
	states  map[string]QuotaGuardState
	fetcher quotaFetcher
}

func NewQuotaGuard(cfg internalconfig.QuotaGuardConfig) *QuotaGuard {
	poll := parseQuotaDuration(cfg.PollInterval, 5*time.Minute)
	maxAge := parseQuotaDuration(cfg.MaxAge, 15*time.Minute)
	guard := &QuotaGuard{
		config: QuotaGuardConfig{Mode: strings.ToLower(strings.TrimSpace(cfg.Mode)), PollInterval: poll, MaxAge: maxAge, StateFile: expandQuotaPath(cfg.StateFile), Policies: make([]QuotaGuardPolicy, 0, len(cfg.Policies))},
		states: make(map[string]QuotaGuardState),
	}
	if guard.config.Mode == "" {
		guard.config.Mode = QuotaGuardModeOff
	}
	for _, policy := range cfg.Policies {
		guard.config.Policies = append(guard.config.Policies, QuotaGuardPolicy{
			ID: policy.ID, Provider: policy.Provider, AuthFile: policy.AuthFile, Window: policy.Window,
			MaxUsedPercent: policy.MaxUsedPercent, AllowWithinReset: parseQuotaDuration(policy.AllowWithinReset, 2*time.Hour),
		})
	}
	guard.fetcher = fetchClaudeQuota
	return guard
}

func NewQuotaGuardForTest(cfg QuotaGuardConfig, fetcher quotaFetcher) *QuotaGuard {
	if cfg.Mode == "" {
		cfg.Mode = QuotaGuardModeActive
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = time.Hour
	}
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = 15 * time.Minute
	}
	if fetcher == nil {
		fetcher = fetchClaudeQuota
	}
	return &QuotaGuard{config: cfg, states: make(map[string]QuotaGuardState), fetcher: fetcher}
}

func EvaluateQuotaPolicy(policy QuotaGuardPolicy, reading *QuotaReading, now time.Time) (QuotaDecision, string) {
	if policy.Window != "" && policy.Window != QuotaGuardWindow7Day {
		return QuotaDecisionUnknown, "unsupported_window"
	}
	if policy.MaxUsedPercent <= 0 || policy.MaxUsedPercent > 100 {
		return QuotaDecisionUnknown, "invalid_threshold"
	}
	if reading == nil || reading.ObservedAt.IsZero() || reading.ResetAt.IsZero() || reading.UsedPercent < 0 || reading.UsedPercent > 100 {
		return QuotaDecisionUnknown, "missing_or_invalid_quota"
	}
	if reading.UsedPercent < policy.MaxUsedPercent {
		return QuotaDecisionEligible, "below_threshold"
	}
	if !reading.ResetAt.Before(now) && reading.ResetAt.Sub(now) <= policy.AllowWithinReset {
		return QuotaDecisionEligible, "reset_within_bypass_window"
	}
	return QuotaDecisionExcluded, "threshold_reached_reset_outside_window"
}

func (g *QuotaGuard) Attach(auth *Auth) {
	if g != nil && auth != nil {
		auth.quotaGuard = g
	}
}

func (g *QuotaGuard) PolicyFor(auth *Auth) (QuotaGuardPolicy, bool) {
	if g == nil || auth == nil {
		return QuotaGuardPolicy{}, false
	}
	for _, policy := range g.config.Policies {
		if policy.Provider != "" && !strings.EqualFold(policy.Provider, auth.Provider) {
			continue
		}
		if policy.AuthFile != "" && policy.AuthFile != auth.FileName {
			continue
		}
		return policy, true
	}
	return QuotaGuardPolicy{}, false
}

func (g *QuotaGuard) IsBlocked(auth *Auth, now time.Time) bool {
	if g == nil || strings.EqualFold(g.config.Mode, QuotaGuardModeOff) || strings.EqualFold(g.config.Mode, QuotaGuardModeShadow) {
		return false
	}
	if _, ok := g.PolicyFor(auth); !ok {
		return false
	}
	g.mu.RLock()
	state, exists := g.states[auth.ID]
	g.mu.RUnlock()
	if !exists || state.Decision == QuotaDecisionUnknown || state.ObservedAt.IsZero() || now.Sub(state.ObservedAt) > g.config.MaxAge {
		return true
	}
	return state.Decision == QuotaDecisionExcluded
}

func (g *QuotaGuard) StateSnapshot() map[string]QuotaGuardState {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make(map[string]QuotaGuardState, len(g.states))
	for id, state := range g.states {
		out[id] = state
	}
	return out
}

func (g *QuotaGuard) PollOnce(ctx context.Context, manager *Manager) error {
	if g == nil || manager == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for _, auth := range manager.List() {
		policy, managed := g.PolicyFor(auth)
		if !managed {
			continue
		}
		state := QuotaGuardState{AuthID: auth.ID, AuthFile: auth.FileName, Provider: auth.Provider, Decision: QuotaDecisionUnknown, CheckedAt: time.Now().UTC()}
		reading, errFetch := g.fetcher(ctx, auth)
		if errFetch != nil {
			state.Error = sanitizeQuotaError(errFetch)
			g.mu.Lock()
			if previous, ok := g.states[auth.ID]; ok && previous.Decision != QuotaDecisionUnknown && time.Since(previous.ObservedAt) <= g.config.MaxAge {
				state = previous
				state.CheckedAt = time.Now().UTC()
				state.Error = sanitizeQuotaError(errFetch)
			}
			g.states[auth.ID] = state
			g.mu.Unlock()
			log.WithFields(log.Fields{"auth_id": auth.ID, "auth_file": auth.FileName, "decision": state.Decision, "reason": state.Reason}).Warn("quota guard usage read failed")
			continue
		}
		reading.ObservedAt = time.Now().UTC()
		decision, reason := EvaluateQuotaPolicy(policy, &reading, reading.ObservedAt)
		used := reading.UsedPercent
		reset := reading.ResetAt
		state.Decision, state.Reason, state.UsedPercent, state.ResetAt, state.ObservedAt = decision, reason, &used, &reset, reading.ObservedAt
		g.mu.Lock()
		g.states[auth.ID] = state
		g.mu.Unlock()
		log.WithFields(log.Fields{"auth_id": auth.ID, "auth_file": auth.FileName, "decision": decision, "reason": reason, "used_percent": used, "reset_at": reset}).Info("quota guard decision")
	}
	return g.persistState()
}

func (g *QuotaGuard) Start(ctx context.Context, manager *Manager) {
	if g == nil || manager == nil || strings.EqualFold(g.config.Mode, QuotaGuardModeOff) {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for _, auth := range manager.List() {
		g.Attach(auth)
	}
	go func() {
		_ = g.PollOnce(ctx, manager)
		ticker := time.NewTicker(g.config.PollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = g.PollOnce(ctx, manager)
			}
		}
	}()
}

func (g *QuotaGuard) persistState() error {
	if g == nil || g.config.StateFile == "" {
		return nil
	}
	data, errMarshal := json.MarshalIndent(g.StateSnapshot(), "", "  ")
	if errMarshal != nil {
		return errMarshal
	}
	if errMkdir := os.MkdirAll(filepath.Dir(g.config.StateFile), 0o700); errMkdir != nil {
		return errMkdir
	}
	tmp, errCreate := os.CreateTemp(filepath.Dir(g.config.StateFile), ".quota-guard-*.tmp")
	if errCreate != nil {
		return errCreate
	}
	name := tmp.Name()
	defer os.Remove(name)
	if errWrite := tmp.Chmod(0o600); errWrite != nil {
		_ = tmp.Close()
		return errWrite
	}
	if _, errWrite := tmp.Write(data); errWrite != nil {
		_ = tmp.Close()
		return errWrite
	}
	if errClose := tmp.Close(); errClose != nil {
		return errClose
	}
	return os.Rename(name, g.config.StateFile)
}

func fetchClaudeQuota(ctx context.Context, auth *Auth) (QuotaReading, error) {
	if auth == nil || !strings.EqualFold(auth.Provider, "claude") {
		return QuotaReading{}, errors.New("unsupported provider")
	}
	token, ok := auth.Metadata["access_token"].(string)
	if !ok || strings.TrimSpace(token) == "" {
		return QuotaReading{}, errors.New("missing access token")
	}
	req, errRequest := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.anthropic.com/api/oauth/usage", nil)
	if errRequest != nil {
		return QuotaReading{}, errRequest
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, errDo := (&http.Client{}).Do(req)
	if errDo != nil {
		return QuotaReading{}, errDo
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return QuotaReading{}, fmt.Errorf("usage endpoint status %d", resp.StatusCode)
	}
	var payload struct {
		SevenDay struct {
			Utilization *float64 `json:"utilization"`
			ResetsAt    string   `json:"resets_at"`
			ResetAt     string   `json:"reset_at"`
		} `json:"seven_day"`
	}
	if errDecode := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&payload); errDecode != nil {
		return QuotaReading{}, errDecode
	}
	if payload.SevenDay.Utilization == nil {
		return QuotaReading{}, errors.New("seven_day utilization missing")
	}
	resetText := payload.SevenDay.ResetsAt
	if resetText == "" {
		resetText = payload.SevenDay.ResetAt
	}
	reset, errParse := time.Parse(time.RFC3339, resetText)
	if errParse != nil {
		return QuotaReading{}, errors.New("seven_day reset missing or invalid")
	}
	return QuotaReading{UsedPercent: *payload.SevenDay.Utilization, ResetAt: reset.UTC(), ObservedAt: time.Now().UTC()}, nil
}

func parseQuotaDuration(value string, fallback time.Duration) time.Duration {
	if parsed, err := time.ParseDuration(strings.TrimSpace(value)); err == nil && parsed > 0 {
		return parsed
	}
	return fallback
}
func expandQuotaPath(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, value[2:])
		}
	}
	return value
}
func sanitizeQuotaError(err error) string {
	if err == nil {
		return ""
	}
	return strings.ReplaceAll(err.Error(), "Bearer ", "Bearer [REDACTED]")
}
