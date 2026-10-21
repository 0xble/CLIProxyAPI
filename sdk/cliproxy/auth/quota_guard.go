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

	quotaGuardFetchTimeout = 30 * time.Second
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

type quotaHTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

type QuotaGuard struct {
	mu         sync.RWMutex
	config     QuotaGuardConfig
	states     map[string]QuotaGuardState
	fetcher    quotaFetcher
	httpClient quotaHTTPClient
}

// NewQuotaGuard creates a guard using the default HTTP transport. Invalid
// configuration is disabled rather than partially applied; callers that need
// to reject configuration should use ValidateQuotaGuardConfig first.
func NewQuotaGuard(cfg internalconfig.QuotaGuardConfig) *QuotaGuard {
	guard, err := newQuotaGuard(cfg, nil)
	if err != nil {
		log.WithError(err).Warn("quota guard configuration disabled")
		return &QuotaGuard{config: QuotaGuardConfig{Mode: QuotaGuardModeOff}, states: make(map[string]QuotaGuardState)}
	}
	return guard
}

// NewQuotaGuardWithHTTPClient is the injectable constructor used by hosts and tests.
func NewQuotaGuardWithHTTPClient(cfg internalconfig.QuotaGuardConfig, client quotaHTTPClient) (*QuotaGuard, error) {
	return newQuotaGuard(cfg, client)
}

func newQuotaGuard(cfg internalconfig.QuotaGuardConfig, client quotaHTTPClient) (*QuotaGuard, error) {
	if err := ValidateQuotaGuardConfig(cfg); err != nil {
		return nil, err
	}
	mode := normalizeQuotaToken(cfg.Mode)
	if mode == "" {
		mode = QuotaGuardModeOff
	}
	poll := parseQuotaDuration(cfg.PollInterval, 5*time.Minute)
	maxAge := parseQuotaDuration(cfg.MaxAge, 15*time.Minute)
	guard := &QuotaGuard{
		config:     QuotaGuardConfig{Mode: mode, PollInterval: poll, MaxAge: maxAge, StateFile: expandQuotaPath(cfg.StateFile), Policies: make([]QuotaGuardPolicy, 0, len(cfg.Policies))},
		states:     make(map[string]QuotaGuardState),
		httpClient: client,
	}
	if guard.httpClient == nil {
		guard.httpClient = &http.Client{Transport: http.DefaultTransport}
	}
	for _, policy := range cfg.Policies {
		window := normalizeQuotaToken(policy.Window)
		if window == "" {
			window = QuotaGuardWindow7Day
		}
		guard.config.Policies = append(guard.config.Policies, QuotaGuardPolicy{
			ID: normalizeQuotaToken(policy.ID), Provider: normalizeQuotaToken(policy.Provider), AuthFile: normalizeQuotaPath(policy.AuthFile), Window: window,
			MaxUsedPercent: policy.MaxUsedPercent, AllowWithinReset: parseQuotaDuration(policy.AllowWithinReset, 2*time.Hour),
		})
	}
	guard.fetcher = func(ctx context.Context, auth *Auth) (QuotaReading, error) {
		return fetchClaudeQuotaWithClient(ctx, auth, guard.httpClient)
	}
	if err := guard.loadState(); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.WithError(err).Warn("failed to load quota guard state")
	}
	return guard, nil
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
	for i := range cfg.Policies {
		cfg.Policies[i] = normalizePolicy(cfg.Policies[i])
	}
	return &QuotaGuard{config: cfg, states: make(map[string]QuotaGuardState), fetcher: fetcher, httpClient: &http.Client{Transport: http.DefaultTransport}}
}

// ValidateQuotaGuardConfig rejects ambiguous or unsafe policy definitions before
// a reload can start a poller with behavior different from the operator's intent.
func ValidateQuotaGuardConfig(cfg internalconfig.QuotaGuardConfig) error {
	mode := normalizeQuotaToken(cfg.Mode)
	if mode != "" && mode != QuotaGuardModeOff && mode != QuotaGuardModeShadow && mode != QuotaGuardModeActive {
		return fmt.Errorf("quota guard mode %q is invalid", cfg.Mode)
	}
	if cfg.PollInterval != "" && parseQuotaDuration(cfg.PollInterval, 0) <= 0 {
		return fmt.Errorf("quota guard poll-interval %q is invalid", cfg.PollInterval)
	}
	if cfg.MaxAge != "" && parseQuotaDuration(cfg.MaxAge, 0) <= 0 {
		return fmt.Errorf("quota guard max-age %q is invalid", cfg.MaxAge)
	}
	seen := make(map[string]struct{}, len(cfg.Policies))
	for i, policy := range cfg.Policies {
		window := normalizeQuotaToken(policy.Window)
		if window != "" && window != QuotaGuardWindow7Day {
			return fmt.Errorf("quota guard policy %d window %q is invalid", i, policy.Window)
		}
		if policy.MaxUsedPercent <= 0 || policy.MaxUsedPercent > 100 {
			return fmt.Errorf("quota guard policy %d max-used-percent must be > 0 and <= 100", i)
		}
		if policy.AllowWithinReset != "" && parseQuotaDuration(policy.AllowWithinReset, 0) <= 0 {
			return fmt.Errorf("quota guard policy %d allow-within-reset %q is invalid", i, policy.AllowWithinReset)
		}
		id, provider, authFile := normalizeQuotaToken(policy.ID), normalizeQuotaToken(policy.Provider), normalizeQuotaPath(policy.AuthFile)
		if id == "" && provider == "" && authFile == "" {
			return fmt.Errorf("quota guard policy %d must identify an auth by id, provider, or auth-file", i)
		}
		key := strings.Join([]string{id, provider, authFile}, "\x00")
		if _, exists := seen[key]; exists {
			return fmt.Errorf("quota guard policy %d duplicates an earlier policy", i)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func normalizePolicy(policy QuotaGuardPolicy) QuotaGuardPolicy {
	policy.ID = normalizeQuotaToken(policy.ID)
	policy.Provider = normalizeQuotaToken(policy.Provider)
	policy.AuthFile = normalizeQuotaPath(policy.AuthFile)
	policy.Window = normalizeQuotaToken(policy.Window)
	if policy.Window == "" {
		policy.Window = QuotaGuardWindow7Day
	}
	return policy
}

func EvaluateQuotaPolicy(policy QuotaGuardPolicy, reading *QuotaReading, now time.Time) (QuotaDecision, string) {
	policy = normalizePolicy(policy)
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

// Attach is retained for package-level tests and legacy callers. Manager-owned
// snapshots should use SetQuotaGuard so registration and updates cannot lose it.
func (g *QuotaGuard) Attach(auth *Auth) {
	if g != nil && auth != nil {
		auth.quotaGuard = g
	}
}

func (g *QuotaGuard) PolicyFor(auth *Auth) (QuotaGuardPolicy, bool) {
	if g == nil || auth == nil {
		return QuotaGuardPolicy{}, false
	}
	authID := normalizeQuotaToken(auth.ID)
	provider := normalizeQuotaToken(auth.Provider)
	authFile := normalizeQuotaPath(auth.FileName)
	g.mu.RLock()
	defer g.mu.RUnlock()
	for _, policy := range g.config.Policies {
		if policy.ID != "" && policy.ID != authID {
			continue
		}
		if policy.Provider != "" && policy.Provider != provider {
			continue
		}
		if policy.AuthFile != "" && policy.AuthFile != authFile {
			continue
		}
		return policy, true
	}
	return QuotaGuardPolicy{}, false
}

func (g *QuotaGuard) IsBlocked(auth *Auth, now time.Time) bool {
	if g == nil || auth == nil || strings.EqualFold(g.config.Mode, QuotaGuardModeOff) || strings.EqualFold(g.config.Mode, QuotaGuardModeShadow) {
		return false
	}
	if _, ok := g.PolicyFor(auth); !ok {
		return false
	}
	g.mu.RLock()
	state, exists := g.states[auth.ID]
	maxAge := g.config.MaxAge
	g.mu.RUnlock()
	if !exists || state.Decision == QuotaDecisionUnknown || state.ObservedAt.IsZero() || now.Before(state.ObservedAt) || now.Sub(state.ObservedAt) > maxAge {
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
		checkedAt := time.Now().UTC()
		state := QuotaGuardState{AuthID: auth.ID, AuthFile: auth.FileName, Provider: auth.Provider, Decision: QuotaDecisionUnknown, CheckedAt: checkedAt}
		fetchCtx, cancel := context.WithTimeout(ctx, quotaGuardFetchTimeout)
		reading, errFetch := g.fetcher(fetchCtx, auth)
		cancel()
		if errFetch != nil {
			state.Error = sanitizeQuotaError(errFetch)
			g.mu.Lock()
			if previous, ok := g.states[auth.ID]; ok && previous.Decision != QuotaDecisionUnknown && previous.ObservedAt != (time.Time{}) && checkedAt.Sub(previous.ObservedAt) >= 0 && checkedAt.Sub(previous.ObservedAt) <= g.config.MaxAge {
				state = previous
				state.CheckedAt = checkedAt
				state.Error = sanitizeQuotaError(errFetch)
			}
			g.states[auth.ID] = state
			g.mu.Unlock()
			log.WithFields(log.Fields{"auth_id": auth.ID, "auth_file": auth.FileName, "decision": state.Decision, "reason": state.Reason}).Warn("quota guard usage read failed")
			continue
		}
		reading.ObservedAt = checkedAt
		decision, reason := EvaluateQuotaPolicy(policy, &reading, checkedAt)
		used := reading.UsedPercent
		reset := reading.ResetAt
		state.Decision, state.Reason, state.UsedPercent, state.ResetAt, state.ObservedAt = decision, reason, &used, &reset, checkedAt
		g.mu.Lock()
		g.states[auth.ID] = state
		g.mu.Unlock()
		log.WithFields(log.Fields{"auth_id": auth.ID, "auth_file": auth.FileName, "decision": decision, "reason": reason, "used_percent": used, "reset_at": reset}).Info("quota guard decision")
	}
	return g.persistState()
}

// Start runs exactly one poller for this guard. Manager owns cancellation and
// replaces the lifetime on configuration reload; Home dispatch is deliberately
// excluded because it selects remotely and never receives local auth snapshots.
func (g *QuotaGuard) Start(ctx context.Context, manager *Manager) {
	if g == nil || manager == nil || strings.EqualFold(g.config.Mode, QuotaGuardModeOff) {
		return
	}
	if ctx == nil {
		ctx = context.Background()
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

func (g *QuotaGuard) loadState() error {
	if g == nil || g.config.StateFile == "" {
		return nil
	}
	info, errStat := os.Lstat(g.config.StateFile)
	if errStat != nil {
		return errStat
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("quota guard state file is a symlink")
	}
	data, errRead := os.ReadFile(g.config.StateFile)
	if errRead != nil {
		return errRead
	}
	var states map[string]QuotaGuardState
	if errUnmarshal := json.Unmarshal(data, &states); errUnmarshal != nil {
		return fmt.Errorf("decode quota guard state: %w", errUnmarshal)
	}
	g.mu.Lock()
	for id, state := range states {
		if strings.TrimSpace(id) == "" || state.AuthID != "" && state.AuthID != id {
			continue
		}
		if state.AuthID == "" {
			state.AuthID = id
		}
		g.states[id] = state
	}
	g.mu.Unlock()
	return nil
}

func (g *QuotaGuard) persistState() error {
	if g == nil || g.config.StateFile == "" {
		return nil
	}
	data, errMarshal := json.MarshalIndent(g.StateSnapshot(), "", "  ")
	if errMarshal != nil {
		return errMarshal
	}
	path := g.config.StateFile
	if errMkdir := os.MkdirAll(filepath.Dir(path), 0o700); errMkdir != nil {
		return errMkdir
	}
	tmp, errCreate := os.CreateTemp(filepath.Dir(path), ".quota-guard-*.tmp")
	if errCreate != nil {
		return errCreate
	}
	name := tmp.Name()
	defer os.Remove(name)
	if errChmod := tmp.Chmod(0o600); errChmod != nil {
		_ = tmp.Close()
		return errChmod
	}
	if _, errWrite := tmp.Write(data); errWrite != nil {
		_ = tmp.Close()
		return errWrite
	}
	if errSync := tmp.Sync(); errSync != nil {
		_ = tmp.Close()
		return errSync
	}
	if errClose := tmp.Close(); errClose != nil {
		return errClose
	}
	if errRename := os.Rename(name, path); errRename != nil {
		return errRename
	}
	if errChmod := os.Chmod(path, 0o600); errChmod != nil {
		return errChmod
	}
	if dir, errOpen := os.Open(filepath.Dir(path)); errOpen == nil {
		defer dir.Close()
		_ = dir.Sync()
	}
	return nil
}

func fetchClaudeQuota(ctx context.Context, auth *Auth) (QuotaReading, error) {
	return fetchClaudeQuotaWithClient(ctx, auth, &http.Client{Transport: http.DefaultTransport})
}

func fetchClaudeQuotaWithClient(ctx context.Context, auth *Auth, client quotaHTTPClient) (QuotaReading, error) {
	if auth == nil || !strings.EqualFold(auth.Provider, "claude") {
		return QuotaReading{}, errors.New("unsupported provider")
	}
	token, ok := auth.Metadata["access_token"].(string)
	if !ok || strings.TrimSpace(token) == "" {
		return QuotaReading{}, errors.New("missing access token")
	}
	if client == nil {
		client = &http.Client{Transport: http.DefaultTransport}
	}
	req, errRequest := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.anthropic.com/api/oauth/usage", nil)
	if errRequest != nil {
		return QuotaReading{}, errRequest
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, errDo := client.Do(req)
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

func normalizeQuotaToken(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizeQuotaPath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	value = expandQuotaPath(value)
	clean := filepath.Clean(value)
	if abs, errAbs := filepath.Abs(clean); errAbs == nil {
		return filepath.Clean(abs)
	}
	return clean
}

func sanitizeQuotaError(err error) string {
	if err == nil {
		return ""
	}
	return strings.ReplaceAll(err.Error(), "Bearer ", "Bearer [REDACTED]")
}
