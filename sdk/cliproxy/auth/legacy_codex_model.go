package auth

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
)

const (
	legacyCodexAstra  = "gpt-6-astra"
	currentCodexAstra = "gpt-6.2-astra"
)

// Warn for the supported legacy name only, based on registered routes rather
// than transient eligibility (cooldown, quota, priority or session affinity).
// Intentional API-key use remains allowed and we never change the request.
func (m *Manager) warnLegacyCodexAPIKeyRoute(ctx context.Context, providers []string, model string) {
	model = canonicalModelKey(model)
	if !strings.EqualFold(model, legacyCodexAstra) || !m.localExecutionAllowed() {
		return
	}
	now := time.Now().UnixNano()
	last := m.lastLegacyCodexWarning.Load()
	if last != 0 && now-last < int64(time.Minute) {
		return
	}
	apiKeyOnly, replacementOnOAuth := m.legacyCodexRouteStatus(providers, model)
	if !apiKeyOnly || !m.lastLegacyCodexWarning.CompareAndSwap(last, now) {
		return
	}
	entry := logEntryWithRequestID(ctx).WithField("model", legacyCodexAstra)
	if replacementOnOAuth {
		entry = entry.WithField("replacement_model", currentCodexAstra)
	}
	entry.Warn("legacy Codex model is routed only by API keys")
}

func (m *Manager) legacyCodexRouteStatus(providers []string, model string) (apiKeyOnly, replacementOnOAuth bool) {
	reg := registry.GetGlobalRegistry()
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, candidate := range m.auths {
		if candidate == nil || candidate.Disabled || candidate.Status == StatusDisabled {
			continue
		}
		provider := executorKeyFromAuth(candidate)
		if _, ok := m.executorLocked(provider); !ok {
			continue
		}
		kind := candidate.AuthKind()
		if slices.Contains(providers, provider) && m.authSupportsRouteModel(reg, candidate, model) {
			if kind != AuthKindAPIKey {
				return false, false
			}
			apiKeyOnly = true
		}
		if provider == "codex" && kind == AuthKindOAuth && m.authSupportsRouteModel(reg, candidate, currentCodexAstra) {
			replacementOnOAuth = true
		}
	}
	return apiKeyOnly, replacementOnOAuth
}
