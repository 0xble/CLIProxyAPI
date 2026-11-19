package auth

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
)

func TestClaudeQuotaWithoutTrustedResetRechecksWithBoundedBackoff(t *testing.T) {
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	headers := http.Header{}
	headers.Set("Anthropic-Ratelimit-Unified-Status", "rejected")
	headers.Set("Anthropic-Ratelimit-Unified-Reset", now.Add(6*24*time.Hour).Format(time.RFC3339))
	auth := &Auth{Provider: "claude", Status: StatusActive}
	errQuota := &Error{HTTPStatus: http.StatusTooManyRequests}

	applyAuthFailureState(auth, errQuota, nil, 0, now, false, headers)
	first := now.Add(15 * time.Minute)
	if !auth.NextRetryAfter.Equal(first) || auth.Quota.BackoffLevel != 1 {
		t.Fatalf("first cooldown = %v (level %d), want %v (level 1)", auth.NextRetryAfter, auth.Quota.BackoffLevel, first)
	}
	applyAuthFailureState(auth, errQuota, nil, 0, now.Add(time.Minute), false, headers)
	if !auth.NextRetryAfter.Equal(first) || auth.Quota.BackoffLevel != 1 {
		t.Fatalf("in-flight 429 extended the live cooldown: %+v", auth.Quota)
	}
	for _, at := range []time.Time{first, first.Add(30 * time.Minute), first.Add(time.Hour)} {
		if blocked, _, next := isAuthBlockedForModel(auth, "", at); blocked {
			t.Fatalf("normal selection still blocked at %v (next: %v)", at, next)
		}
		applyAuthFailureState(auth, errQuota, nil, 0, at, false, headers)
		if want := at.Add(30 * time.Minute); !auth.NextRetryAfter.Equal(want) {
			t.Fatalf("repeated cooldown = %v, want %v", auth.NextRetryAfter, want)
		}
	}
}

func TestClaudeQuotaRecoveryUsesFallbackOnlyWithoutTrustedReset(t *testing.T) {
	withQuotaCooldownEnabled(t)
	const model = "claude-recovery-test"
	for _, tc := range []struct {
		name             string
		credentialScoped bool
		hint             *time.Duration
		want             time.Duration
	}{
		{name: "model fallback", want: 15 * time.Minute},
		{name: "credential fallback", credentialScoped: true, want: 15 * time.Minute},
		{name: "credential authoritative reset", credentialScoped: true, hint: new(6 * 24 * time.Hour), want: 6 * 24 * time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := logging.WithResponseHeadersHolder(context.Background())
			headers := http.Header{}
			headers.Set("Anthropic-Ratelimit-Unified-Status", "rejected")
			logging.SetResponseHeaders(ctx, headers)
			manager := NewManager(nil, nil, nil)
			id := "claude-recovery"
			if _, errRegister := manager.Register(ctx, &Auth{ID: id, Provider: "claude", Status: StatusActive}); errRegister != nil {
				t.Fatal(errRegister)
			}
			before := time.Now().Round(0)
			manager.MarkResult(ctx, Result{AuthID: id, Provider: "claude", Model: model, CredentialScope: tc.credentialScoped, RetryAfter: tc.hint, Error: &Error{HTTPStatus: http.StatusTooManyRequests}})
			after := time.Now().Round(0)
			auth, _ := manager.GetByID(id)
			state := auth.ModelStates[model]
			if state == nil {
				t.Fatal("model state not recorded")
			}
			got := state.Quota.NextRecoverAt
			if got.Before(before.Add(tc.want)) || got.After(after.Add(tc.want)) {
				t.Fatalf("model recovery = %v, want %v after failure", got, tc.want)
			}
			if tc.credentialScoped && (auth.Quota.Reason != "credential_quota" || !auth.Quota.NextRecoverAt.Equal(got)) {
				t.Fatalf("credential cooldown not recorded: %+v", auth.Quota)
			}
			if !tc.credentialScoped && auth.Quota.Reason == "credential_quota" {
				t.Fatalf("model fallback cooled the credential: %+v", auth.Quota)
			}
		})
	}
}
