package auth

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestManager_ClaudeRefreshTokenExpired(t *testing.T) {
	for _, tc := range []struct {
		name     string
		message  string
		terminal bool
	}{
		{
			name:     "expired refresh token description",
			message:  `token refresh failed with status 400: {"error":"invalid_grant","error_description":"Refresh token expired"}`,
			terminal: true,
		},
		{
			name:     "case insensitive expired refresh token description",
			message:  `token refresh failed with status 400: {"error":"invalid_grant","error_description":"REFRESH TOKEN EXPIRED"}`,
			terminal: true,
		},
		{
			name:     "existing expired refresh token code",
			message:  `token refresh failed with status 400: {"error":"invalid_grant","code":"refresh_token_expired"}`,
			terminal: true,
		},
		{
			name:    "generic invalid grant remains retryable",
			message: `token refresh failed with status 400: {"error":"invalid_grant","error_description":"Bad Request"}`,
		},
		{
			name:    "access token expiry does not imply expired refresh token",
			message: `token refresh failed with status 400: {"error":"invalid_grant","error_description":"Access token expired"}`,
		},
		{
			name:    "transient server error remains retryable",
			message: `token refresh failed with status 503: service unavailable`,
		},
	} {
		for _, accessValid := range []bool{false, true} {
			accessState := "expired access token"
			if accessValid {
				accessState = "unexpired access token"
			}
			t.Run(tc.name+"/"+accessState, func(t *testing.T) {
				ctx := WithSkipPersist(context.Background())
				now := time.Now().UTC()
				expiry := now.Add(-time.Hour).Truncate(time.Second)
				if accessValid {
					expiry = now.Add(24 * time.Hour).Truncate(time.Second)
				}
				credential := &Auth{
					ID:       "claude-refresh-expired.json",
					Provider: "claude",
					Status:   StatusActive,
					Metadata: map[string]any{
						"access_token":  "test-access-token",
						"refresh_token": "test-refresh-token",
						"expired":       expiry.Format(time.RFC3339),
					},
				}
				executor := &mockOAuthErrorExecutor{id: "claude", errToReturn: errors.New(tc.message)}
				manager := NewManager(nil, nil, nil)
				manager.RegisterExecutor(executor)
				if _, errReg := manager.Register(ctx, credential); errReg != nil {
					t.Fatalf("Register: %v", errReg)
				}

				manager.refreshAuth(ctx, credential.ID)
				current, ok := manager.GetByID(credential.ID)
				if !ok || current == nil {
					t.Fatal("credential missing after refresh failure")
				}
				if current.RequiresSignIn != tc.terminal {
					t.Fatalf("RequiresSignIn = %v, want %v", current.RequiresSignIn, tc.terminal)
				}
				if current.RefreshError == nil || current.RefreshError.Retryable == tc.terminal {
					t.Fatalf("RefreshError = %+v, want retryable=%v", current.RefreshError, !tc.terminal)
				}
				if executor.refreshCalls.Load() != 1 {
					t.Fatalf("Refresh calls = %d, want 1", executor.refreshCalls.Load())
				}
				if !tc.terminal {
					if current.RenewalStateAt(now) != RenewalStateRetryScheduled || !current.NextRefreshAfter.After(now) {
						t.Fatalf("transient failure must schedule retry: state=%q next=%v", current.RenewalStateAt(now), current.NextRefreshAfter)
					}
					if current.RejectedRefreshToken != "" {
						t.Fatal("retryable failure rejected refresh token")
					}
					return
				}
				if current.RejectedRefreshToken != "test-refresh-token" {
					t.Fatal("terminal failure did not mark the unchanged refresh token as rejected")
				}
				if accessValid {
					if current.Unavailable || current.Status != StatusActive || current.RenewalStateAt(now) != RenewalStateSignInRequired {
						t.Fatalf("unexpired access token must remain active but require sign-in: %+v", current)
					}
					if !current.NextRefreshAfter.Equal(expiry) {
						t.Fatalf("NextRefreshAfter = %v, want access expiry %v rather than grant retry", current.NextRefreshAfter, expiry)
					}
				} else {
					if !current.Unavailable || current.Status != StatusError || current.RenewalStateAt(now) != RenewalStateExpiredSignInRequired {
						t.Fatalf("expired access token must be unavailable and require sign-in: %+v", current)
					}
					if next, scheduled := nextRefreshCheckAt(now, current, time.Minute); scheduled || !current.NextRefreshAfter.IsZero() {
						t.Fatalf("terminal credential scheduled another refresh: next=%v marker=%v", next, current.NextRefreshAfter)
					}
				}
				manager.refreshAuth(ctx, credential.ID)
				if executor.refreshCalls.Load() != 1 {
					t.Fatalf("unchanged expired refresh token retried: calls=%d", executor.refreshCalls.Load())
				}
			})
		}
	}
}
