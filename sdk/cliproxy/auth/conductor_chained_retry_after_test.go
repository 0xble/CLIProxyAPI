package auth

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestChainedCPAPoolCooldownKeepsShorterClientRetryAfter(t *testing.T) {
	for _, tc := range []struct {
		name   string
		marker string
		values []string
		want   string
	}{
		{name: "shorter chained hint", marker: logging.CPARetryAdviceHeader, values: []string{"17"}, want: "17"},
		{name: "older CPA with trace header", marker: logging.CPATraceIDHeader, values: []string{"17"}, want: "17"},
		{name: "local pool recovers first", marker: logging.CPARetryAdviceHeader, values: []string{"80"}, want: "44"},
		{name: "unmarked upstream", values: []string{"17"}, want: "44"},
		{name: "ambiguous header", marker: logging.CPARetryAdviceHeader, values: []string{"17", "21"}, want: "44"},
		{name: "invalid header", marker: logging.CPARetryAdviceHeader, values: []string{"-17"}, want: "44"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			credential := newIssue7521Auth("chained-retry-local")
			exec := &customStreamMockExecutor{identifier: "claude", mockCustomErrorExecutor: mockCustomErrorExecutor{
				identifier: "claude",
				executeFn: func(ctx context.Context, _ *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
					cliproxyexecutor.MarkUpstreamAttempt(ctx)
					headers := http.Header{"Retry-After": tc.values}
					if tc.marker != "" {
						headers.Set(tc.marker, "1")
					}
					logging.SetResponseHeaders(ctx, headers)
					return cliproxyexecutor.Response{}, newIssue7521Upstream429("upstream rate limited", 44*time.Second)
				},
			}}
			manager := newIssue7521Manager(t, nil, exec, credential)
			_, errExec := manager.Execute(context.Background(), []string{"claude"}, cliproxyexecutor.Request{Model: issue7521PoolModel}, cliproxyexecutor.Options{})
			var terminal *poolCooldownTerminalError
			if !errors.As(errExec, &terminal) {
				t.Fatalf("error = %v, want pool cooldown", errExec)
			}
			if got := SafeResponseHeaders(errExec).Get("Retry-After"); got != tc.want {
				t.Fatalf("client Retry-After = %s, want %s", got, tc.want)
			}
			stored, _ := manager.GetByID(credential.ID)
			localDeadline := stored.ModelStates[issue7521PoolModel].NextRetryAfter
			if !terminal.deadline.Equal(localDeadline) {
				t.Fatalf("pool deadline = %v, want recorded deadline %v", terminal.deadline, localDeadline)
			}
			if blocked, _, _ := isAuthBlockedForModel(stored, issue7521PoolModel, localDeadline.Add(-20*time.Second)); !blocked {
				t.Fatal("credential became selectable before its local hard deadline")
			}
		})
	}
}

func TestChainedCPAPoolCooldownDoesNotReviveExpiredHeaders(t *testing.T) {
	now := time.Now()
	cause := newIssue7521Upstream429("upstream rate limited", 44*time.Second)
	terminal := &poolCooldownTerminalError{cause: cause, deadline: now.Add(-time.Second), chainedRetryAt: now.Add(17 * time.Second)}
	if got := SafeResponseHeaders(terminal).Get("Retry-After"); got != "" {
		t.Fatalf("expired local deadline emitted Retry-After %q", got)
	}
	terminal.deadline = now.Add(44 * time.Second)
	terminal.chainedRetryAt = now.Add(-time.Second)
	if got := SafeResponseHeaders(terminal).Get("Retry-After"); got != "44" {
		t.Fatalf("expired chained hint displaced live local deadline: %q", got)
	}
}
