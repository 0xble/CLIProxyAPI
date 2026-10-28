package auth

import (
	"context"
	"net/http"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

type issue7017InFlightExecutor struct {
	issue7017Executor
	entered chan chan error
}

func (e *issue7017InFlightExecutor) Execute(ctx context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	e.record(auth)
	response := make(chan error, 1)
	select {
	case e.entered <- response:
	case <-ctx.Done():
		return cliproxyexecutor.Response{}, ctx.Err()
	}
	select {
	case err := <-response:
		return cliproxyexecutor.Response{}, err
	case <-ctx.Done():
		return cliproxyexecutor.Response{}, ctx.Err()
	}
}

func TestIssue7017ZeroHintKeepsInFlightRequestScopedCooldown(t *testing.T) {
	withQuotaCooldownEnabled(t)
	manager := NewManager(nil, nil, nil)
	manager.SetRetryConfig(0, 0, 0)
	executor := &issue7017InFlightExecutor{entered: make(chan chan error, 2)}
	manager.RegisterExecutor(executor)
	auth := &Auth{
		ID:       "turn-zero-in-flight",
		Provider: "codex",
		Metadata: map[string]any{
			"type": "codex",
			"request_scoped_errors": []internalconfig.RequestScopedErrorRule{{
				Status:   http.StatusBadRequest,
				Match:    []string{"credit exhausted"},
				Action:   RequestScopedActionStopAndCooldown,
				Cooldown: "1h",
			}},
		},
	}
	const model = "gpt-6.1-sol"
	reg := registry.GetGlobalRegistry()
	reg.RegisterClient(auth.ID, "codex", []*registry.ModelInfo{{ID: model}})
	t.Cleanup(func() { reg.UnregisterClient(auth.ID) })
	issue7017Register(t, manager, auth)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 2)
	for range 2 {
		go func() {
			_, errExecute := manager.Execute(ctx, []string{"codex"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{})
			finished <- errExecute
		}()
	}
	// Neither response is released until both requests have reached upstream.
	responses := make([]chan error, 2)
	for i := range responses {
		select {
		case responses[i] = <-executor.entered:
		case err := <-finished:
			t.Fatalf("request returned before both attempts were in flight: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("both requests did not reach upstream")
		}
	}
	responses[0] <- requestScopedCooldownError{status: http.StatusBadRequest, body: "credit exhausted"}
	if err := <-finished; err == nil {
		t.Fatal("expected the matched request-scoped failure")
	}
	before, _ := manager.GetByID(auth.ID)
	state := before.ModelStates[model]
	if state == nil || !state.Unavailable || !state.NextRetryAfter.After(time.Now().Add(59*time.Minute)) {
		t.Fatalf("expected the first request to establish the 1h minimum: %+v", state)
	}
	deadline := state.NextRetryAfter

	zero := time.Duration(0)
	responses[1] <- issue7017HintError{msg: issue7017TurnBody(), hint: &zero}
	if err := <-finished; err == nil {
		t.Fatal("expected the later transient capacity rejection")
	}
	after, _ := manager.GetByID(auth.ID)
	state = after.ModelStates[model]
	if state == nil || !state.Unavailable || !state.NextRetryAfter.Equal(deadline) {
		t.Fatalf("zero RetryAfter cleared the live request-scoped minimum %v: %+v", deadline, state)
	}
	if state.Quota.Exceeded || after.Quota.Exceeded {
		t.Fatal("transient capacity rejection must not become quota exhaustion")
	}
	if selected, errSelect := manager.SelectAuth(context.Background(), "codex", model, cliproxyexecutor.Options{}); errSelect == nil || selected != nil {
		t.Fatalf("credential must remain unselectable until the minimum deadline: selected=%v err=%v", selected, errSelect)
	}
	if calls := executor.callIDs(); len(calls) != 2 {
		t.Fatalf("upstream attempts = %v, want exactly the 2 in-flight requests", calls)
	}
}

func TestIssue7017ZeroHintCooldownBoundaries(t *testing.T) {
	withQuotaCooldownEnabled(t)
	for _, model := range []string{"gpt-6.1-sol", ""} {
		for _, tc := range []struct {
			name     string
			previous time.Duration
			disabled bool
			keep     bool
		}{
			{name: "live minimum", previous: time.Hour, keep: true},
			{name: "no existing deadline"},
			{name: "expired deadline", previous: -time.Hour},
			{name: "cooling disabled", previous: time.Hour, disabled: true},
		} {
			scope := "model"
			if model == "" {
				scope = "auth"
			}
			t.Run(scope+"/"+tc.name, func(t *testing.T) {
				manager := NewManager(nil, nil, nil)
				auth := &Auth{ID: "turn-zero-boundary", Provider: "codex", Metadata: map[string]any{"disable_cooling": tc.disabled}}
				issue7017Register(t, manager, auth)
				var deadline time.Time
				if tc.previous != 0 {
					manager.MarkResult(context.Background(), Result{
						AuthID: auth.ID, Provider: "codex", Model: model,
						Error:    &Error{Code: ErrorCodeForceCooldown, HTTPStatus: http.StatusBadRequest, Message: "credit exhausted"},
						Cooldown: time.Hour,
					})
					manager.mu.Lock()
					if model == "" {
						deadline = manager.auths[auth.ID].NextRetryAfter
						if tc.previous < 0 {
							manager.auths[auth.ID].NextRetryAfter = time.Now().Add(tc.previous)
						}
					} else {
						deadline = manager.auths[auth.ID].ModelStates[model].NextRetryAfter
						if tc.previous < 0 {
							manager.auths[auth.ID].ModelStates[model].NextRetryAfter = time.Now().Add(tc.previous)
						}
					}
					manager.mu.Unlock()
				}
				zero := time.Duration(0)
				manager.MarkResult(context.Background(), Result{
					AuthID: auth.ID, Provider: "codex", Model: model, RetryAfter: &zero,
					Error: resultErrorFromError(issue7017HintError{msg: issue7017TurnBody(), hint: &zero}),
				})
				got, _ := manager.GetByID(auth.ID)
				next, unavailable, quota := got.NextRetryAfter, got.Unavailable, got.Quota
				if model != "" {
					state := got.ModelStates[model]
					if state == nil {
						t.Fatal("missing model state")
					}
					next, unavailable, quota = state.NextRetryAfter, state.Unavailable, state.Quota
				}
				if tc.keep {
					if !next.Equal(deadline) || !unavailable {
						t.Fatalf("zero RetryAfter cleared the live minimum: next=%v want=%v unavailable=%t", next, deadline, unavailable)
					}
				} else if !next.IsZero() || unavailable {
					t.Fatalf("zero RetryAfter must not create a cooldown: next=%v unavailable=%t", next, unavailable)
				}
				if quota.Exceeded || quota.BackoffLevel != 0 {
					t.Fatalf("transient capacity rejection changed quota: %+v", quota)
				}
			})
		}
	}
}
