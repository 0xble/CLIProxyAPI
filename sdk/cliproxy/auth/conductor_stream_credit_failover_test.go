package auth

import (
	"context"
	"net/http"
	"sync"
	"testing"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// With request-retry 0, an API key that rejects a stream before any byte for lack of credits must
// not end the request: the conductor tries the next credential in the same round, and the
// configured quota rule still cools the exhausted key.
func TestExecuteStream_CreditExhaustedBeforeFirstByteFailsOverWithoutRetryRounds(t *testing.T) {
	previous := quotaCooldownDisabled.Load()
	quotaCooldownDisabled.Store(false)
	t.Cleanup(func() { quotaCooldownDisabled.Store(previous) })

	m := NewManager(nil, nil, nil)
	m.SetRetryConfig(0, 0, 0)
	ids := registerOverloadAuths(t, m, 3)

	var mu sync.Mutex
	var order []string
	exhausted := ids[0]
	m.RegisterExecutor(&customStreamMockExecutor{
		identifier: "codex",
		streamFn: func(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
			mu.Lock()
			order = append(order, auth.ID)
			mu.Unlock()
			if auth.ID == exhausted {
				return nil, customStatusError{code: http.StatusTooManyRequests, msg: `{"error":{"type":"insufficient_quota","code":"credit_balance_exhausted","message":"You have no credits remaining."},"sequence_number":2}`}
			}
			return successStreamResult(), nil
		},
	})

	result, err := m.ExecuteStream(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: "gpt-5.6-terra"}, cliproxyexecutor.Options{})
	if err != nil || result == nil {
		t.Fatalf("expected failover to serve the request, got result=%v err=%v", result, err)
	}
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			t.Fatalf("unexpected chunk error: %v", chunk.Err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(order) != 2 || order[0] != exhausted || order[1] == exhausted {
		t.Fatalf("attempt order = %v, want the exhausted key then one other credential", order)
	}
	if got, ok := m.GetByID(exhausted); !ok || !got.Unavailable {
		t.Fatalf("exhausted key was not cooled down: %+v", got)
	}
}
