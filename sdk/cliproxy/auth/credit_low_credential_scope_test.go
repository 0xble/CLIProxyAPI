package auth

import (
	"context"
	"net/http"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestCreditExhaustedClaudeAPIKeyCooldownIsCredentialWide(t *testing.T) {
	previous := quotaCooldownDisabled.Load()
	quotaCooldownDisabled.Store(false)
	t.Cleanup(func() { quotaCooldownDisabled.Store(previous) })
	m := NewManager(nil, nil, nil)
	const provider = "claude"
	const keyID = "credit-low-api-key"
	const backupID = "backup-api-key"
	key := &Auth{ID: keyID, Provider: provider, Status: StatusActive,
		Attributes: map[string]string{AttributeAuthKind: AuthKindAPIKey, "priority": "10"},
		Metadata: map[string]any{"request_scoped_errors": []internalconfig.RequestScopedErrorRule{{
			Status: 400, Match: []string{"credit balance is too low"},
			Action: "continue-and-cooldown", Cooldown: "24h",
		}}}}
	backup := &Auth{ID: backupID, Provider: provider, Status: StatusActive,
		Attributes: map[string]string{AttributeAuthKind: AuthKindAPIKey}}
	reg := registry.GetGlobalRegistry()
	models := []*registry.ModelInfo{{ID: "model-a"}, {ID: "model-b"}}
	reg.RegisterClient(keyID, provider, models)
	reg.RegisterClient(backupID, provider, models)
	t.Cleanup(func() { reg.UnregisterClient(keyID); reg.UnregisterClient(backupID) })
	if _, err := m.Register(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Register(context.Background(), backup); err != nil {
		t.Fatal(err)
	}
	var calls []string
	m.RegisterExecutor(&mockCustomErrorExecutor{identifier: provider, executeFn: func(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
		calls = append(calls, auth.ID+":"+req.Model)
		if auth.ID == keyID {
			return cliproxyexecutor.Response{}, customStatusError{code: http.StatusBadRequest, msg: `{"error":{"message":"Your credit balance is too low"}}`}
		}
		return cliproxyexecutor.Response{Payload: []byte(auth.ID)}, nil
	}})
	for _, model := range []string{"model-a", "model-b"} {
		if _, err := m.Execute(context.Background(), []string{provider}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{}); err != nil {
			t.Fatalf("execute %s: %v", model, err)
		}
	}
	want := []string{keyID + ":model-a", backupID + ":model-a", backupID + ":model-b"}
	if len(calls) != len(want) {
		t.Fatalf("calls=%v, want %v", calls, want)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Fatalf("calls=%v, want %v", calls, want)
		}
	}
}
