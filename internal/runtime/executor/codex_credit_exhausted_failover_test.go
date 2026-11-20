package executor

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

const codexCreditExhaustedEvent = `{"type":"error","error":{"type":"insufficient_quota","code":"credit_balance_exhausted","message":"You have no credits remaining.","param":null},"sequence_number":2}`

// An exhausted API-key balance arrives in-stream right after the response preamble. With
// stream-bootstrap-buffering on, it must fail the attempt before anything is released, so the
// conductor can serve the request from another credential.
func TestCodexExecutor_BootstrapBuffering_CreditExhaustedFailsAttempt(t *testing.T) {
	server := codexSSEServer(codexCreatedEvent, codexInProgressEvent, codexCreditExhaustedEvent)
	defer server.Close()

	req, opts := codexTestRequest()
	result, err := NewCodexExecutor(codexBufferingConfig(true)).ExecuteStream(context.Background(), codexTestAuth(server.URL), req, opts)
	if err == nil || result != nil {
		t.Fatalf("expected a synchronous failure with no result, got result=%v err=%v", result, err)
	}
	if got := statusCodeFromTestError(t, err); got != http.StatusTooManyRequests {
		t.Fatalf("status code = %d, want %d", got, http.StatusTooManyRequests)
	}
}

// With stream-bootstrap-buffering off nothing is held, so the preamble streams immediately and a
// credit-shaped error is still delivered in-stream (it is still classified 429 for cooldown rules).
func TestCodexExecutor_UnbufferedCreditErrorStaysInStream(t *testing.T) {
	server := codexSSEServer(codexCreatedEvent, codexInProgressEvent, codexCreditExhaustedEvent)
	defer server.Close()

	req, opts := codexTestRequest()
	auth := &cliproxyauth.Auth{Attributes: map[string]string{"base_url": server.URL}, Metadata: map[string]any{"access_token": "oauth-token"}}
	result, err := NewCodexExecutor(codexBufferingConfig(false)).ExecuteStream(context.Background(), auth, req, opts)
	if err != nil || result == nil {
		t.Fatalf("expected unbuffered stream, got result=%v err=%v", result, err)
	}
	combined, streamErr := drainChunks(result)
	if streamErr == nil || !strings.Contains(combined, `"type":"response.created"`) {
		t.Fatalf("expected preamble then in-stream error, got %q err=%v", combined, streamErr)
	}
}

// Drive the real executor and conductor together: the HTTP 200/SSE billing
// failure must preserve the structured reason through bootstrap conversion.
func TestCodexExecutor_CreditExhaustedParksCredential(t *testing.T) {
	exhausted := codexSSEServer(codexCreatedEvent, codexInProgressEvent, codexCreditExhaustedEvent)
	defer exhausted.Close()
	funded := codexSSEServer(codexCreatedEvent, codexOutputAddedEvent, codexOutputDeltaEvent, codexCompletedEventBody)
	defer funded.Close()
	ctx := t.Context()
	manager := cliproxyauth.NewManager(nil, nil, nil)
	manager.SetRetryConfig(0, 0, 0)
	manager.RegisterExecutor(NewCodexExecutor(codexBufferingConfig(true)))
	req, opts := codexTestRequest()
	key := codexTestAuth(exhausted.URL)
	key.ID, key.Provider = t.Name()+"-exhausted", "codex"
	key.Attributes["priority"] = "10"
	key.Attributes[cliproxyauth.AttributeCodexCreditResetDay] = "1"
	fallback := codexTestAuth(funded.URL)
	fallback.ID, fallback.Provider = t.Name()+"-funded", "codex"
	for _, a := range []*cliproxyauth.Auth{key, fallback} {
		registry.GetGlobalRegistry().RegisterClient(a.ID, a.Provider, []*registry.ModelInfo{{ID: req.Model}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(a.ID) })
		if _, err := manager.Register(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	result, err := manager.ExecuteStream(ctx, []string{"codex"}, req, opts)
	if err != nil || result == nil {
		t.Fatalf("expected same-round failover, got %v", err)
	}
	if _, err := drainChunks(result); err != nil {
		t.Fatalf("fallback stream: %v", err)
	}
	parked, _ := manager.GetByID(key.ID)
	views := cliproxyauth.CooldownSnapshotForAuth(parked, time.Now())
	if len(views) != 1 || views[0].Reason != cliproxyauth.CodexCreditParkReason || views[0].Scope != "credential" {
		t.Fatalf("expected credential-wide credit park, got %+v", views)
	}
}
