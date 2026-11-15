package executor

import (
	"context"
	"net/http"
	"strings"
	"testing"

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
