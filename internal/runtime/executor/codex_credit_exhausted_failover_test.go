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
// stream-bootstrap-buffering off (the default), an API-key credential must still fail the attempt
// before anything is released, so the conductor can serve the request from another credential.
func TestCodexExecutor_APIKeyCreditExhaustedFailsAttemptWithoutBuffering(t *testing.T) {
	server := codexSSEServer(codexCreatedEvent, codexInProgressEvent, codexCreditExhaustedEvent)
	defer server.Close()

	req, opts := codexTestRequest()
	result, err := NewCodexExecutor(codexBufferingConfig(false)).ExecuteStream(context.Background(), codexTestAuth(server.URL), req, opts)
	if err == nil {
		t.Fatal("expected the credit-exhausted rejection to fail the attempt")
	}
	if result != nil {
		t.Fatal("expected nil result so the preamble cannot reach the client")
	}
	if got := statusCodeFromTestError(t, err); got != http.StatusTooManyRequests {
		t.Fatalf("status code = %d, want %d", got, http.StatusTooManyRequests)
	}
}

// The same holds when stream-bootstrap-buffering is on.
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

// The API-key preamble hold must not delay generation: once a generated frame arrives the
// stream is released and every frame reaches the client in order.
func TestCodexExecutor_APIKeyPreambleHoldReleasesOnGeneration(t *testing.T) {
	server := codexSSEServer(codexCreatedEvent, codexInProgressEvent, codexOutputAddedEvent, codexOutputDeltaEvent, codexCompletedEventBody)
	defer server.Close()

	req, opts := codexTestRequest()
	result, err := NewCodexExecutor(codexBufferingConfig(false)).ExecuteStream(context.Background(), codexTestAuth(server.URL), req, opts)
	if err != nil || result == nil {
		t.Fatalf("expected a stream, got result=%v err=%v", result, err)
	}
	combined, streamErr := drainChunks(result)
	if streamErr != nil {
		t.Fatalf("unexpected stream error: %v", streamErr)
	}
	created := strings.Index(combined, `"type":"response.created"`)
	added := strings.Index(combined, `"type":"response.output_item.added"`)
	delta := strings.Index(combined, `"type":"response.output_text.delta"`)
	completed := strings.Index(combined, `"type":"response.completed"`)
	if created < 0 || added < created || delta < added || completed < delta {
		t.Fatalf("frames missing or out of order: %s", combined)
	}
}

// Request-level failures on an API key keep their in-stream delivery: only a credential that
// cannot serve the request at all fails over.
func TestCodexExecutor_APIKeyNonCreditFailureStaysInStream(t *testing.T) {
	server := codexSSEServer(codexCreatedEvent, codexInProgressEvent, codexInvalidEvent)
	defer server.Close()

	req, opts := codexTestRequest()
	result, err := NewCodexExecutor(codexBufferingConfig(false)).ExecuteStream(context.Background(), codexTestAuth(server.URL), req, opts)
	if err != nil || result == nil {
		t.Fatalf("expected in-stream delivery, got result=%v err=%v", result, err)
	}
	combined, streamErr := drainChunks(result)
	if streamErr == nil {
		t.Fatal("expected the invalid-request failure as an in-stream error")
	}
	if !strings.Contains(combined, `"type":"response.created"`) {
		t.Fatalf("preamble must be flushed before the in-stream error: %s", combined)
	}
	if got := statusCodeFromTestError(t, streamErr); got != http.StatusBadRequest {
		t.Fatalf("status code = %d, want %d", got, http.StatusBadRequest)
	}
}

// Subscription (OAuth) credentials are unchanged: with buffering off nothing is held, so the
// preamble streams immediately and a credit-shaped error is still delivered in-stream.
func TestCodexExecutor_OAuthCredentialKeepsUnbufferedDelivery(t *testing.T) {
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
