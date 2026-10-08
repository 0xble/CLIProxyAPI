package executor

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"github.com/gin-gonic/gin"
	claudeauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/claude"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func resetClaudeDeviceProfileCache() {
	helps.ResetClaudeDeviceProfileCache()
}

func claudeOAuthTestMetadata() map[string]any {
	return map[string]any{
		"account_uuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		claudeauth.ClaudeDeviceIDsMetadataKey: []string{
			"0000000000000000000000000000000000000000000000000000000000000000",
		},
	}
}

func malformedClaudeTreeSignatureForClaudeExecutorTest() string {
	return base64.StdEncoding.EncodeToString([]byte{0x12, 0xFF, 0xFE, 0xFD})
}

func newClaudeHeaderTestRequest(t *testing.T, incoming http.Header) *http.Request {
	t.Helper()

	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(recorder)
	ginReq := httptest.NewRequest(http.MethodPost, "http://localhost/v1/messages", nil)
	ginReq.Header = incoming.Clone()
	ginCtx.Request = ginReq

	req := httptest.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", nil)
	return req.WithContext(context.WithValue(req.Context(), "gin", ginCtx))
}

func assertClaudeFingerprint(t *testing.T, headers http.Header, userAgent, pkgVersion, runtimeVersion, osName, arch string) {
	t.Helper()

	if got := headers.Get("User-Agent"); got != userAgent {
		t.Fatalf("User-Agent = %q, want %q", got, userAgent)
	}
	if got := headers.Get("X-Stainless-Package-Version"); got != pkgVersion {
		t.Fatalf("X-Stainless-Package-Version = %q, want %q", got, pkgVersion)
	}
	if got := headers.Get("X-Stainless-Runtime-Version"); got != runtimeVersion {
		t.Fatalf("X-Stainless-Runtime-Version = %q, want %q", got, runtimeVersion)
	}
	if got := headers.Get("X-Stainless-Os"); got != osName {
		t.Fatalf("X-Stainless-Os = %q, want %q", got, osName)
	}
	if got := headers.Get("X-Stainless-Arch"); got != arch {
		t.Fatalf("X-Stainless-Arch = %q, want %q", got, arch)
	}
}

func assertClaudeCredentialIdentity(t *testing.T, body []byte, headers http.Header, deviceIDs []string, accountUUID string) {
	t.Helper()
	userID := gjson.GetBytes(body, "metadata.user_id").String()
	deviceID := gjson.Get(userID, "device_id").String()
	inPool := false
	for _, candidate := range deviceIDs {
		if deviceID == candidate {
			inPool = true
			break
		}
	}
	if !inPool {
		t.Fatalf("device_id = %q, want selected credential device pool entry", deviceID)
	}
	if got := gjson.Get(userID, "account_uuid").String(); got != accountUUID {
		t.Fatalf("account_uuid = %q, want selected credential account %q", got, accountUUID)
	}
	sessionID := gjson.Get(userID, "session_id").String()
	if sessionID == "" || sessionID != headers.Get("X-Claude-Code-Session-Id") {
		t.Fatalf("metadata session_id = %q, header session ID = %q", sessionID, headers.Get("X-Claude-Code-Session-Id"))
	}
	resigned, errResign := finalizeAnthropicMessagesBodyCCH(body, "")
	if errResign != nil {
		t.Fatalf("re-finalize Claude CCH: %v", errResign)
	}
	if !bytes.Equal(resigned, body) {
		t.Fatal("Claude CCH was calculated before final credential metadata rewrite")
	}
}

// assertClaudeCountTokensIdentity pins the count_tokens shape captured from real
// Claude Code 2.1.220: the endpoint carries no metadata whatsoever. Anthropic
// rejects the field there with "metadata: Extra inputs are not permitted", so the
// credential identity travels only on the header and on the Messages endpoint.
func assertClaudeCountTokensIdentity(t *testing.T, body []byte, headers http.Header) {
	t.Helper()
	if got := gjson.GetBytes(body, "metadata"); got.Exists() {
		t.Fatalf("count_tokens metadata = %s, want it absent", got.Raw)
	}
	if got := headers.Get("X-Claude-Code-Session-Id"); got == "" {
		t.Fatal("count_tokens is missing X-Claude-Code-Session-Id")
	}
	resigned, errResign := finalizeAnthropicMessagesBodyCCH(body, "")
	if errResign != nil {
		t.Fatalf("re-finalize Claude CCH: %v", errResign)
	}
	if !bytes.Equal(resigned, body) {
		t.Fatal("count_tokens CCH was calculated before the final body rewrite")
	}
}

func claudeOAuthCancellationTestMetadata() map[string]any {
	return map[string]any{
		"account_uuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		claudeauth.ClaudeDeviceIDsMetadataKey: []string{
			"0000000000000000000000000000000000000000000000000000000000000000",
		},
	}
}

func executeOpenAIChatCompletionThroughClaude(t *testing.T, upstreamBody string) (cliproxyexecutor.Response, error) {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(upstreamBody))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-123",
		"base_url": server.URL,
	}}
	payload := []byte(`{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"hi"}]}`)

	return executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-3-5-sonnet-20241022",
		Payload: payload,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("openai"),
	})
}

func assertStatusErr(t *testing.T, err error, want int) {
	t.Helper()

	status, ok := err.(interface{ StatusCode() int })
	if !ok {
		t.Fatalf("error %T does not expose StatusCode", err)
	}
	if got := status.StatusCode(); got != want {
		t.Fatalf("StatusCode() = %d, want %d", got, want)
	}
}

func testClaudeExecutorInvalidCompressedErrorBody(
	t *testing.T,
	invoke func(executor *ClaudeExecutor, auth *cliproxyauth.Auth, payload []byte) error,
) {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("not-a-valid-gzip-stream"))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-123",
		"base_url": server.URL,
	}}
	payload := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`)

	err := invoke(executor, auth, payload)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to decode error response body") {
		t.Fatalf("expected decode failure message, got: %v", err)
	}
	if statusProvider, ok := err.(interface{ StatusCode() int }); !ok || statusProvider.StatusCode() != http.StatusBadRequest {
		t.Fatalf("expected status code 400, got: %v", err)
	}
}

// assertClaudeMidConversationSystemMessage checks a forwarded caller system prompt.
// wantTTL is "" for the native default marker and "1h" once
// upgradeClaudeCacheControlTTL has run, which only happens for OAuth credentials.
func assertClaudeMidConversationSystemMessage(t *testing.T, body []byte, messageIndex int, wantText, wantTTL string) {
	t.Helper()
	messagePath := fmt.Sprintf("messages.%d", messageIndex)
	if got := gjson.GetBytes(body, messagePath+".role").String(); got != "system" {
		t.Fatalf("%s.role = %q, want system", messagePath, got)
	}
	content := gjson.GetBytes(body, messagePath+".content").Array()
	if len(content) != 1 {
		t.Fatalf("%s.content has %d blocks, want 1", messagePath, len(content))
	}
	if got := content[0].Get("text").String(); got != wantText {
		t.Fatalf("%s.content.0.text lost caller prompt: got len %d, want len %d", messagePath, len(got), len(wantText))
	}
	if got := content[0].Get("cache_control.type").String(); got != "ephemeral" {
		t.Fatalf("%s.content.0.cache_control.type = %q, want ephemeral", messagePath, got)
	}
	if got := content[0].Get("cache_control.ttl").String(); got != wantTTL {
		t.Fatalf("%s.content.0.cache_control.ttl = %q, want %q: %s", messagePath, got, wantTTL, content[0].Raw)
	}
}

func assertClaudeLegacySystemReminderLayout(t *testing.T, body []byte, wantSystem, wantUser, wantTTL string) {
	t.Helper()
	if got := gjson.GetBytes(body, "system.#").Int(); got != 2 {
		t.Fatalf("top-level system block count = %d, want billing and identity only", got)
	}
	if got := gjson.GetBytes(body, "messages.#").Int(); got != 1 {
		t.Fatalf("message count = %d, want one user turn and no role=system", got)
	}
	content := gjson.GetBytes(body, "messages.0.content").Array()
	if len(content) != 3 {
		t.Fatalf("user content has %d blocks, want currentDate, caller reminder, and user text", len(content))
	}
	assertClaudeCodeCurrentDateBlock(t, content[0])
	if got := content[1].Get("text").String(); got != claudeCallerSystemReminder(wantSystem) {
		t.Fatalf("caller reminder lost system prompt: got len %d, want len %d", len(got), len(wantSystem))
	}
	if content[1].Get("cache_control").Exists() {
		t.Fatalf("caller reminder unexpectedly has cache_control: %s", content[1].Raw)
	}
	assertEphemeralUserTextBlock(t, content[2], wantUser, wantTTL)
}

func assertClaudeCodeCurrentDateBlock(t *testing.T, block gjson.Result) {
	t.Helper()
	assertClaudeCodeCurrentDateBlockAt(t, block, time.Now())
}

func assertClaudeCodeCurrentDateBlockAt(t *testing.T, block gjson.Result, now time.Time) {
	t.Helper()
	if got := block.Get("type").String(); got != "text" {
		t.Fatalf("currentDate block type = %q, want text", got)
	}
	if got, want := block.Get("text").String(), claudeCodeCurrentDateReminder(now); got != want {
		t.Fatalf("currentDate reminder = %q, want %q", got, want)
	}
	if block.Get("cache_control").Exists() {
		t.Fatalf("currentDate block must not contain cache_control: %s", block.Raw)
	}
}

// assertEphemeralUserTextBlock checks the cloaked first-user block. wantTTL is ""
// for the native default marker and "1h" once upgradeClaudeCacheControlTTL has run,
// which only happens for OAuth credentials.
func assertEphemeralUserTextBlock(t *testing.T, block gjson.Result, wantText, wantTTL string) {
	t.Helper()
	if got := block.Get("type").String(); got != "text" {
		t.Fatalf("user block type = %q, want text", got)
	}
	if got := block.Get("text").String(); got != wantText {
		t.Fatalf("user block text = %q, want %q", got, wantText)
	}
	if got := block.Get("cache_control.type").String(); got != "ephemeral" {
		t.Fatalf("user block cache_control.type = %q, want ephemeral", got)
	}
	if got := block.Get("cache_control.ttl").String(); got != wantTTL {
		t.Fatalf("user block cache_control.ttl = %q, want %q: %s", got, wantTTL, block.Raw)
	}
}

func executeClaudeContextManagementRequest(t *testing.T, cfg *config.Config, payload []byte, stream bool) []byte {
	t.Helper()

	var upstreamBody []byte
	transport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		var errRead error
		upstreamBody, errRead = io.ReadAll(req.Body)
		if errRead != nil {
			t.Fatal(errRead)
		}
		contentType := "application/json"
		responseBody := `{"id":"msg_test","type":"message","role":"assistant","model":"claude-opus-5","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`
		if stream {
			contentType = "text/event-stream"
			responseBody = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_test\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-opus-5\",\"content\":[],\"stop_reason\":null,\"usage\":{\"input_tokens\":1,\"output_tokens\":0}}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{contentType}},
			Body:       io.NopCloser(strings.NewReader(responseBody)),
			Request:    req,
		}, nil
	})
	ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", http.RoundTripper(transport))
	executor := NewClaudeExecutor(cfg)
	auth := &cliproxyauth.Auth{Attributes: map[string]string{"api_key": "key-payload-rule", "cloak_mode": "always"}}
	request := cliproxyexecutor.Request{Model: "claude-opus-5", Payload: payload}
	options := cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatClaude}

	if stream {
		result, errStream := executor.ExecuteStream(ctx, auth, request, options)
		if errStream != nil {
			t.Fatalf("ExecuteStream() error = %v", errStream)
		}
		for chunk := range result.Chunks {
			if chunk.Err != nil {
				t.Fatalf("stream chunk error = %v", chunk.Err)
			}
		}
		return upstreamBody
	}
	if _, errExecute := executor.Execute(ctx, auth, request, options); errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	return upstreamBody
}
