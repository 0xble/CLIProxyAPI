package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

func TestClaudeBillingFingerprintUsesFirstUserText(t *testing.T) {
	const prompt = "CPA_OFFICIAL_BASEURL_CLI_SYSTEM_EMPTY_b82d4e"
	payload := []byte(`{"system":"must not seed the build hash","messages":[{"role":"user","content":[{"type":"text","text":"<system-reminder>date</system-reminder>"},{"type":"text","text":"` + prompt + `"}]},{"role":"assistant","content":"answer"},{"role":"user","content":"turn2"}]}`)
	if got := claudeBillingFingerprintMessageText(payload); got != prompt {
		t.Fatalf("claudeBillingFingerprintMessageText() = %q, want %q", got, prompt)
	}
	if got := computeFingerprint(prompt, "2.1.258"); got != "1f4" {
		t.Fatalf("computeFingerprint() = %q, want official 2.1.258 capture suffix 1f4", got)
	}
}

func TestClaudeCodeLocalDateMatchesNativeLocalCalendarAlgorithm(t *testing.T) {
	instant := time.Date(2026, time.July, 31, 15, 30, 0, 0, time.UTC)
	kiritimati := time.FixedZone("Kiritimati", 14*60*60)
	minusTwelve := time.FixedZone("Etc/GMT+12", -12*60*60)

	if got := claudeCodeLocalDate(instant.In(kiritimati)); got != "2026-08-01" {
		t.Fatalf("Kiritimati local date = %q, want 2026-08-01", got)
	}
	if got := claudeCodeLocalDate(instant.In(minusTwelve)); got != "2026-07-31" {
		t.Fatalf("GMT-12 local date = %q, want 2026-07-31", got)
	}
	wantReminder := "<system-reminder>\nAs you answer the user's questions, you can use the following context:\n# currentDate\nToday's date is 2026-08-01.\n\n      IMPORTANT: this context may or may not be relevant to your tasks. You should not respond to this context unless it is highly relevant to your task.\n</system-reminder>\n\n"
	if got := claudeCodeCurrentDateReminder(instant.In(kiritimati)); got != wantReminder {
		t.Fatalf("currentDate reminder = %q, want exact native text %q", got, wantReminder)
	}
}

func TestClaudeCodeTimezoneUsesCredentialThenConfiguredProfile(t *testing.T) {
	instant := time.Date(2026, time.August, 2, 1, 30, 0, 0, time.UTC)
	cfg := &config.Config{ClaudeHeaderDefaults: config.ClaudeHeaderDefaults{Timezone: "Asia/Tokyo"}}
	auth := &cliproxyauth.Auth{Metadata: map[string]any{"timezone": "Pacific/Honolulu"}}
	if got := claudeCodeLocalDate(instant.In(claudeCodeTimezone(cfg, auth))); got != "2026-08-01" {
		t.Fatalf("credential currentDate = %q, want 2026-08-01", got)
	}
	if got := claudeCodeLocalDate(instant.In(claudeCodeTimezone(cfg, nil))); got != "2026-08-02" {
		t.Fatalf("configured currentDate = %q, want 2026-08-02", got)
	}
	invalidAuth := &cliproxyauth.Auth{Metadata: map[string]any{"timezone": "not/a-timezone"}}
	if got := claudeCodeTimezone(cfg, invalidAuth).String(); got != "Asia/Tokyo" {
		t.Fatalf("invalid credential timezone = %q, want config fallback", got)
	}
	invalid := &config.Config{ClaudeHeaderDefaults: config.ClaudeHeaderDefaults{Timezone: "not/a-timezone"}}
	if got := claudeCodeTimezone(invalid, nil); got != time.Local {
		t.Fatalf("invalid timezone location = %v, want time.Local", got)
	}
}

func TestInjectClaudeCodeCurrentDateIsIdempotentAndAlignsFirstUserCache(t *testing.T) {
	fixed := time.Date(2026, time.August, 1, 9, 0, 0, 0, time.FixedZone("UTC+8", 8*60*60))
	payload := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hello","cache_control":{"type":"ephemeral","ttl":"1h"}}]}]}`)

	first := injectClaudeCodeCurrentDate(payload, fixed)
	if !bytes.Contains(first, []byte(`<system-reminder>`)) || bytes.Contains(first, []byte(`\u003csystem-reminder`)) {
		t.Fatalf("currentDate angle brackets must match JSON.stringify bytes: %s", first)
	}
	second := injectClaudeCodeCurrentDate(first, fixed)
	if !bytes.Equal(first, second) {
		t.Fatalf("currentDate injection is not idempotent:\nfirst:  %s\nsecond: %s", first, second)
	}
	content := gjson.GetBytes(first, "messages.0.content").Array()
	if len(content) != 2 {
		t.Fatalf("first user content has %d blocks, want 2: %s", len(content), first)
	}
	if got := content[0].Get("text").String(); got != claudeCodeCurrentDateReminder(fixed) {
		t.Fatalf("currentDate text = %q, want exact native reminder", got)
	}
	if content[0].Get("cache_control").Exists() {
		t.Fatalf("currentDate block must not contain cache_control: %s", content[0].Raw)
	}
	assertEphemeralUserTextBlock(t, content[1], "hello", "")
}

func TestInjectClaudeCodeCurrentDateMovesExistingCopyToFirstBlock(t *testing.T) {
	fixed := time.Date(2026, time.August, 1, 9, 0, 0, 0, time.FixedZone("UTC+8", 8*60*60))
	dateBlock := buildTextBlock(claudeCodeCurrentDateReminder(fixed), nil)
	payload := []byte(`{"messages":[{"role":"user","content":[` +
		`{"type":"text","text":"hello"},` + dateBlock + `]}]}`)

	out := injectClaudeCodeCurrentDate(payload, fixed)
	content := gjson.GetBytes(out, "messages.0.content").Array()
	if len(content) != 2 {
		t.Fatalf("content has %d blocks, want one currentDate and user text: %s", len(content), out)
	}
	assertClaudeCodeCurrentDateBlockAt(t, content[0], fixed)
	assertEphemeralUserTextBlock(t, content[1], "hello", "")
}

func TestInjectClaudeCodeCurrentDatePrecedesExistingReminder(t *testing.T) {
	fixed := time.Date(2026, time.August, 1, 9, 0, 0, 0, time.FixedZone("UTC+8", 8*60*60))
	reminder := "<system-reminder>\ncaller instructions\n</system-reminder>"
	payload := []byte(`{"messages":[{"role":"user","content":[` +
		buildTextBlock(reminder, nil) + `,` +
		`{"type":"text","text":"continue","cache_control":{"type":"ephemeral","ttl":"1h"}}]}]}`)

	out := injectClaudeCodeCurrentDate(payload, fixed)
	content := gjson.GetBytes(out, "messages.0.content").Array()
	if len(content) != 3 {
		t.Fatalf("content has %d blocks, want currentDate, reminder, and user text: %s", len(content), out)
	}
	assertClaudeCodeCurrentDateBlockAt(t, content[0], fixed)
	if got := content[1].Get("text").String(); got != reminder {
		t.Fatalf("content[1].text = %q, want standalone reminder", got)
	}
	assertEphemeralUserTextBlock(t, content[2], "continue", "")
}

func TestInjectClaudeCodeCurrentDateFollowsLeadingToolResults(t *testing.T) {
	fixed := time.Date(2026, time.August, 1, 9, 0, 0, 0, time.FixedZone("UTC+8", 8*60*60))
	payload := []byte(`{"messages":[` +
		`{"role":"assistant","content":[{"type":"tool_use","id":"toolu_1","name":"Read","input":{}}]},` +
		`{"role":"user","content":[` +
		`{"type":"tool_result","tool_use_id":"toolu_1","content":"ok"},` +
		`{"type":"text","text":"continue"}]}]}`)

	first := injectClaudeCodeCurrentDate(payload, fixed)
	second := injectClaudeCodeCurrentDate(first, fixed)
	if !bytes.Equal(first, second) {
		t.Fatalf("currentDate injection is not idempotent:\nfirst:  %s\nsecond: %s", first, second)
	}

	content := gjson.GetBytes(first, "messages.1.content").Array()
	if len(content) != 3 {
		t.Fatalf("content has %d blocks, want tool_result, currentDate, and user text: %s", len(content), first)
	}
	if got := content[0].Get("type").String(); got != "tool_result" {
		t.Fatalf("content[0].type = %q, want tool_result to stay first: %s", got, first)
	}
	if got := content[0].Get("tool_use_id").String(); got != "toolu_1" {
		t.Fatalf("content[0].tool_use_id = %q, want toolu_1", got)
	}
	assertClaudeCodeCurrentDateBlockAt(t, content[1], fixed)
	assertEphemeralUserTextBlock(t, content[2], "continue", "")
}

func TestInjectClaudeCodeCurrentDateFollowsAllLeadingToolResults(t *testing.T) {
	fixed := time.Date(2026, time.August, 1, 9, 0, 0, 0, time.FixedZone("UTC+8", 8*60*60))
	payload := []byte(`{"messages":[` +
		`{"role":"assistant","content":[` +
		`{"type":"tool_use","id":"toolu_1","name":"Read","input":{}},` +
		`{"type":"tool_use","id":"toolu_2","name":"Read","input":{}}]},` +
		`{"role":"user","content":[` +
		`{"type":"tool_result","tool_use_id":"toolu_1","content":"ok"},` +
		`{"type":"tool_result","tool_use_id":"toolu_2","content":"ok"}]}]}`)

	out := injectClaudeCodeCurrentDate(payload, fixed)
	content := gjson.GetBytes(out, "messages.1.content").Array()
	if len(content) != 3 {
		t.Fatalf("content has %d blocks, want two tool_results and currentDate: %s", len(content), out)
	}
	for idx, wantID := range []string{"toolu_1", "toolu_2"} {
		if got := content[idx].Get("type").String(); got != "tool_result" {
			t.Fatalf("content[%d].type = %q, want tool_result: %s", idx, got, out)
		}
		if got := content[idx].Get("tool_use_id").String(); got != wantID {
			t.Fatalf("content[%d].tool_use_id = %q, want %q", idx, got, wantID)
		}
	}
	assertClaudeCodeCurrentDateBlockAt(t, content[2], fixed)
}

// Test case 1: String system prompt becomes an authoritative mid-conversation
// system message after the first user turn.
func TestCheckSystemInstructionsWithMode_StringSystemPreserved(t *testing.T) {
	payload := []byte(`{"model":"claude-opus-5","system":"You are a helpful assistant.","messages":[{"role":"user","content":"hi"}]}`)

	out := checkSystemInstructionsWithMode(payload, false)

	system := gjson.GetBytes(out, "system")
	if !system.IsArray() {
		t.Fatalf("system should be an array, got %s", system.Type)
	}
	blocks := system.Array()
	if len(blocks) != 2 {
		t.Fatalf("expected billing and identity blocks only, got %d", len(blocks))
	}
	if got := blocks[0].Get("text").String(); !strings.Contains(got, "cc_entrypoint=cli;") {
		t.Fatalf("blocks[0] should use CLI billing attribution, got %q", got)
	}
	if blocks[1].Get("text").String() != claudeCodeCLIIdentity {
		t.Fatalf("blocks[1] should be official CLI identity, got %q", blocks[1].Get("text").String())
	}
	if got := blocks[1].Get("cache_control.type").String(); got != "ephemeral" {
		t.Fatalf("blocks[1] cache_control.type = %q, want ephemeral", got)
	}
	if blocks[1].Get("cache_control.ttl").Exists() {
		t.Fatalf("blocks[1] cache_control must not carry a default ttl: %s", blocks[1].Raw)
	}
	content := gjson.GetBytes(out, "messages.0.content").Array()
	if len(content) != 2 {
		t.Fatalf("messages[0].content has %d blocks, want currentDate and user text: %s", len(content), out)
	}
	assertClaudeCodeCurrentDateBlock(t, content[0])
	assertEphemeralUserTextBlock(t, content[1], "hi", "")
	assertClaudeMidConversationSystemMessage(t, out, 1, "You are a helpful assistant.", "")
}

func TestClaudeUsesLegacySystemReminder(t *testing.T) {
	tests := map[string]bool{
		"claude-opus-4-6":          true,
		"claude-opus-4-7":          true,
		"claude-sonnet-5":          false,
		"prefix/claude-sonnet-4-6": true,
		"claude-3-5-haiku-latest":  true,
		"claude-opus-5":            false,
		"prefix/claude-opus-4-8":   false,
		"claude-fable-5":           false,
		"claude-future-6":          false,
		"":                         false,
	}
	for model, want := range tests {
		t.Run(model, func(t *testing.T) {
			payload := []byte(`{"model":` + fmt.Sprintf("%q", model) + `}`)
			if got := claudeUsesLegacySystemReminder(payload); got != want {
				t.Fatalf("claudeUsesLegacySystemReminder(%q) = %v, want %v", model, got, want)
			}
		})
	}
}

func TestCheckSystemInstructionsWithMode_FutureModelDefaultsToMidSystem(t *testing.T) {
	payload := []byte(`{"model":"claude-opus-6","system":"future instructions","messages":[{"role":"user","content":"hi"}]}`)

	out := checkSystemInstructionsWithMode(payload, false)
	if got := gjson.GetBytes(out, "system.#").Int(); got != 2 {
		t.Fatalf("top-level system block count = %d, want 2", got)
	}
	content := gjson.GetBytes(out, "messages.0.content").Array()
	if len(content) != 2 {
		t.Fatalf("user content has %d blocks, want currentDate and user text", len(content))
	}
	assertClaudeCodeCurrentDateBlock(t, content[0])
	assertEphemeralUserTextBlock(t, content[1], "hi", "")
	assertClaudeMidConversationSystemMessage(t, out, 1, "future instructions", "")
}

func TestCheckSystemInstructionsWithMode_LegacyModelUsesSystemReminder(t *testing.T) {
	payload := []byte(`{"model":"claude-opus-4-6","system":"legacy instructions","messages":[{"role":"user","content":"hi"}]}`)

	out := checkSystemInstructionsWithMode(payload, false)
	if got := gjson.GetBytes(out, "system.#").Int(); got != 2 {
		t.Fatalf("top-level system block count = %d, want billing and identity only", got)
	}
	if got := gjson.GetBytes(out, "messages.#").Int(); got != 1 {
		t.Fatalf("message count = %d, want no role=system insertion", got)
	}
	content := gjson.GetBytes(out, "messages.0.content").Array()
	if len(content) != 3 {
		t.Fatalf("user content has %d blocks, want currentDate, caller reminder, and user text", len(content))
	}
	assertClaudeCodeCurrentDateBlock(t, content[0])
	if got := content[1].Get("text").String(); got != claudeCallerSystemReminder("legacy instructions") {
		t.Fatalf("caller system reminder = %q", got)
	}
	if content[1].Get("cache_control").Exists() {
		t.Fatalf("caller system reminder unexpectedly has cache_control: %s", content[1].Raw)
	}
	assertEphemeralUserTextBlock(t, content[2], "hi", "")
}

func TestCheckSystemInstructionsWithMode_LegacyModelKeepsSystemBlocksSeparate(t *testing.T) {
	payload := []byte(`{"model":"claude-opus-4-6","system":[` +
		`{"type":"text","text":"first guidance","cache_control":{"type":"ephemeral","ttl":"1h"}},` +
		`{"type":"text","text":"second guidance"}],` +
		`"messages":[{"role":"user","content":"hi"}]}`)

	out := checkSystemInstructionsWithMode(payload, false)
	content := gjson.GetBytes(out, "messages.0.content").Array()
	if len(content) != 4 {
		t.Fatalf("user content has %d blocks, want currentDate, two caller reminders, and user text: %s", len(content), out)
	}
	assertClaudeCodeCurrentDateBlock(t, content[0])
	for idx, want := range []string{"first guidance", "second guidance"} {
		block := content[idx+1]
		if got := block.Get("text").String(); got != claudeCallerSystemReminder(want) {
			t.Fatalf("content[%d].text = %q, want separate caller reminder %q", idx+1, got, want)
		}
		if block.Get("cache_control").Exists() {
			t.Fatalf("content[%d] caller reminder unexpectedly has cache_control: %s", idx+1, block.Raw)
		}
	}
	assertEphemeralUserTextBlock(t, content[3], "hi", "")
}

// Test case 2: Strict mode keeps only the injected Claude Code system blocks.
func TestCheckSystemInstructionsWithMode_StringSystemStrict(t *testing.T) {
	payload := []byte(`{"system":"You are a helpful assistant.","messages":[{"role":"user","content":"hi"}]}`)

	out := checkSystemInstructionsWithMode(payload, true)

	blocks := gjson.GetBytes(out, "system").Array()
	if len(blocks) != 2 {
		t.Fatalf("strict mode should produce 2 injected blocks, got %d", len(blocks))
	}
	content := gjson.GetBytes(out, "messages.0.content").Array()
	if len(content) != 2 {
		t.Fatalf("strict mode content has %d blocks, want currentDate and user text", len(content))
	}
	assertClaudeCodeCurrentDateBlock(t, content[0])
	assertEphemeralUserTextBlock(t, content[1], "hi", "")
}

// Test case 3: Empty string system prompt adds only currentDate before user text.
func TestCheckSystemInstructionsWithMode_EmptyStringSystemIgnored(t *testing.T) {
	payload := []byte(`{"system":"","messages":[{"role":"user","content":"hi"}]}`)

	out := checkSystemInstructionsWithMode(payload, false)

	blocks := gjson.GetBytes(out, "system").Array()
	if len(blocks) != 2 {
		t.Fatalf("empty string system should still produce 2 injected blocks, got %d", len(blocks))
	}
	content := gjson.GetBytes(out, "messages.0.content").Array()
	if len(content) != 2 {
		t.Fatalf("empty system content has %d blocks, want 2", len(content))
	}
	assertClaudeCodeCurrentDateBlock(t, content[0])
	assertEphemeralUserTextBlock(t, content[1], "hi", "")
}

// Test case 4: Array system prompt becomes one mid-conversation system message.
func TestCheckSystemInstructionsWithMode_ArraySystemStillWorks(t *testing.T) {
	payload := []byte(`{"model":"claude-opus-5","system":[{"type":"text","text":"Be concise."}],"messages":[{"role":"user","content":"hi"}]}`)

	out := checkSystemInstructionsWithMode(payload, false)

	blocks := gjson.GetBytes(out, "system").Array()
	if len(blocks) != 2 {
		t.Fatalf("expected 2 top-level system blocks, got %d", len(blocks))
	}
	content := gjson.GetBytes(out, "messages.0.content").Array()
	if len(content) != 2 {
		t.Fatalf("messages[0].content has %d blocks, want currentDate and user text", len(content))
	}
	assertClaudeCodeCurrentDateBlock(t, content[0])
	assertEphemeralUserTextBlock(t, content[1], "hi", "")
	assertClaudeMidConversationSystemMessage(t, out, 1, "Be concise.", "")
}

func TestCheckSystemInstructionsWithMode_ArraySystemKeepsBlocksAsSeparateMessages(t *testing.T) {
	payload := []byte(`{"model":"claude-opus-5","system":[` +
		`{"type":"text","text":"first guidance","cache_control":{"type":"ephemeral","ttl":"1h"}},` +
		`{"type":"text","text":"second guidance"}],` +
		`"messages":[{"role":"user","content":"hi"}]}`)

	out := checkSystemInstructionsWithMode(payload, false)
	if got := gjson.GetBytes(out, "messages.#").Int(); got != 3 {
		t.Fatalf("message count = %d, want user and two separate system messages: %s", got, out)
	}
	content := gjson.GetBytes(out, "messages.0.content").Array()
	if len(content) != 2 {
		t.Fatalf("user content has %d blocks, want currentDate and user text: %s", len(content), out)
	}
	assertClaudeCodeCurrentDateBlock(t, content[0])
	assertEphemeralUserTextBlock(t, content[1], "hi", "")
	assertClaudeMidConversationSystemMessage(t, out, 1, "first guidance", "")
	assertClaudeMidConversationSystemMessage(t, out, 2, "second guidance", "")
}

func TestRelocateClaudeSystemPromptForCountTokensKeepsBlocksSeparate(t *testing.T) {
	tests := []struct {
		name   string
		model  string
		legacy bool
	}{
		{name: "mid-system model", model: "claude-opus-5"},
		{name: "legacy model", model: "claude-opus-4-6", legacy: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := []byte(`{"model":"` + test.model + `","system":[` +
				`{"type":"text","text":"first guidance"},` +
				`{"type":"text","text":"second guidance"}],` +
				`"messages":[{"role":"user","content":"hi"}]}`)

			out := relocateClaudeSystemPromptForCountTokens(payload, false)
			if gjson.GetBytes(out, "system").Exists() {
				t.Fatalf("count_tokens system must be absent: %s", out)
			}
			if test.legacy {
				content := gjson.GetBytes(out, "messages.0.content").Array()
				if len(content) != 3 {
					t.Fatalf("legacy content has %d blocks, want two reminders and user text: %s", len(content), out)
				}
				if got := content[0].Get("text").String(); got != claudeCallerSystemReminder("first guidance") {
					t.Fatalf("first caller reminder = %q", got)
				}
				if got := content[1].Get("text").String(); got != claudeCallerSystemReminder("second guidance") {
					t.Fatalf("second caller reminder = %q", got)
				}
				if got := content[2].Get("text").String(); got != "hi" {
					t.Fatalf("user text = %q, want hi", got)
				}
				return
			}
			if got := gjson.GetBytes(out, "messages.#").Int(); got != 3 {
				t.Fatalf("message count = %d, want user and two system messages: %s", got, out)
			}
			assertClaudeMidConversationSystemMessage(t, out, 1, "first guidance", "")
			assertClaudeMidConversationSystemMessage(t, out, 2, "second guidance", "")
		})
	}
}

func TestCheckSystemInstructionsWithMode_AdvisorToolResultPreservesTopLevelSystemAndKeepsMessagesIntact(t *testing.T) {
	payload := []byte(`{
		"model": "claude-opus-5",
		"system": [
			{"type": "text", "text": "first guidance"},
			{"type": "text", "text": "second guidance"}
		],
		"messages": [
			{"role": "user", "content": "hello"},
			{
				"role": "assistant",
				"content": [
					{"type": "server_tool_use", "id": "srvtoolu_adv1", "name": "advisor", "input": {}}
				]
			},
			{
				"role": "user",
				"content": [
					{
						"type": "advisor_tool_result",
						"tool_use_id": "srvtoolu_adv1",
						"content": {
							"type": "advisor_redacted_result",
							"encrypted_content": "ciphertext123"
						}
					}
				]
			},
			{"role": "assistant", "content": "advice acknowledged"}
		]
	}`)

	out := checkSystemInstructionsWithMode(payload, false)

	// Messages must NOT have mid-conversation role=system turns inserted,
	// so the message count stays at 4 and roles remain intact.
	if got := gjson.GetBytes(out, "messages.#").Int(); got != 4 {
		t.Fatalf("messages count = %d, want 4 (no mid-conversation system splice): %s", got, out)
	}
	roles := gjson.GetBytes(out, "messages.#.role").Array()
	wantRoles := []string{"user", "assistant", "user", "assistant"}
	for idx, wantRole := range wantRoles {
		if got := roles[idx].String(); got != wantRole {
			t.Fatalf("messages[%d].role = %q, want %q", idx, got, wantRole)
		}
	}

	// Top-level system must retain caller system blocks in addition to Claude Code identity blocks.
	systemBlocks := gjson.GetBytes(out, "system").Array()
	if len(systemBlocks) != 4 {
		t.Fatalf("system blocks count = %d, want 4 (2 identity + 2 caller blocks): %s", len(systemBlocks), out)
	}
	if got := systemBlocks[2].Get("text").String(); got != "first guidance" {
		t.Fatalf("system[2].text = %q, want first guidance", got)
	}
	if got := systemBlocks[3].Get("text").String(); got != "second guidance" {
		t.Fatalf("system[3].text = %q, want second guidance", got)
	}
}

func TestRelocateClaudeSystemPromptForCountTokens_AdvisorToolResultLeavesMessagesUntouched(t *testing.T) {
	payload := []byte(`{
		"model": "claude-opus-5",
		"system": [
			{"type": "text", "text": "first guidance"},
			{"type": "text", "text": "second guidance"}
		],
		"messages": [
			{"role": "user", "content": "hello"},
			{
				"role": "assistant",
				"content": [
					{"type": "server_tool_use", "id": "srvtoolu_adv1", "name": "advisor", "input": {}}
				]
			},
			{
				"role": "user",
				"content": [
					{
						"type": "advisor_tool_result",
						"tool_use_id": "srvtoolu_adv1",
						"content": [
							{
								"type": "advisor_redacted_result",
								"encrypted_content": "ciphertext123"
							}
						]
					}
				]
			}
		]
	}`)

	out := relocateClaudeSystemPromptForCountTokens(payload, false)

	// Caller system blocks must be retained in top-level system so that
	// their tokens are counted, without splicing them into messages[].
	systemBlocks := gjson.GetBytes(out, "system").Array()
	if len(systemBlocks) != 2 {
		t.Fatalf("count_tokens system blocks count = %d, want 2: %s", len(systemBlocks), out)
	}
	if got := systemBlocks[0].Get("text").String(); got != "first guidance" {
		t.Fatalf("system[0].text = %q, want first guidance", got)
	}
	if got := systemBlocks[1].Get("text").String(); got != "second guidance" {
		t.Fatalf("system[1].text = %q, want second guidance", got)
	}

	if got := gjson.GetBytes(out, "messages.#").Int(); got != 3 {
		t.Fatalf("count_tokens messages count = %d, want 3 (no mid-conversation system splice): %s", got, out)
	}
	roles := gjson.GetBytes(out, "messages.#.role").Array()
	wantRoles := []string{"user", "assistant", "user"}
	for idx, wantRole := range wantRoles {
		if got := roles[idx].String(); got != wantRole {
			t.Fatalf("messages[%d].role = %q, want %q", idx, got, wantRole)
		}
	}
}

func TestCheckSystemInstructionsWithMode_UnicodeEscapedAdvisor(t *testing.T) {
	// JSON with unicode-escaped "advisor" name: \u0061dvisor
	payload := []byte(`{
		"model": "claude-opus-5",
		"system": [
			{"type": "text", "text": "guidance"}
		],
		"messages": [
			{"role": "user", "content": "hello"},
			{
				"role": "assistant",
				"content": [
					{"type": "server_tool_use", "id": "srvtoolu_adv1", "name": "\u0061dvisor", "input": {}}
				]
			}
		]
	}`)

	out := checkSystemInstructionsWithMode(payload, false)

	if got := gjson.GetBytes(out, "messages.#").Int(); got != 2 {
		t.Fatalf("messages count = %d, want 2 (no mid-conversation splice): %s", got, out)
	}
	systemBlocks := gjson.GetBytes(out, "system").Array()
	if len(systemBlocks) != 3 {
		t.Fatalf("system blocks count = %d, want 3: %s", len(systemBlocks), out)
	}
	if got := systemBlocks[2].Get("text").String(); got != "guidance" {
		t.Fatalf("system[2].text = %q, want guidance", got)
	}
}

func TestCheckSystemInstructionsWithMode_StandaloneAdvisorCallWithoutResult(t *testing.T) {
	// Assistant made an advisor call, but no result has arrived yet
	payload := []byte(`{
		"model": "claude-opus-5",
		"system": [
			{"type": "text", "text": "guidance"}
		],
		"messages": [
			{"role": "user", "content": "hello"},
			{
				"role": "assistant",
				"content": [
					{"type": "server_tool_use", "id": "srvtoolu_adv1", "name": "advisor", "input": {}}
				]
			}
		]
	}`)

	out := checkSystemInstructionsWithMode(payload, false)

	if got := gjson.GetBytes(out, "messages.#").Int(); got != 2 {
		t.Fatalf("messages count = %d, want 2 (no mid-conversation splice): %s", got, out)
	}
	roles := gjson.GetBytes(out, "messages.#.role").Array()
	wantRoles := []string{"user", "assistant"}
	for idx, wantRole := range wantRoles {
		if got := roles[idx].String(); got != wantRole {
			t.Fatalf("messages[%d].role = %q, want %q", idx, got, wantRole)
		}
	}
	systemBlocks := gjson.GetBytes(out, "system").Array()
	if len(systemBlocks) != 3 {
		t.Fatalf("system blocks count = %d, want 3: %s", len(systemBlocks), out)
	}
	if got := systemBlocks[2].Get("text").String(); got != "guidance" {
		t.Fatalf("system[2].text = %q, want guidance", got)
	}
}

func TestCheckSystemInstructionsWithMode_StandaloneAdvisorResultWithoutCall(t *testing.T) {
	// User message has advisor_tool_result without preceding server_tool_use in the window
	payload := []byte(`{
		"model": "claude-opus-5",
		"system": [
			{"type": "text", "text": "guidance"}
		],
		"messages": [
			{"role": "user", "content": "hello"},
			{
				"role": "user",
				"content": [
					{
						"type": "advisor_tool_result",
						"tool_use_id": "srvtoolu_adv1",
						"content": [
							{
								"type": "advisor_redacted_result",
								"encrypted_content": "ciphertext123"
							}
						]
					}
				]
			}
		]
	}`)

	out := checkSystemInstructionsWithMode(payload, false)

	if got := gjson.GetBytes(out, "messages.#").Int(); got != 2 {
		t.Fatalf("messages count = %d, want 2 (no mid-conversation splice): %s", got, out)
	}
	roles := gjson.GetBytes(out, "messages.#.role").Array()
	wantRoles := []string{"user", "user"}
	for idx, wantRole := range wantRoles {
		if got := roles[idx].String(); got != wantRole {
			t.Fatalf("messages[%d].role = %q, want %q", idx, got, wantRole)
		}
	}
	systemBlocks := gjson.GetBytes(out, "system").Array()
	if len(systemBlocks) != 3 {
		t.Fatalf("system blocks count = %d, want 3: %s", len(systemBlocks), out)
	}
	if got := systemBlocks[2].Get("text").String(); got != "guidance" {
		t.Fatalf("system[2].text = %q, want guidance", got)
	}
}

func TestCheckSystemInstructionsWithMode_NormalTextWithAdvisorWordDoesNotBypassMidSystemSplice(t *testing.T) {
	payload := []byte(`{
		"model": "claude-opus-5",
		"system": [
			{"type": "text", "text": "first guidance"},
			{"type": "text", "text": "second guidance"}
		],
		"messages": [
			{"role": "user", "content": "I need an advisor on financial planning."}
		]
	}`)

	out := checkSystemInstructionsWithMode(payload, false)

	// Since there is no advisor tool invocation/result, normal mid-conversation system insertion occurs.
	if got := gjson.GetBytes(out, "messages.#").Int(); got != 3 {
		t.Fatalf("messages count = %d, want 3 (user + 2 system messages): %s", got, out)
	}
	assertClaudeMidConversationSystemMessage(t, out, 1, "first guidance", "")
	assertClaudeMidConversationSystemMessage(t, out, 2, "second guidance", "")
}

func TestCheckSystemInstructionsWithMode_AdvisorToolResultArrayContent(t *testing.T) {
	payload := []byte(`{
		"model": "claude-opus-5",
		"system": [
			{"type": "text", "text": "guidance"}
		],
		"messages": [
			{"role": "user", "content": "hello"},
			{
				"role": "assistant",
				"content": [
					{"type": "server_tool_use", "id": "srvtoolu_adv1", "name": "advisor", "input": {}}
				]
			},
			{
				"role": "user",
				"content": [
					{
						"type": "advisor_tool_result",
						"tool_use_id": "srvtoolu_adv1",
						"content": [
							{
								"type": "advisor_redacted_result",
								"encrypted_content": "ciphertext123"
							}
						]
					}
				]
			}
		]
	}`)

	out := checkSystemInstructionsWithMode(payload, false)

	if got := gjson.GetBytes(out, "messages.#").Int(); got != 3 {
		t.Fatalf("messages count = %d, want 3: %s", got, out)
	}
	roles := gjson.GetBytes(out, "messages.#.role").Array()
	wantRoles := []string{"user", "assistant", "user"}
	for idx, wantRole := range wantRoles {
		if got := roles[idx].String(); got != wantRole {
			t.Fatalf("messages[%d].role = %q, want %q", idx, got, wantRole)
		}
	}
	systemBlocks := gjson.GetBytes(out, "system").Array()
	if len(systemBlocks) != 3 {
		t.Fatalf("system blocks count = %d, want 3: %s", len(systemBlocks), out)
	}
	if got := systemBlocks[2].Get("text").String(); got != "guidance" {
		t.Fatalf("system[2].text = %q, want guidance", got)
	}
}

func TestCheckSystemInstructionsWithMode_ToolResultWithAdvisorRedactedResult(t *testing.T) {
	payload := []byte(`{
		"model": "claude-opus-5",
		"system": [
			{"type": "text", "text": "guidance"}
		],
		"messages": [
			{"role": "user", "content": "hello"},
			{
				"role": "assistant",
				"content": [
					{"type": "tool_use", "id": "toolu_adv1", "name": "advisor", "input": {}}
				]
			},
			{
				"role": "user",
				"content": [
					{
						"type": "tool_result",
						"tool_use_id": "toolu_adv1",
						"content": [
							{
								"type": "advisor_redacted_result",
								"encrypted_content": "ciphertext123"
							}
						]
					}
				]
			}
		]
	}`)

	out := checkSystemInstructionsWithMode(payload, false)

	if got := gjson.GetBytes(out, "messages.#").Int(); got != 3 {
		t.Fatalf("messages count = %d, want 3: %s", got, out)
	}
	roles := gjson.GetBytes(out, "messages.#.role").Array()
	wantRoles := []string{"user", "assistant", "user"}
	for idx, wantRole := range wantRoles {
		if got := roles[idx].String(); got != wantRole {
			t.Fatalf("messages[%d].role = %q, want %q", idx, got, wantRole)
		}
	}
	systemBlocks := gjson.GetBytes(out, "system").Array()
	if len(systemBlocks) != 3 {
		t.Fatalf("system blocks count = %d, want 3: %s", len(systemBlocks), out)
	}
	if got := systemBlocks[2].Get("text").String(); got != "guidance" {
		t.Fatalf("system[2].text = %q, want guidance", got)
	}
}

func TestCheckSystemInstructionsWithMode_ClientToolNamedAdvisorRelocatesSystemPrompt(t *testing.T) {
	// A client tool (e.g. MCP tool) happens to be named "advisor".
	// It uses ordinary "tool_use" (not "server_tool_use") and returns a string "tool_result".
	// The caller's system prompt must be relocated to mid-conversation system messages,
	// NOT hoisted into the top-level system array.
	payload := []byte(`{
		"model": "claude-opus-5",
		"system": [
			{"type": "text", "text": "caller guidance"}
		],
		"messages": [
			{"role": "user", "content": "hello"},
			{
				"role": "assistant",
				"content": [
					{"type": "tool_use", "id": "toolu_client1", "name": "advisor", "input": {"query": "help"}}
				]
			},
			{
				"role": "user",
				"content": [
					{
						"type": "tool_result",
						"tool_use_id": "toolu_client1",
						"content": "client advice text"
					}
				]
			}
		]
	}`)

	out := checkSystemInstructionsWithMode(payload, false)

	// Caller prompt must be relocated to a mid-conversation system message,
	// so the top-level system must only have the 2 Claude Code cloak blocks.
	systemBlocks := gjson.GetBytes(out, "system").Array()
	if len(systemBlocks) != 2 {
		t.Fatalf("system blocks count = %d, want 2 (caller prompt must be relocated, not hoisted): %s", len(systemBlocks), out)
	}
	for i, b := range systemBlocks {
		if strings.Contains(b.Get("text").String(), "caller guidance") {
			t.Fatalf("system[%d] unexpectedly contains caller guidance: %s", i, b.Raw)
		}
	}
	assertClaudeMidConversationSystemMessage(t, out, 1, "caller guidance", "")
}

func TestRelocateClaudeSystemPromptForCountTokens_ClientToolNamedAdvisorRelocatesSystemPrompt(t *testing.T) {
	payload := []byte(`{
		"model": "claude-opus-5",
		"system": [
			{"type": "text", "text": "caller guidance"}
		],
		"messages": [
			{"role": "user", "content": "hello"},
			{
				"role": "assistant",
				"content": [
					{"type": "tool_use", "id": "toolu_client1", "name": "advisor", "input": {"query": "help"}}
				]
			},
			{
				"role": "user",
				"content": [
					{
						"type": "tool_result",
						"tool_use_id": "toolu_client1",
						"content": "client advice text"
					}
				]
			}
		]
	}`)

	out := relocateClaudeSystemPromptForCountTokens(payload, false)

	if gjson.GetBytes(out, "system").Exists() {
		t.Fatalf("count_tokens system field should have been relocated out of top-level system: %s", out)
	}
	assertClaudeMidConversationSystemMessage(t, out, 1, "caller guidance", "")
}

// Test case 5: Special characters survive the mid-conversation system move.
func TestCheckSystemInstructionsWithMode_StringWithSpecialChars(t *testing.T) {
	payload := []byte(`{"model":"claude-opus-5","system":"Use <xml> tags & \"quotes\" in output.","messages":[{"role":"user","content":"hi"}]}`)

	out := checkSystemInstructionsWithMode(payload, false)

	wantSystem := `Use <xml> tags & "quotes" in output.`
	if got := gjson.GetBytes(out, "system.#").Int(); got != 2 {
		t.Fatalf("top-level system block count = %d, want 2", got)
	}
	content := gjson.GetBytes(out, "messages.0.content").Array()
	if len(content) != 2 {
		t.Fatalf("messages[0].content has %d blocks, want 2", len(content))
	}
	assertClaudeCodeCurrentDateBlock(t, content[0])
	assertEphemeralUserTextBlock(t, content[1], "hi", "")
	assertClaudeMidConversationSystemMessage(t, out, 1, wantSystem, "")
}

func TestCheckSystemInstructionsWithSigningMode_LongPromptIsExactAndIdempotent(t *testing.T) {
	wantSystem := "\nPI_SYSTEM_BEGIN\nEmbedded reference: # currentDate\nToday's date is caller-owned text.\n" + strings.Repeat("Preserve tools, policies, and caller semantics exactly.\n", 560) + "PI_SYSTEM_END  \n"
	payloadMap := map[string]any{
		"model":  "claude-opus-5",
		"system": wantSystem,
		"messages": []any{map[string]any{
			"role":    "user",
			"content": "hello",
		}},
	}
	payload, errMarshal := json.Marshal(payloadMap)
	if errMarshal != nil {
		t.Fatalf("marshal payload: %v", errMarshal)
	}

	first := checkSystemInstructionsWithSigningMode(payload, false, true, "2.1.258", "cli", "")
	second := checkSystemInstructionsWithSigningMode(first, false, true, "2.1.258", "cli", "")
	if !bytes.Equal(first, second) {
		t.Fatalf("complete cloak layout is not byte-idempotent:\nfirst:  %s\nsecond: %s", first, second)
	}
	if got := gjson.GetBytes(first, "system.#").Int(); got != 2 {
		t.Fatalf("top-level system block count = %d, want 2", got)
	}
	if got := gjson.GetBytes(first, "messages.#").Int(); got != 2 {
		t.Fatalf("message count = %d, want user then system", got)
	}
	content := gjson.GetBytes(first, "messages.0.content").Array()
	if len(content) != 2 {
		t.Fatalf("user content has %d blocks, want currentDate and user text", len(content))
	}
	assertClaudeCodeCurrentDateBlock(t, content[0])
	assertEphemeralUserTextBlock(t, content[1], "hello", "")
	assertClaudeMidConversationSystemMessage(t, first, 1, wantSystem, "")
	if strings.Contains(content[0].Get("text").String(), "PI_SYSTEM_BEGIN") || strings.Contains(content[1].Get("text").String(), "PI_SYSTEM_BEGIN") {
		t.Fatal("caller system prompt leaked into the user content blocks")
	}
	if !bytes.Contains(first, []byte(`<system-reminder>`)) || bytes.Contains(first, []byte(`\u003csystem-reminder`)) {
		t.Fatalf("currentDate reminder angle brackets must remain literal JSON bytes")
	}

	signed, errSign := finalizeAnthropicMessagesBodyCCH(first, "")
	if errSign != nil {
		t.Fatalf("finalize Claude CCH: %v", errSign)
	}
	resigned, errResign := finalizeAnthropicMessagesBodyCCH(signed, "")
	if errResign != nil {
		t.Fatalf("re-finalize Claude CCH: %v", errResign)
	}
	if !bytes.Equal(signed, resigned) {
		t.Fatal("CCH finalization is not byte-idempotent after long prompt preservation")
	}
}

func TestClaudeExecutor_CustomBaseURLPreservesBodyByDefault(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seenBody = bytes.Clone(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-3-5-sonnet","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-123",
		"base_url": server.URL,
	}}
	payload := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`)

	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-3-5-sonnet-20241022",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if len(seenBody) == 0 {
		t.Fatal("expected request body to be captured")
	}

	if strings.Contains(string(seenBody), "x-anthropic-billing-header:") || strings.Contains(string(seenBody), "cch=") {
		t.Fatalf("default custom BaseURL request must not inject billing/CCH: %s", seenBody)
	}
}

func TestClaudeExecutor_CustomBaseURLAPIKeyDoesNotEnableCCHSigning(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seenBody = bytes.Clone(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-3-5-sonnet","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey:                 "key-123",
			BaseURL:                server.URL,
			ExperimentalCCHSigning: true,
		}},
	})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-123",
		"base_url": server.URL,
	}}
	const messageText = "please keep literal cch=00000 in this message"
	payload := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"please keep literal cch=00000 in this message"}]}]}`)

	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-3-5-sonnet-20241022",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if len(seenBody) == 0 {
		t.Fatal("expected request body to be captured")
	}
	if got := gjson.GetBytes(seenBody, "messages.0.content.0.text").String(); got != messageText {
		t.Fatalf("message text = %q, want %q", got, messageText)
	}
	if strings.Contains(string(seenBody), "x-anthropic-billing-header:") {
		t.Fatalf("default custom BaseURL request must not inject a billing header: %s", seenBody)
	}
}

func TestClaudeExecutor_CustomBaseURLOAuthGeneratesMissingCCH(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seenBody = bytes.Clone(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-opus-4-6","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{
		Attributes: map[string]string{
			"api_key":    "sk-ant-oat-custom-cch",
			"base_url":   server.URL,
			"cloak_mode": "never",
		},
		Metadata: claudeOAuthTestMetadata(),
	}
	payload := []byte(`{"model":"claude-opus-4-6","system":"keep original system","messages":[{"role":"user","content":"hello"}],"max_tokens":64}`)

	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-opus-4-6",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatClaude})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if _, ok := claudeBillingCCHDigitsOffset(seenBody); !ok {
		t.Fatalf("Claude OAuth custom BaseURL body is missing generated CCH: %s", seenBody)
	}
	if got := gjson.GetBytes(seenBody, "system.1.text").String(); got != "keep original system" {
		t.Fatalf("system.1.text = %q, want preserved system text", got)
	}
}

func TestClaudeExecutor_RebuildMidSystemMessageDisabledByDefault(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seenBody = bytes.Clone(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-3-5-sonnet","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey:  "key-123",
			BaseURL: server.URL,
		}},
	})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-123",
		"base_url": server.URL,
	}}
	payload := []byte(`{"system":[{"type":"text","text":"Top rule","cache_control":{"type":"ephemeral"}}],"messages":[{"role":"user","content":[{"type":"text","text":"hi"}]},{"role":"system","content":"Mid rule"},{"role":"user","content":[{"type":"text","text":"continue"}]}],"metadata":{"user_id":"{\"device_id\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"account_uuid\":\"\",\"session_id\":\"11111111-2222-4333-8444-555555555555\"}"}}`)
	ctx := contextWithGinHeaders(map[string]string{
		"User-Agent":     "claude-cli/2.1.258 (external, cli)",
		"X-App":          "cli",
		"Anthropic-Beta": "claude-code-20250219",
	})

	_, errExecute := executor.Execute(ctx, auth, cliproxyexecutor.Request{
		Model:   "claude-3-5-sonnet-20241022",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if len(seenBody) == 0 {
		t.Fatal("expected request body to be captured")
	}
	if got := gjson.GetBytes(seenBody, "system.0.text").String(); got != "Top rule" {
		t.Fatalf("system.0.text = %q, want top-level system preserved", got)
	}
	if got := gjson.GetBytes(seenBody, `messages.#(role=="system").content`).String(); got != "Mid rule" {
		t.Fatalf("mid system message = %q, want original message preserved", got)
	}
}

func TestClaudeExecutor_RebuildMidSystemMessageOptInMovesSystemMessages(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seenBody = bytes.Clone(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-3-5-sonnet","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey:                  "key-123",
			BaseURL:                 server.URL,
			RebuildMidSystemMessage: true,
		}},
	})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-123",
		"base_url": server.URL,
	}}
	payload := []byte(`{"system":"Top rule","messages":[{"role":"user","content":[{"type":"text","text":"hi"}]},{"role":"system","content":"Mid string rule"},{"role":"assistant","content":[{"type":"text","text":"ok"}]},{"role":"system","content":[{"type":"text","text":"Mid array rule","cache_control":{"type":"ephemeral"}}]},{"role":"user","content":[{"type":"text","text":"continue"}]}],"metadata":{"user_id":"{\"device_id\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"account_uuid\":\"\",\"session_id\":\"11111111-2222-4333-8444-555555555555\"}"}}`)
	ctx := contextWithGinHeaders(map[string]string{
		"User-Agent":     "claude-cli/2.1.258 (external, cli)",
		"X-App":          "cli",
		"Anthropic-Beta": "claude-code-20250219",
	})

	_, errExecute := executor.Execute(ctx, auth, cliproxyexecutor.Request{
		Model:   "claude-3-5-sonnet-20241022",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude")})
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if len(seenBody) == 0 {
		t.Fatal("expected request body to be captured")
	}

	system := gjson.GetBytes(seenBody, "system").Array()
	if len(system) != 3 {
		t.Fatalf("system has %d items, want 3: %s", len(system), gjson.GetBytes(seenBody, "system").Raw)
	}
	wantTexts := []string{"Top rule", "Mid string rule", "Mid array rule"}
	for i, want := range wantTexts {
		if got := system[i].Get("text").String(); got != want {
			t.Fatalf("system[%d].text = %q, want %q", i, got, want)
		}
	}
	if got := gjson.GetBytes(seenBody, "system.2.cache_control.type").String(); got != "ephemeral" {
		t.Fatalf("system.2.cache_control.type = %q, want ephemeral", got)
	}
	if gjson.GetBytes(seenBody, `messages.#(role=="system")`).Exists() {
		t.Fatalf("messages should not contain system role after rebuild: %s", gjson.GetBytes(seenBody, "messages").Raw)
	}
	if got := gjson.GetBytes(seenBody, "messages.#").Int(); got != 3 {
		t.Fatalf("messages count = %d, want 3", got)
	}
}

func TestResolveClaudeWirePolicy(t *testing.T) {
	tests := []struct {
		name      string
		confirmed bool
		mode      string
		wantCloak bool
	}{
		{name: "unknown auto", mode: "auto", wantCloak: true},
		{name: "unknown always", mode: "always", wantCloak: true},
		{name: "unknown never", mode: "never", wantCloak: false},
		{name: "confirmed auto", confirmed: true, mode: "auto", wantCloak: false},
		{name: "confirmed always", confirmed: true, mode: "always", wantCloak: false},
		{name: "confirmed never", confirmed: true, mode: "never", wantCloak: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			auth := &cliproxyauth.Auth{Metadata: map[string]any{"cloak_mode": test.mode}}
			policy, _ := resolveClaudeWirePolicy(&config.Config{}, auth, "sk-ant-oat-test", test.confirmed)
			if !policy.OAuth {
				t.Fatal("resolveClaudeWirePolicy() OAuth = false, want true")
			}
			if policy.ConfirmedClaudeCode != test.confirmed {
				t.Fatalf("ConfirmedClaudeCode = %v, want %v", policy.ConfirmedClaudeCode, test.confirmed)
			}
			if policy.Cloak != test.wantCloak {
				t.Fatalf("Cloak = %v, want %v", policy.Cloak, test.wantCloak)
			}
		})
	}
}

func TestApplyCloaking_PreservesConfiguredStrictModeAndSensitiveWordsWhenModeOmitted(t *testing.T) {
	cfg := &config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey: "key-123",
			Cloak: &config.CloakConfig{
				StrictMode:     true,
				SensitiveWords: []string{"proxy"},
			},
		}},
	}
	auth := &cliproxyauth.Auth{Attributes: map[string]string{"api_key": "key-123"}}
	payload := []byte(`{"system":"proxy rules","messages":[{"role":"user","content":[{"type":"text","text":"proxy access"}]}]}`)

	out, cloaked, errCloaking := applyCloaking(
		context.Background(),
		cfg,
		auth,
		payload,
		"key-123",
		false,
		false,
	)
	if errCloaking != nil {
		t.Fatalf("applyCloaking() error = %v", errCloaking)
	}

	if !cloaked {
		t.Fatal("applyCloaking() cloaked = false, want true")
	}
	blocks := gjson.GetBytes(out, "system").Array()
	if len(blocks) != 2 {
		t.Fatalf("expected strict mode to keep the 2 injected Claude CLI system blocks, got %d", len(blocks))
	}
	content := gjson.GetBytes(out, "messages.0.content").Array()
	if len(content) != 2 {
		t.Fatalf("strict mode should add only currentDate before user text, got %d content blocks", len(content))
	}
	assertClaudeCodeCurrentDateBlock(t, content[0])
	if got := content[1].Get("text").String(); !strings.Contains(got, "\u200B") {
		t.Fatalf("expected configured sensitive word obfuscation to apply, got %q", got)
	}
}

func TestApplyCloaking_FableInjectsFallbacksAndDisplayUpdates(t *testing.T) {
	cfg := &config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey: "sk-ant-oat-fable-test",
			Cloak:  &config.CloakConfig{},
		}},
	}
	auth := &cliproxyauth.Auth{Attributes: map[string]string{"api_key": "sk-ant-oat-fable-test"}}
	payload := []byte(`{"model":"claude-fable-5-1","thinking":{"type":"adaptive"},"messages":[{"role":"user","content":"test"}]}`)

	out, cloaked, err := applyCloaking(
		context.Background(),
		cfg,
		auth,
		payload,
		"sk-ant-oat-fable-test",
		false,
		true,
	)
	if err != nil {
		t.Fatalf("applyCloaking() error = %v", err)
	}
	if !cloaked {
		t.Fatal("applyCloaking() cloaked = false, want true")
	}

	fallbacks := gjson.GetBytes(out, "fallbacks").Array()
	if len(fallbacks) != 1 || fallbacks[0].Get("model").String() != "claude-opus-5" {
		t.Fatalf("expected fallbacks=[{\"model\":\"claude-opus-5\"}], got: %s", gjson.GetBytes(out, "fallbacks").Raw)
	}

	systemBlocks := gjson.GetBytes(out, "system").Array()
	if len(systemBlocks) != 3 {
		t.Fatalf("expected 3 system blocks for Fable cloaking (billing, identity, reporting outcomes), got %d", len(systemBlocks))
	}
	if !strings.Contains(systemBlocks[2].Get("text").String(), "Reporting outcomes") {
		t.Fatalf("expected system block 2 to contain Reporting outcomes, got: %s", systemBlocks[2].Get("text").String())
	}
	if systemBlocks[2].Get("cache_control").Exists() {
		t.Fatalf("system block 2 for Reporting outcomes should have no cache_control, got: %s", systemBlocks[2].Get("cache_control").Raw)
	}

	display := gjson.GetBytes(out, "thinking.display").String()
	if display != "updates" {
		t.Fatalf("expected thinking.display=updates, got: %q", display)
	}

	betas := claudeCodeCLIBetas(out, nil, true)
	if !strings.Contains(betas, "server-side-fallback-2026-06-01") {
		t.Fatalf("expected server-side-fallback beta in betas, got: %s", betas)
	}
	if !strings.Contains(betas, "thinking-display-updates-2026-08-18") {
		t.Fatalf("expected thinking-display-updates beta in betas, got: %s", betas)
	}
	if strings.Contains(betas, "redact-thinking-2026-02-12") {
		t.Fatalf("expected redact-thinking beta to be dropped when display=updates, got: %s", betas)
	}
}

func TestApplyCloaking_SonnetOmitsReportingOutcomes(t *testing.T) {
	cfg := &config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey: "sk-ant-oat-sonnet-test",
			Cloak:  &config.CloakConfig{},
		}},
	}
	auth := &cliproxyauth.Auth{Attributes: map[string]string{"api_key": "sk-ant-oat-sonnet-test"}}
	payload := []byte(`{"model":"claude-sonnet-5","messages":[{"role":"user","content":"test"}]}`)

	out, cloaked, err := applyCloaking(
		context.Background(),
		cfg,
		auth,
		payload,
		"sk-ant-oat-sonnet-test",
		false,
		true,
	)
	if err != nil {
		t.Fatalf("applyCloaking() error = %v", err)
	}
	if !cloaked {
		t.Fatal("applyCloaking() cloaked = false, want true")
	}

	systemBlocks := gjson.GetBytes(out, "system").Array()
	if len(systemBlocks) != 2 {
		t.Fatalf("expected 2 system blocks for Sonnet (billing, identity only), got %d", len(systemBlocks))
	}
	for i, b := range systemBlocks {
		if strings.Contains(b.Get("text").String(), "Reporting outcomes") {
			t.Fatalf("system block %d should not contain Reporting outcomes on non-Fable model, got: %s", i, b.Get("text").String())
		}
	}
}

func TestApplyCloaking_DisabledByConfigLeavesFableUntouched(t *testing.T) {
	cfg := &config.Config{
		DisableClaudeCloakMode: true,
	}
	auth := &cliproxyauth.Auth{Attributes: map[string]string{"api_key": "sk-ant-oat-fable-test"}}
	originalSystem := "You are a custom assistant for my company."
	payload := []byte(`{"model":"claude-fable-5-1","system":"` + originalSystem + `","messages":[{"role":"user","content":"test"}]}`)

	out, cloaked, err := applyCloaking(
		context.Background(),
		cfg,
		auth,
		payload,
		"sk-ant-oat-fable-test",
		false,
		true,
	)
	if err != nil {
		t.Fatalf("applyCloaking() error = %v", err)
	}
	if cloaked {
		t.Fatal("applyCloaking() cloaked = true, want false when DisableClaudeCloakMode is true")
	}
	if got := gjson.GetBytes(out, "system").String(); got != originalSystem {
		t.Fatalf("expected system to be preserved unchanged, got: %s", got)
	}
	if gjson.GetBytes(out, "fallbacks").Exists() {
		t.Fatalf("expected no fallbacks injected when cloaking is disabled, got: %s", gjson.GetBytes(out, "fallbacks").Raw)
	}
}

func TestApplyCloaking_NativeClaudeCodeLeavesFableUntouched(t *testing.T) {
	cfg := &config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey: "sk-ant-oat-fable-test",
			Cloak:  &config.CloakConfig{},
		}},
	}
	auth := &cliproxyauth.Auth{Attributes: map[string]string{"api_key": "sk-ant-oat-fable-test"}}
	originalSystem := "You are a native claude code agent."
	payload := []byte(`{"model":"claude-fable-5-1","system":"` + originalSystem + `","messages":[{"role":"user","content":"test"}]}`)

	out, cloaked, err := applyCloaking(
		context.Background(),
		cfg,
		auth,
		payload,
		"sk-ant-oat-fable-test",
		true, // confirmedClaudeCode = true
		true,
	)
	if err != nil {
		t.Fatalf("applyCloaking() error = %v", err)
	}
	if cloaked {
		t.Fatal("applyCloaking() cloaked = true, want false for confirmed native Claude Code")
	}
	if got := gjson.GetBytes(out, "system").String(); got != originalSystem {
		t.Fatalf("expected system to be preserved unchanged for native client, got: %s", got)
	}
}

func TestApplyCloaking_Fable5OmitsFallbacksAndReportingOutcomes(t *testing.T) {
	cfg := &config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey: "sk-ant-oat-fable5-test",
			Cloak:  &config.CloakConfig{},
		}},
	}
	auth := &cliproxyauth.Auth{Attributes: map[string]string{"api_key": "sk-ant-oat-fable5-test"}}
	payload := []byte(`{"model":"claude-fable-5","messages":[{"role":"user","content":"test"}]}`)

	out, cloaked, err := applyCloaking(
		context.Background(),
		cfg,
		auth,
		payload,
		"sk-ant-oat-fable5-test",
		false,
		true,
	)
	if err != nil {
		t.Fatalf("applyCloaking() error = %v", err)
	}
	if !cloaked {
		t.Fatal("applyCloaking() cloaked = false, want true")
	}

	if gjson.GetBytes(out, "fallbacks").Exists() {
		t.Fatalf("claude-fable-5 should not have fallbacks injected, got: %s", gjson.GetBytes(out, "fallbacks").Raw)
	}

	systemBlocks := gjson.GetBytes(out, "system").Array()
	if len(systemBlocks) != 2 {
		t.Fatalf("expected 2 system blocks for claude-fable-5, got %d", len(systemBlocks))
	}
	for _, b := range systemBlocks {
		if strings.Contains(b.Get("text").String(), "Reporting outcomes") {
			t.Fatalf("claude-fable-5 should not contain Reporting outcomes, got: %s", b.Get("text").String())
		}
	}
}

func TestClaudeExecutor_TitleHelperWithSystemPromptIsolated(t *testing.T) {
	helps.ResetClaudeDiagnosticsForTest()
	defer helps.ResetClaudeDiagnosticsForTest()

	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("request-id", "req_helper123")
		_, _ = w.Write([]byte(`{"id":"msg_helper123","type":"message","model":"claude-sonnet-5","role":"assistant","content":[{"type":"text","text":"Title"}]}`))
	}))
	defer server.Close()

	payload := []byte(`{"model":"claude-sonnet-5","system":"Return a short title summarizing this conversation","messages":[{"role":"user","content":"test"}]}`)
	cfg := &config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey: "sk-ant-oat-title-test",
			Cloak:  &config.CloakConfig{},
		}},
	}
	auth := &cliproxyauth.Auth{
		ID:       "auth-title-test",
		Metadata: claudeOAuthTestMetadata(),
		Attributes: map[string]string{
			"api_key":  "sk-ant-oat-title-test",
			"base_url": server.URL,
		},
	}

	executor := NewClaudeExecutor(cfg)
	ctx := helps.WithClaudeSessionID(context.Background(), "session-title-1")
	_, err := executor.Execute(ctx, auth, cliproxyexecutor.Request{
		Model:   "claude-sonnet-5",
		Payload: payload,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatClaude,
	})
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}

	// Title helper must NOT carry diagnostics
	if gjson.GetBytes(seenBody, "diagnostics").Exists() {
		t.Fatalf("expected title helper to omit diagnostics, got: %s", gjson.GetBytes(seenBody, "diagnostics").Raw)
	}

	// Title helper must NOT advance session continuity state
	credID := claudeDiagnosticsCredentialIdentity(auth)
	_, _, prevMsg := helps.BeginClaudeDiagnostics(credID, "session-title-1")
	if prevMsg != "" {
		t.Fatalf("expected title helper to leave prevMsg empty, got: %q", prevMsg)
	}
}

func TestClaudeExecutor_SubagentAndProbeOmit1hCacheTTLAndBeta(t *testing.T) {
	var seenBody []byte
	var seenHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		seenHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_sub1","type":"message","model":"claude-sonnet-5","role":"assistant","content":[{"type":"text","text":"ok"}]}`))
	}))
	defer server.Close()

	cfg := &config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey: "sk-ant-oat-subagent-cache-test",
			Cloak:  &config.CloakConfig{},
		}},
	}
	auth := &cliproxyauth.Auth{
		ID:       "auth-subagent-cache-test",
		Metadata: claudeOAuthTestMetadata(),
		Attributes: map[string]string{
			"api_key":  "sk-ant-oat-subagent-cache-test",
			"base_url": server.URL,
		},
	}

	executor := NewClaudeExecutor(cfg)

	// 1. Subagent request: carries X-Claude-Code-Agent-Id header
	subagentPayload := []byte(`{"model":"claude-sonnet-5","messages":[{"role":"user","content":"do task"}]}`)
	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-sonnet-5",
		Payload: subagentPayload,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatClaude,
		Headers: http.Header{
			"X-Claude-Code-Agent-Id": {"subagent-123"},
		},
	})
	if err != nil {
		t.Fatalf("Execute(subagent) error = %v", err)
	}
	if strings.Contains(seenHeaders.Get("Anthropic-Beta"), "extended-cache-ttl-2025-04-11") {
		t.Fatalf("subagent must not carry extended-cache-ttl beta, got: %s", seenHeaders.Get("Anthropic-Beta"))
	}
	for _, blk := range gjson.GetBytes(seenBody, "system").Array() {
		if blk.Get("cache_control.ttl").String() == "1h" {
			t.Fatalf("subagent system block must not carry ttl: 1h, got: %s", blk.Raw)
		}
	}

	// 2. Probe request: max_tokens: 1
	probePayload := []byte(`{"model":"claude-sonnet-5","max_tokens":1,"messages":[{"role":"user","content":"probe"}]}`)
	_, err = executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-sonnet-5",
		Payload: probePayload,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatClaude,
	})
	if err != nil {
		t.Fatalf("Execute(probe) error = %v", err)
	}
	if strings.Contains(seenHeaders.Get("Anthropic-Beta"), "extended-cache-ttl-2025-04-11") {
		t.Fatalf("probe must not carry extended-cache-ttl beta, got: %s", seenHeaders.Get("Anthropic-Beta"))
	}
	for _, blk := range gjson.GetBytes(seenBody, "system").Array() {
		if blk.Get("cache_control.ttl").String() == "1h" {
			t.Fatalf("probe system block must not carry ttl: 1h, got: %s", blk.Raw)
		}
	}

	// 3. Normal interactive main-thread request: MUST carry 1h cache and beta
	mainPayload := []byte(`{"model":"claude-sonnet-5","messages":[{"role":"user","content":"hello"}]}`)
	_, err = executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-sonnet-5",
		Payload: mainPayload,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatClaude,
	})
	if err != nil {
		t.Fatalf("Execute(main) error = %v", err)
	}
	if !strings.Contains(seenHeaders.Get("Anthropic-Beta"), "extended-cache-ttl-2025-04-11") {
		t.Fatalf("main thread request must carry extended-cache-ttl beta, got: %s", seenHeaders.Get("Anthropic-Beta"))
	}
	has1h := false
	for _, blk := range gjson.GetBytes(seenBody, "system").Array() {
		if blk.Get("cache_control.ttl").String() == "1h" {
			has1h = true
			break
		}
	}
	if !has1h {
		t.Fatalf("main thread request system block must carry ttl: 1h, got: %s", gjson.GetBytes(seenBody, "system").Raw)
	}

	// 4. Confirmed native Claude Code subagent: must NOT have extended-cache-ttl restored
	confirmedSubagentPayload := []byte(`{"model":"claude-sonnet-5","messages":[{"role":"user","content":"task"}]}`)
	_, err = executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-sonnet-5",
		Payload: confirmedSubagentPayload,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatClaude,
		Headers: http.Header{
			"User-Agent":             {"claude-cli/2.1.258 (external, cli)"},
			"X-Claude-Code-Agent-Id": {"subagent-confirmed-456"},
			"Anthropic-Beta":         {"claude-code-20250219,oauth-2025-04-20,effort-2025-11-24"},
		},
	})
	if err != nil {
		t.Fatalf("Execute(confirmed subagent) error = %v", err)
	}
	if strings.Contains(seenHeaders.Get("Anthropic-Beta"), "extended-cache-ttl-2025-04-11") {
		t.Fatalf("confirmed subagent must not carry extended-cache-ttl beta, got: %s", seenHeaders.Get("Anthropic-Beta"))
	}
}

func TestClaudeExecutor_PayloadOverrideFableModelReconciled(t *testing.T) {
	var seenBody []byte
	var seenHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		seenHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-sonnet-5","role":"assistant","content":[{"type":"text","text":"ok"}]}`))
	}))
	defer server.Close()

	cfg := &config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey: "sk-ant-oat-payload-fable-test",
			Cloak:  &config.CloakConfig{},
		}},
		Payload: config.PayloadConfig{
			Override: []config.PayloadRule{{
				Models: []config.PayloadModelRule{{Name: "claude-fable-5-1"}},
				Params: map[string]any{
					"model": "claude-sonnet-5",
				},
			}},
		},
	}
	auth := &cliproxyauth.Auth{
		ID:       "auth-payload-fable-test",
		Metadata: claudeOAuthTestMetadata(),
		Attributes: map[string]string{
			"api_key":  "sk-ant-oat-payload-fable-test",
			"base_url": server.URL,
		},
	}

	executor := NewClaudeExecutor(cfg)
	payload := []byte(`{"model":"claude-fable-5-1","thinking":{"type":"adaptive"},"messages":[{"role":"user","content":"test"}]}`)
	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-fable-5-1",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatClaude})
	if err != nil {
		t.Fatalf("Execute error = %v", err)
	}

	// Model was rewritten to claude-sonnet-5
	if got := gjson.GetBytes(seenBody, "model").String(); got != "claude-sonnet-5" {
		t.Fatalf("model = %q, want claude-sonnet-5", got)
	}

	// Because model is now claude-sonnet-5, Fable additions must NOT be present:
	if gjson.GetBytes(seenBody, "fallbacks").Exists() {
		t.Fatalf("fallbacks must be omitted when rewritten to non-Fable, got: %s", gjson.GetBytes(seenBody, "fallbacks").Raw)
	}
	if strings.Contains(seenHeaders.Get("Anthropic-Beta"), "server-side-fallback") {
		t.Fatalf("server-side-fallback beta must be omitted when rewritten to non-Fable, got: %s", seenHeaders.Get("Anthropic-Beta"))
	}
	for _, blk := range gjson.GetBytes(seenBody, "system").Array() {
		if strings.Contains(blk.Get("text").String(), "Reporting outcomes") {
			t.Fatalf("system must not contain Reporting outcomes when rewritten to non-Fable, got: %s", blk.Raw)
		}
	}
}

func TestClaudeExecutor_PayloadOverrideNonFableToFableReconciled(t *testing.T) {
	var seenBody []byte
	var seenHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		seenHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-fable-5-1","role":"assistant","content":[{"type":"text","text":"ok"}]}`))
	}))
	defer server.Close()

	cfg := &config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey: "sk-ant-oat-payload-fable-test-2",
			Cloak:  &config.CloakConfig{},
		}},
		Payload: config.PayloadConfig{
			Override: []config.PayloadRule{{
				Models: []config.PayloadModelRule{{Name: "claude-sonnet-5"}},
				Params: map[string]any{
					"model": "claude-fable-5-1",
				},
			}},
		},
	}
	auth := &cliproxyauth.Auth{
		ID:       "auth-payload-fable-test-2",
		Metadata: claudeOAuthTestMetadata(),
		Attributes: map[string]string{
			"api_key":  "sk-ant-oat-payload-fable-test-2",
			"base_url": server.URL,
		},
	}

	executor := NewClaudeExecutor(cfg)
	payload := []byte(`{"model":"claude-sonnet-5","thinking":{"type":"adaptive"},"messages":[{"role":"user","content":"test"}]}`)
	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-sonnet-5",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatClaude})
	if err != nil {
		t.Fatalf("Execute error = %v", err)
	}

	// Model was rewritten to claude-fable-5-1
	if got := gjson.GetBytes(seenBody, "model").String(); got != "claude-fable-5-1" {
		t.Fatalf("model = %q, want claude-fable-5-1", got)
	}

	// Fable additions must now be attached:
	fallbacks := gjson.GetBytes(seenBody, "fallbacks").Array()
	if len(fallbacks) != 1 || fallbacks[0].Get("model").String() != "claude-opus-5" {
		t.Fatalf("fallbacks must be injected for Fable 5.1, got: %s", gjson.GetBytes(seenBody, "fallbacks").Raw)
	}
	if !strings.Contains(seenHeaders.Get("Anthropic-Beta"), "server-side-fallback") {
		t.Fatalf("server-side-fallback beta must be present, got: %s", seenHeaders.Get("Anthropic-Beta"))
	}
	hasReporting := false
	for _, blk := range gjson.GetBytes(seenBody, "system").Array() {
		if strings.Contains(blk.Get("text").String(), "Reporting outcomes") {
			hasReporting = true
			break
		}
	}
	if !hasReporting {
		t.Fatalf("system must contain Reporting outcomes for Fable 5.1, got: %s", gjson.GetBytes(seenBody, "system").Raw)
	}
}

func TestClaudeExecutor_PayloadOverridePreservesExplicitFallbacks(t *testing.T) {
	var seenBody []byte
	var seenHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		seenHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-sonnet-5","role":"assistant","content":[{"type":"text","text":"ok"}]}`))
	}))
	defer server.Close()

	cfg := &config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey: "sk-ant-oat-payload-fable-test-3",
			Cloak:  &config.CloakConfig{},
		}},
		Payload: config.PayloadConfig{
			Override: []config.PayloadRule{{
				Models: []config.PayloadModelRule{{Name: "claude-fable-5-1"}},
				Params: map[string]any{
					"model":     "claude-sonnet-5",
					"fallbacks": []any{map[string]any{"model": "claude-opus-5"}},
				},
			}},
		},
	}
	auth := &cliproxyauth.Auth{
		ID:       "auth-payload-fable-test-3",
		Metadata: claudeOAuthTestMetadata(),
		Attributes: map[string]string{
			"api_key":  "sk-ant-oat-payload-fable-test-3",
			"base_url": server.URL,
		},
	}

	executor := NewClaudeExecutor(cfg)
	payload := []byte(`{"model":"claude-fable-5-1","thinking":{"type":"adaptive"},"messages":[{"role":"user","content":"test"}]}`)
	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-fable-5-1",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatClaude})
	if err != nil {
		t.Fatalf("Execute error = %v", err)
	}

	// Explicit payload fallback override must be preserved!
	fallbacks := gjson.GetBytes(seenBody, "fallbacks").Array()
	if len(fallbacks) != 1 || fallbacks[0].Get("model").String() != "claude-opus-5" {
		t.Fatalf("explicit payload fallback override must be preserved, got: %s", gjson.GetBytes(seenBody, "fallbacks").Raw)
	}
	if !strings.Contains(seenHeaders.Get("Anthropic-Beta"), "server-side-fallback") {
		t.Fatalf("server-side-fallback beta must be present for explicit fallback, got: %s", seenHeaders.Get("Anthropic-Beta"))
	}
}

func TestClaudeExecutor_PayloadOverrideUnrelatedModelRuleDoesNotPreserveFableFallbacks(t *testing.T) {
	var seenBody []byte
	var seenHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		seenHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-sonnet-5","role":"assistant","content":[{"type":"text","text":"ok"}]}`))
	}))
	defer server.Close()

	cfg := &config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey: "sk-ant-oat-payload-fable-test-4",
			Cloak:  &config.CloakConfig{},
		}},
		Payload: config.PayloadConfig{
			Override: []config.PayloadRule{
				// Rule 1: Unrelated rule for gpt-4 has fallbacks
				{
					Models: []config.PayloadModelRule{{Name: "gpt-4"}},
					Params: map[string]any{
						"fallbacks": []any{map[string]any{"model": "claude-opus-5"}},
					},
				},
				// Rule 2: Rewrites Fable 5.1 to Sonnet 5 WITHOUT fallbacks
				{
					Models: []config.PayloadModelRule{{Name: "claude-fable-5-1"}},
					Params: map[string]any{
						"model": "claude-sonnet-5",
					},
				},
			},
		},
	}
	auth := &cliproxyauth.Auth{
		ID:       "auth-payload-fable-test-4",
		Metadata: claudeOAuthTestMetadata(),
		Attributes: map[string]string{
			"api_key":  "sk-ant-oat-payload-fable-test-4",
			"base_url": server.URL,
		},
	}

	executor := NewClaudeExecutor(cfg)
	payload := []byte(`{"model":"claude-fable-5-1","thinking":{"type":"adaptive"},"messages":[{"role":"user","content":"test"}]}`)
	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-fable-5-1",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatClaude})
	if err != nil {
		t.Fatalf("Execute error = %v", err)
	}

	// Unrelated rule must NOT preserve fallback on Sonnet 5
	if gjson.GetBytes(seenBody, "fallbacks").Exists() {
		t.Fatalf("unrelated rule for gpt-4 must not cause fallbacks to be preserved on sonnet-5, got: %s", gjson.GetBytes(seenBody, "fallbacks").Raw)
	}
	if strings.Contains(seenHeaders.Get("Anthropic-Beta"), "server-side-fallback") {
		t.Fatalf("server-side-fallback beta must be omitted, got: %s", seenHeaders.Get("Anthropic-Beta"))
	}
}

func TestClaudeExecutor_PayloadOverrideMaxTokensTo1ReclassifiesAsProbe(t *testing.T) {
	var seenBody []byte
	var seenHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		seenHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_probe1","type":"message","model":"claude-sonnet-5","role":"assistant","content":[{"type":"text","text":"."}]}`))
	}))
	defer server.Close()

	cfg := &config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey: "sk-ant-oat-payload-probe-test",
			Cloak:  &config.CloakConfig{},
		}},
		Payload: config.PayloadConfig{
			Override: []config.PayloadRule{{
				Models: []config.PayloadModelRule{{Name: "claude-sonnet-5"}},
				Params: map[string]any{
					"max_tokens": 1,
				},
			}},
		},
	}
	auth := &cliproxyauth.Auth{
		ID:       "auth-payload-probe-test",
		Metadata: claudeOAuthTestMetadata(),
		Attributes: map[string]string{
			"api_key":  "sk-ant-oat-payload-probe-test",
			"base_url": server.URL,
		},
	}

	executor := NewClaudeExecutor(cfg)
	payload := []byte(`{"model":"claude-sonnet-5","max_tokens":1000,"messages":[{"role":"user","content":"."}]}`)
	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-sonnet-5",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatClaude})
	if err != nil {
		t.Fatalf("Execute error = %v", err)
	}

	// Payload rule made it max_tokens: 1
	if got := gjson.GetBytes(seenBody, "max_tokens").Int(); got != 1 {
		t.Fatalf("max_tokens = %d, want 1", got)
	}

	// Probe must NOT carry 1h cache control and must NOT carry extended-cache-ttl beta
	if strings.Contains(seenHeaders.Get("Anthropic-Beta"), "extended-cache-ttl-2025-04-11") {
		t.Fatalf("reclassified probe must not carry extended-cache-ttl beta, got: %s", seenHeaders.Get("Anthropic-Beta"))
	}
	for _, blk := range gjson.GetBytes(seenBody, "system").Array() {
		if blk.Get("cache_control.ttl").String() == "1h" {
			t.Fatalf("reclassified probe system block must not carry ttl: 1h, got: %s", blk.Raw)
		}
	}

	// Probe must NOT carry diagnostics
	if gjson.GetBytes(seenBody, "diagnostics").Exists() {
		t.Fatalf("reclassified probe must omit diagnostics, got: %s", gjson.GetBytes(seenBody, "diagnostics").Raw)
	}

	// Probe must NOT carry cc_prev_req or cc_prompt_id in billing header
	billingText := gjson.GetBytes(seenBody, "system.0.text").String()
	if strings.Contains(billingText, "cc_prev_req=") {
		t.Fatalf("reclassified probe must omit cc_prev_req, got: %s", billingText)
	}
	if strings.Contains(billingText, "cc_prompt_id=") {
		t.Fatalf("reclassified probe must omit cc_prompt_id, got: %s", billingText)
	}
}

func TestClaudeExecutor_PayloadOverrideFableToProbeStripsFableAdditions(t *testing.T) {
	var seenBody []byte
	var seenHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		seenHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-fable-5-1","role":"assistant","content":[{"type":"text","text":"ok"}]}`))
	}))
	defer server.Close()

	cfg := &config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey: "sk-ant-oat-payload-fable-probe-strip-test",
			Cloak:  &config.CloakConfig{},
		}},
		Payload: config.PayloadConfig{
			Override: []config.PayloadRule{{
				Models: []config.PayloadModelRule{{Name: "claude-fable-5-1"}},
				Params: map[string]any{
					"max_tokens": 1,
				},
			}},
		},
	}
	auth := &cliproxyauth.Auth{
		ID:       "auth-payload-fable-probe-strip-test",
		Metadata: claudeOAuthTestMetadata(),
		Attributes: map[string]string{
			"api_key":  "sk-ant-oat-payload-fable-probe-strip-test",
			"base_url": server.URL,
		},
	}

	executor := NewClaudeExecutor(cfg)
	// Initially non-probe (max_tokens: 1000, content: ".")
	payload := []byte(`{"model":"claude-fable-5-1","thinking":{"type":"adaptive"},"max_tokens":1000,"messages":[{"role":"user","content":"."}]}`)
	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-fable-5-1",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatClaude})
	if err != nil {
		t.Fatalf("Execute error = %v", err)
	}

	// Because payload rule reclassified request as probe (max_tokens: 1):
	// 1. fallbacks must be stripped
	if gjson.GetBytes(seenBody, "fallbacks").Exists() {
		t.Fatalf("probe must not carry fallbacks, got: %s", gjson.GetBytes(seenBody, "fallbacks").Raw)
	}
	// 2. thinking.display must be stripped
	if gjson.GetBytes(seenBody, "thinking.display").Exists() {
		t.Fatalf("probe must not carry thinking.display, got: %s", gjson.GetBytes(seenBody, "thinking.display").Raw)
	}
	// 3. Reporting outcomes block must be stripped
	for _, blk := range gjson.GetBytes(seenBody, "system").Array() {
		if strings.Contains(blk.Get("text").String(), "Reporting outcomes") {
			t.Fatalf("probe must not carry Reporting outcomes block, got: %s", blk.Raw)
		}
	}
	// 4. Beta headers must omit server-side-fallback, thinking-display-updates, and extended-cache-ttl
	betas := seenHeaders.Get("Anthropic-Beta")
	if strings.Contains(betas, "server-side-fallback") {
		t.Fatalf("probe must omit server-side-fallback beta, got: %s", betas)
	}
	if strings.Contains(betas, "thinking-display-updates") {
		t.Fatalf("probe must omit thinking-display-updates beta, got: %s", betas)
	}
	if strings.Contains(betas, "extended-cache-ttl") {
		t.Fatalf("probe must omit extended-cache-ttl beta, got: %s", betas)
	}
}

func TestClaudeExecutor_PayloadOverrideProbeToNormalReinitializes(t *testing.T) {
	var seenBody []byte
	var seenHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		seenHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-fable-5-1","role":"assistant","content":[{"type":"text","text":"ok"}]}`))
	}))
	defer server.Close()

	cfg := &config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey: "sk-ant-oat-payload-declassify-probe-test",
			Cloak:  &config.CloakConfig{},
		}},
		Payload: config.PayloadConfig{
			Override: []config.PayloadRule{{
				Models: []config.PayloadModelRule{{Name: "claude-fable-5-1"}},
				Params: map[string]any{
					"max_tokens": 1000,
				},
			}},
		},
	}
	auth := &cliproxyauth.Auth{
		ID:       "auth-payload-declassify-probe-test",
		Metadata: claudeOAuthTestMetadata(),
		Attributes: map[string]string{
			"api_key":  "sk-ant-oat-payload-declassify-probe-test",
			"base_url": server.URL,
		},
	}

	executor := NewClaudeExecutor(cfg)
	// Initially a probe (max_tokens: 1, content: ".")
	payload := []byte(`{"model":"claude-fable-5-1","thinking":{"type":"adaptive"},"max_tokens":1,"messages":[{"role":"user","content":"."}]}`)
	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-fable-5-1",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatClaude})
	if err != nil {
		t.Fatalf("Execute error = %v", err)
	}

	// Declassified probe is now a normal request:
	// 1. Must carry 1h cache TTL and extended-cache-ttl beta
	has1h := false
	for _, blk := range gjson.GetBytes(seenBody, "system").Array() {
		if blk.Get("cache_control.ttl").String() == "1h" {
			has1h = true
			break
		}
	}
	if !has1h {
		t.Fatalf("declassified normal request must carry 1h cache, got: %s", gjson.GetBytes(seenBody, "system").Raw)
	}
	betas := seenHeaders.Get("Anthropic-Beta")
	if !strings.Contains(betas, "extended-cache-ttl-2025-04-11") {
		t.Fatalf("declassified normal request must carry extended-cache-ttl beta, got: %s", betas)
	}
	// 2. Must carry Fable additions (fallbacks, display, reporting block)
	if !gjson.GetBytes(seenBody, "fallbacks").Exists() {
		t.Fatalf("declassified Fable request must carry fallbacks")
	}

	// 3. Must carry cc_prompt_id in billing header
	billingText := gjson.GetBytes(seenBody, "system.0.text").String()
	if !strings.Contains(billingText, "cc_prompt_id=") {
		t.Fatalf("declassified normal request must carry cc_prompt_id, got: %s", billingText)
	}
}

func TestClaudeExecutor_CallerOwnedDiagnosticsPreservedOnProbe(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-haiku-4-5-20251001","role":"assistant","content":[{"type":"text","text":"ok"}]}`))
	}))
	defer server.Close()

	cfg := &config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey: "sk-ant-api-caller-diagnostics-test",
			Cloak:  &config.CloakConfig{Mode: "never"},
		}},
	}
	auth := &cliproxyauth.Auth{
		ID: "auth-caller-diagnostics-test",
		Attributes: map[string]string{
			"api_key":  "sk-ant-api-caller-diagnostics-test",
			"base_url": server.URL,
		},
	}

	executor := NewClaudeExecutor(cfg)
	// Caller sends max_tokens: 1 probe with their own explicit diagnostics object
	payload := []byte(`{"model":"claude-haiku-4-5-20251001","max_tokens":1,"diagnostics":{"caller_custom_key":"val123"},"messages":[{"role":"user","content":"quota"}]}`)
	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-haiku-4-5-20251001",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatClaude})
	if err != nil {
		t.Fatalf("Execute error = %v", err)
	}

	// Caller-owned diagnostics must be preserved!
	if got := gjson.GetBytes(seenBody, "diagnostics.caller_custom_key").String(); got != "val123" {
		t.Fatalf("caller diagnostics must be preserved, got: %s", gjson.GetBytes(seenBody, "diagnostics").Raw)
	}
}

func TestClaudeExecutor_PayloadOverrideParentThinkingPreventsDisplayUpdates(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-fable-5-1","role":"assistant","content":[{"type":"text","text":"ok"}]}`))
	}))
	defer server.Close()

	cfg := &config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey: "sk-ant-oat-payload-parent-thinking-test",
			Cloak:  &config.CloakConfig{},
		}},
		Payload: config.PayloadConfig{
			Override: []config.PayloadRule{{
				Models: []config.PayloadModelRule{{Name: "claude-fable-5-1"}},
				Params: map[string]any{
					"thinking": map[string]any{
						"type": "adaptive",
					},
				},
			}},
		},
	}
	auth := &cliproxyauth.Auth{
		ID:       "auth-payload-parent-thinking-test",
		Metadata: claudeOAuthTestMetadata(),
		Attributes: map[string]string{
			"api_key":  "sk-ant-oat-payload-parent-thinking-test",
			"base_url": server.URL,
		},
	}

	executor := NewClaudeExecutor(cfg)
	payload := []byte(`{"model":"claude-fable-5-1","thinking":{"type":"adaptive"},"messages":[{"role":"user","content":"test"}]}`)
	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-fable-5-1",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatClaude})
	if err != nil {
		t.Fatalf("Execute error = %v", err)
	}

	// Payload rule replaced parent "thinking" without "display", so "display" must NOT be re-added!
	if gjson.GetBytes(seenBody, "thinking.display").Exists() {
		t.Fatalf("thinking.display must not be injected when parent thinking was overridden, got: %s", gjson.GetBytes(seenBody, "thinking").Raw)
	}
}

func TestClaudeExecutor_PayloadSystemTTLOverrideStillRemovesInjectedFableReportingBlock(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-sonnet-5","role":"assistant","content":[{"type":"text","text":"ok"}]}`))
	}))
	defer server.Close()

	cfg := &config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey: "sk-ant-oat-payload-system-ttl-fable-test",
			Cloak:  &config.CloakConfig{},
		}},
		Payload: config.PayloadConfig{
			Override: []config.PayloadRule{{
				Models: []config.PayloadModelRule{{Name: "claude-fable-5-1"}},
				Params: map[string]any{
					"model":                      "claude-sonnet-5",
					"system.0.cache_control.ttl": "1h",
				},
			}},
		},
	}
	auth := &cliproxyauth.Auth{
		ID:       "auth-payload-system-ttl-fable-test",
		Metadata: claudeOAuthTestMetadata(),
		Attributes: map[string]string{
			"api_key":  "sk-ant-oat-payload-system-ttl-fable-test",
			"base_url": server.URL,
		},
	}

	executor := NewClaudeExecutor(cfg)
	payload := []byte(`{"model":"claude-fable-5-1","thinking":{"type":"adaptive"},"messages":[{"role":"user","content":"test"}]}`)
	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-fable-5-1",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatClaude})
	if err != nil {
		t.Fatalf("Execute error = %v", err)
	}

	// Model was rewritten from Fable 5.1 to Sonnet 5, so injected Reporting outcomes block
	// MUST be removed even though payload rule touched system.0.cache_control.ttl!
	for _, blk := range gjson.GetBytes(seenBody, "system").Array() {
		if strings.Contains(blk.Get("text").String(), "Reporting outcomes") {
			t.Fatalf("Reporting outcomes block must be removed on rewritten Sonnet model, got: %s", blk.Raw)
		}
	}
}

func TestClaudeExecutor_PayloadSonnetToFableWithSystemTTLEditsAddsReportingBlock(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-fable-5-1","role":"assistant","content":[{"type":"text","text":"ok"}]}`))
	}))
	defer server.Close()

	cfg := &config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey: "sk-ant-oat-payload-sonnet-to-fable-test",
			Cloak:  &config.CloakConfig{},
		}},
		Payload: config.PayloadConfig{
			Override: []config.PayloadRule{{
				Models: []config.PayloadModelRule{{Name: "claude-sonnet-5"}},
				Params: map[string]any{
					"model":                      "claude-fable-5-1",
					"system.1.cache_control.ttl": "1h",
				},
			}},
		},
	}
	auth := &cliproxyauth.Auth{
		ID:       "auth-payload-sonnet-to-fable-test",
		Metadata: claudeOAuthTestMetadata(),
		Attributes: map[string]string{
			"api_key":  "sk-ant-oat-payload-sonnet-to-fable-test",
			"base_url": server.URL,
		},
	}

	executor := NewClaudeExecutor(cfg)
	payload := []byte(`{"model":"claude-sonnet-5","thinking":{"type":"adaptive"},"messages":[{"role":"user","content":"test"}]}`)
	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-sonnet-5",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatClaude})
	if err != nil {
		t.Fatalf("Execute error = %v", err)
	}

	// Model was rewritten from Sonnet 5 to Fable 5.1, so Reporting outcomes block
	// MUST be added even though payload rule touched system.1.cache_control.ttl!
	hasReporting := false
	for _, blk := range gjson.GetBytes(seenBody, "system").Array() {
		if strings.Contains(blk.Get("text").String(), "Reporting outcomes") {
			hasReporting = true
			break
		}
	}
	if !hasReporting {
		t.Fatalf("Reporting outcomes block must be attached on rewritten Fable model, got: %s", gjson.GetBytes(seenBody, "system").Raw)
	}
}

func TestClaudeExecutor_PayloadOverrideProbeWithExplicitDiagnosticsPreserved(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-haiku-4-5-20251001","role":"assistant","content":[{"type":"text","text":"ok"}]}`))
	}))
	defer server.Close()

	cfg := &config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey: "sk-ant-oat-probe-explicit-diag-test",
			Cloak:  &config.CloakConfig{},
		}},
		Payload: config.PayloadConfig{
			Override: []config.PayloadRule{{
				Models: []config.PayloadModelRule{{Name: "claude-haiku-4-5-20251001"}},
				Params: map[string]any{
					"max_tokens": 1,
					"diagnostics": map[string]any{
						"operator_custom": "custom_value_123",
					},
				},
			}},
		},
	}
	auth := &cliproxyauth.Auth{
		ID:       "auth-probe-explicit-diag-test",
		Metadata: claudeOAuthTestMetadata(),
		Attributes: map[string]string{
			"api_key":  "sk-ant-oat-probe-explicit-diag-test",
			"base_url": server.URL,
		},
	}

	executor := NewClaudeExecutor(cfg)
	// Initially non-probe so CPA injects diagnostics, then payload rule overrides to probe AND sets custom diagnostics
	payload := []byte(`{"model":"claude-haiku-4-5-20251001","max_tokens":1000,"messages":[{"role":"user","content":"quota"}]}`)
	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-haiku-4-5-20251001",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatClaude})
	if err != nil {
		t.Fatalf("Execute error = %v", err)
	}

	// The operator-provided diagnostics object must be preserved!
	if got := gjson.GetBytes(seenBody, "diagnostics.operator_custom").String(); got != "custom_value_123" {
		t.Fatalf("operator custom diagnostics must be preserved, got: %s", gjson.GetBytes(seenBody, "diagnostics").Raw)
	}
}

func TestClaudeExecutor_PayloadStringSystemFableAddsReportingBlock(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-fable-5-1","role":"assistant","content":[{"type":"text","text":"ok"}]}`))
	}))
	defer server.Close()

	cfg := &config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey: "sk-ant-oat-string-system-fable-test",
			Cloak:  &config.CloakConfig{},
		}},
		Payload: config.PayloadConfig{
			Override: []config.PayloadRule{{
				Models: []config.PayloadModelRule{{Name: "claude-sonnet-5"}},
				Params: map[string]any{
					"model":  "claude-fable-5-1",
					"system": "You are a helpful coding assistant.",
				},
			}},
		},
	}
	auth := &cliproxyauth.Auth{
		ID:       "auth-string-system-fable-test",
		Metadata: claudeOAuthTestMetadata(),
		Attributes: map[string]string{
			"api_key":  "sk-ant-oat-string-system-fable-test",
			"base_url": server.URL,
		},
	}

	executor := NewClaudeExecutor(cfg)
	payload := []byte(`{"model":"claude-sonnet-5","thinking":{"type":"adaptive"},"messages":[{"role":"user","content":"test"}]}`)
	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-sonnet-5",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatClaude})
	if err != nil {
		t.Fatalf("Execute error = %v", err)
	}

	// Payload rule set string system and rewrote to Fable 5.1:
	// System must become an array containing the reporting outcomes block!
	hasReporting := false
	for _, blk := range gjson.GetBytes(seenBody, "system").Array() {
		if strings.Contains(blk.Get("text").String(), "Reporting outcomes") {
			hasReporting = true
			break
		}
	}
	if !hasReporting {
		t.Fatalf("Reporting outcomes block must be attached for string system Fable request, got: %s", gjson.GetBytes(seenBody, "system").Raw)
	}
}

func TestClaudeExecutor_PayloadStringSystemMentioningReportingOutcomesStillInjectsFableReportingBlock(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-fable-5-1","role":"assistant","content":[{"type":"text","text":"ok"}]}`))
	}))
	defer server.Close()

	cfg := &config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey: "sk-ant-oat-string-system-mention-test",
			Cloak:  &config.CloakConfig{},
		}},
		Payload: config.PayloadConfig{
			Override: []config.PayloadRule{{
				Models: []config.PayloadModelRule{{Name: "claude-sonnet-5"}},
				Params: map[string]any{
					"model":  "claude-fable-5-1",
					"system": "Please follow best practices when reporting outcomes to the user.",
				},
			}},
		},
	}
	auth := &cliproxyauth.Auth{
		ID:       "auth-string-system-mention-test",
		Metadata: claudeOAuthTestMetadata(),
		Attributes: map[string]string{
			"api_key":  "sk-ant-oat-string-system-mention-test",
			"base_url": server.URL,
		},
	}

	executor := NewClaudeExecutor(cfg)
	payload := []byte(`{"model":"claude-sonnet-5","thinking":{"type":"adaptive"},"messages":[{"role":"user","content":"test"}]}`)
	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-sonnet-5",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatClaude})
	if err != nil {
		t.Fatalf("Execute error = %v", err)
	}

	// Payload rule had a system string that merely mentioned "reporting outcomes".
	// The exact `# Reporting outcomes` block MUST be injected!
	hasExactReporting := false
	for _, blk := range gjson.GetBytes(seenBody, "system").Array() {
		if blk.Get("text").String() == claudeCodeFableReportingOutcomes {
			hasExactReporting = true
			break
		}
	}
	if !hasExactReporting {
		t.Fatalf("exact `# Reporting outcomes` block must be injected even when string mentions reporting outcomes, got: %s", gjson.GetBytes(seenBody, "system").Raw)
	}
}

func TestClaudeExecutor_PayloadStringSystemWithExactReportingPromptDoesNotDuplicate(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-fable-5-1","role":"assistant","content":[{"type":"text","text":"ok"}]}`))
	}))
	defer server.Close()

	cfg := &config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey: "sk-ant-oat-string-system-exact-test",
			Cloak:  &config.CloakConfig{},
		}},
		Payload: config.PayloadConfig{
			Override: []config.PayloadRule{{
				Models: []config.PayloadModelRule{{Name: "claude-sonnet-5"}},
				Params: map[string]any{
					"model":  "claude-fable-5-1",
					"system": claudeCodeFableReportingOutcomes,
				},
			}},
		},
	}
	auth := &cliproxyauth.Auth{
		ID:       "auth-string-system-exact-test",
		Metadata: claudeOAuthTestMetadata(),
		Attributes: map[string]string{
			"api_key":  "sk-ant-oat-string-system-exact-test",
			"base_url": server.URL,
		},
	}

	executor := NewClaudeExecutor(cfg)
	payload := []byte(`{"model":"claude-sonnet-5","thinking":{"type":"adaptive"},"messages":[{"role":"user","content":"test"}]}`)
	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-sonnet-5",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatClaude})
	if err != nil {
		t.Fatalf("Execute error = %v", err)
	}

	reportingCount := 0
	for _, blk := range gjson.GetBytes(seenBody, "system").Array() {
		if blk.Get("text").String() == claudeCodeFableReportingOutcomes {
			reportingCount++
		}
	}
	if reportingCount != 1 {
		t.Fatalf("expected exactly 1 reporting block, got %d in: %s", reportingCount, gjson.GetBytes(seenBody, "system").Raw)
	}
}

func TestClaudeExecutor_PayloadFableThinkingAdaptiveToDisabledDropsInjectedDisplay(t *testing.T) {
	var seenHeaders http.Header
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		seenHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-fable-5-1","role":"assistant","content":[{"type":"text","text":"ok"}]}`))
	}))
	defer server.Close()

	cfg := &config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey: "sk-ant-oat-fable-disabled-thinking-test",
			Cloak:  &config.CloakConfig{},
		}},
		Payload: config.PayloadConfig{
			Override: []config.PayloadRule{{
				Models: []config.PayloadModelRule{{Name: "claude-fable-5-1"}},
				Params: map[string]any{
					"thinking.type": "disabled",
				},
			}},
		},
	}
	auth := &cliproxyauth.Auth{
		ID:       "auth-fable-disabled-thinking-test",
		Metadata: claudeOAuthTestMetadata(),
		Attributes: map[string]string{
			"api_key":  "sk-ant-oat-fable-disabled-thinking-test",
			"base_url": server.URL,
		},
	}

	executor := NewClaudeExecutor(cfg)
	// Starts with adaptive thinking so CPA cloaking injects thinking.display=updates,
	// then payload rule overrides thinking.type to disabled:
	payload := []byte(`{"model":"claude-fable-5-1","thinking":{"type":"adaptive"},"messages":[{"role":"user","content":"test"}]}`)
	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-fable-5-1",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatClaude})
	if err != nil {
		t.Fatalf("Execute error = %v", err)
	}

	// Injected thinking.display must be dropped
	if gjson.GetBytes(seenBody, "thinking.display").Exists() {
		t.Fatalf("thinking.display must be dropped when thinking.type is disabled, got: %s", gjson.GetBytes(seenBody, "thinking").Raw)
	}
	// thinking-display-updates beta header must NOT be present
	betas := seenHeaders.Get("anthropic-beta")
	if strings.Contains(betas, "thinking-display-updates") {
		t.Fatalf("thinking-display-updates beta header must NOT be present on disabled thinking, got: %s", betas)
	}
}

func TestClaudeExecutor_UncloakedProbePreservesCallerBillingTags(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-haiku-4-5-20251001","role":"assistant","content":[{"type":"text","text":"ok"}]}`))
	}))
	defer server.Close()

	cfg := &config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey: "sk-ant-api03-uncloaked-test",
			// No CloakConfig, uncloaked request
		}},
	}
	auth := &cliproxyauth.Auth{
		ID: "auth-uncloaked-probe-test",
		Attributes: map[string]string{
			"api_key":  "sk-ant-api03-uncloaked-test",
			"base_url": server.URL,
		},
	}

	executor := NewClaudeExecutor(cfg)
	// Caller provides their own billing header with prompt ID on probe
	callerBilling := "x-anthropic-billing-header: cc_version=2.1.258; cc_entrypoint=cli; cch=abc12; cc_prompt_id=00000000-0000-4000-8000-000000000001;"
	payload := []byte(fmt.Sprintf(`{"model":"claude-haiku-4-5-20251001","max_tokens":1,"system":[{"type":"text","text":%q}],"messages":[{"role":"user","content":"quota"}]}`, callerBilling))

	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-haiku-4-5-20251001",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatClaude})
	if err != nil {
		t.Fatalf("Execute error = %v", err)
	}

	// Because cloaking was disabled, the caller-owned billing header must be preserved exactly!
	gotSystem := gjson.GetBytes(seenBody, "system.0.text").String()
	if !strings.Contains(gotSystem, "cc_prompt_id=00000000-0000-4000-8000-000000000001") {
		t.Fatalf("uncloaked request must preserve caller billing tags on probe, got: %s", gotSystem)
	}
}

func TestClaudeExecutor_FableWithSensitiveWordsHasSingleObfuscatedReportingBlock(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-fable-5-1","role":"assistant","content":[{"type":"text","text":"ok"}]}`))
	}))
	defer server.Close()

	cfg := &config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey: "sk-ant-oat-fable-sensitive-test",
			Cloak: &config.CloakConfig{
				SensitiveWords: []string{"Reporting"},
			},
		}},
	}
	auth := &cliproxyauth.Auth{
		ID:       "auth-fable-sensitive-test",
		Metadata: claudeOAuthTestMetadata(),
		Attributes: map[string]string{
			"api_key":  "sk-ant-oat-fable-sensitive-test",
			"base_url": server.URL,
		},
	}

	executor := NewClaudeExecutor(cfg)
	payload := []byte(`{"model":"claude-fable-5-1","thinking":{"type":"adaptive"},"messages":[{"role":"user","content":"test"}]}`)
	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-fable-5-1",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatClaude})
	if err != nil {
		t.Fatalf("Execute error = %v", err)
	}

	reportingCount := 0
	for _, blk := range gjson.GetBytes(seenBody, "system").Array() {
		raw := blk.Get("text").String()
		cleaned := strings.ReplaceAll(raw, "\u200B", "")
		if cleaned == claudeCodeFableReportingOutcomes {
			reportingCount++
			if !strings.Contains(raw, "\u200B") {
				t.Fatalf("Reporting block must be obfuscated with zero-width space, got: %q", raw)
			}
			if strings.Contains(raw, "Reporting") {
				t.Fatalf("Reporting block must not contain cleartext sensitive word 'Reporting', got: %q", raw)
			}
		}
	}
	if reportingCount != 1 {
		t.Fatalf("expected exactly 1 reporting block, got %d; system = %s", reportingCount, gjson.GetBytes(seenBody, "system").Raw)
	}
}

func TestClaudeExecutor_PayloadSonnetToFableWithSensitiveWordsObfuscatesInjectedReportingBlock(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-fable-5-1","role":"assistant","content":[{"type":"text","text":"ok"}]}`))
	}))
	defer server.Close()

	cfg := &config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey: "sk-ant-oat-sonnet-to-fable-sensitive-test",
			Cloak: &config.CloakConfig{
				SensitiveWords: []string{"Reporting"},
			},
		}},
		Payload: config.PayloadConfig{
			Override: []config.PayloadRule{{
				Models: []config.PayloadModelRule{{Name: "claude-sonnet-5"}},
				Params: map[string]any{
					"model": "claude-fable-5-1",
				},
			}},
		},
	}
	auth := &cliproxyauth.Auth{
		ID:       "auth-sonnet-to-fable-sensitive-test",
		Metadata: claudeOAuthTestMetadata(),
		Attributes: map[string]string{
			"api_key":  "sk-ant-oat-sonnet-to-fable-sensitive-test",
			"base_url": server.URL,
		},
	}

	executor := NewClaudeExecutor(cfg)
	payload := []byte(`{"model":"claude-sonnet-5","thinking":{"type":"adaptive"},"messages":[{"role":"user","content":"test"}]}`)
	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-sonnet-5",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatClaude})
	if err != nil {
		t.Fatalf("Execute error = %v", err)
	}

	reportingCount := 0
	for _, blk := range gjson.GetBytes(seenBody, "system").Array() {
		raw := blk.Get("text").String()
		cleaned := strings.ReplaceAll(raw, "\u200B", "")
		if cleaned == claudeCodeFableReportingOutcomes {
			reportingCount++
			if !strings.Contains(raw, "\u200B") {
				t.Fatalf("Reporting block must be obfuscated with zero-width space, got: %q", raw)
			}
			if strings.Contains(raw, "Reporting") {
				t.Fatalf("Reporting block must not contain cleartext sensitive word 'Reporting', got: %q", raw)
			}
		}
	}
	if reportingCount != 1 {
		t.Fatalf("expected exactly 1 reporting block, got %d; system = %s", reportingCount, gjson.GetBytes(seenBody, "system").Raw)
	}
}

func TestClaudeExecutor_PayloadFableToSonnetWithSensitiveWordsRemovesReportingBlock(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-sonnet-5","role":"assistant","content":[{"type":"text","text":"ok"}]}`))
	}))
	defer server.Close()

	cfg := &config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey: "sk-ant-oat-fable-to-sonnet-sensitive-test",
			Cloak: &config.CloakConfig{
				SensitiveWords: []string{"Reporting"},
			},
		}},
		Payload: config.PayloadConfig{
			Override: []config.PayloadRule{{
				Models: []config.PayloadModelRule{{Name: "claude-fable-5-1"}},
				Params: map[string]any{
					"model": "claude-sonnet-5",
				},
			}},
		},
	}
	auth := &cliproxyauth.Auth{
		ID:       "auth-fable-to-sonnet-sensitive-test",
		Metadata: claudeOAuthTestMetadata(),
		Attributes: map[string]string{
			"api_key":  "sk-ant-oat-fable-to-sonnet-sensitive-test",
			"base_url": server.URL,
		},
	}

	executor := NewClaudeExecutor(cfg)
	payload := []byte(`{"model":"claude-fable-5-1","thinking":{"type":"adaptive"},"messages":[{"role":"user","content":"test"}]}`)
	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-fable-5-1",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatClaude})
	if err != nil {
		t.Fatalf("Execute error = %v", err)
	}

	for _, blk := range gjson.GetBytes(seenBody, "system").Array() {
		raw := blk.Get("text").String()
		cleaned := strings.ReplaceAll(raw, "\u200B", "")
		if cleaned == claudeCodeFableReportingOutcomes {
			t.Fatalf("reporting block should be removed when rewritten to Sonnet 5, got: %s", raw)
		}
	}
}

func TestClaudeExecutor_SensitiveWordsDoNotCorruptBillingHeaderTags(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-fable-5-1","role":"assistant","content":[{"type":"text","text":"ok"}]}`))
	}))
	defer server.Close()

	cfg := &config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey: "sk-ant-oat-billing-corrupt-test",
			Cloak: &config.CloakConfig{
				SensitiveWords: []string{"cli", "version", "entrypoint", "prompt", "anthropic"},
			},
		}},
	}
	auth := &cliproxyauth.Auth{
		ID:       "auth-billing-corrupt-test",
		Metadata: claudeOAuthTestMetadata(),
		Attributes: map[string]string{
			"api_key":  "sk-ant-oat-billing-corrupt-test",
			"base_url": server.URL,
		},
	}

	executor := NewClaudeExecutor(cfg)
	payload := []byte(`{"model":"claude-fable-5-1","thinking":{"type":"adaptive"},"messages":[{"role":"user","content":"test"}]}`)
	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-fable-5-1",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatClaude})
	if err != nil {
		t.Fatalf("Execute error = %v", err)
	}

	// system[0] billing header must NOT contain zero-width spaces in its tags
	billingText := gjson.GetBytes(seenBody, "system.0.text").String()
	if !strings.HasPrefix(billingText, "x-anthropic-billing-header: cc_version=") {
		t.Fatalf("billing header must start cleanly without obfuscation, got: %q", billingText)
	}
	if strings.Contains(billingText, "\u200B") {
		t.Fatalf("billing header must not contain zero-width space characters, got: %q", billingText)
	}
	if !strings.Contains(billingText, "cc_entrypoint=cli;") {
		t.Fatalf("billing header must preserve cc_entrypoint=cli;, got: %q", billingText)
	}
}

func TestClaudeExecutor_DisabledCloakingSkipsSensitiveWordObfuscation(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-sonnet-5","role":"assistant","content":[{"type":"text","text":"ok"}]}`))
	}))
	defer server.Close()

	cfg := &config.Config{
		DisableClaudeCloakMode: true,
		ClaudeKey: []config.ClaudeKey{{
			APIKey: "sk-ant-oat-skip-obfuscate-test",
			Cloak: &config.CloakConfig{
				SensitiveWords: []string{"confidential", "secret"},
			},
		}},
	}
	auth := &cliproxyauth.Auth{
		ID:       "auth-skip-obfuscate-test",
		Metadata: claudeOAuthTestMetadata(),
		Attributes: map[string]string{
			"api_key":  "sk-ant-oat-skip-obfuscate-test",
			"base_url": server.URL,
		},
	}

	executor := NewClaudeExecutor(cfg)
	payload := []byte(`{"model":"claude-sonnet-5","system":[{"type":"text","text":"this is confidential"}],"messages":[{"role":"user","content":"keep this secret"}]}`)
	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-sonnet-5",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatClaude})
	if err != nil {
		t.Fatalf("Execute error = %v", err)
	}

	rawBody := string(seenBody)
	if strings.Contains(rawBody, "\u200B") {
		t.Fatalf("disabled cloaking must not insert zero-width spaces into Execute body, got: %s", rawBody)
	}
	if !strings.Contains(rawBody, "confidential") || !strings.Contains(rawBody, "secret") {
		t.Fatalf("expected cleartext preserved in Execute, got: %s", rawBody)
	}
}

func TestClaudeExecutor_DisabledCloakingStreamSkipsSensitiveWordObfuscation(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-sonnet-5\",\"content\":[]}}\n\n"))
		_, _ = w.Write([]byte("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"))
	}))
	defer server.Close()

	cfg := &config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey: "sk-ant-oat-skip-obfuscate-stream-test",
			Cloak: &config.CloakConfig{
				Mode:           "never",
				SensitiveWords: []string{"confidential", "secret"},
			},
		}},
	}
	auth := &cliproxyauth.Auth{
		ID:       "auth-skip-obfuscate-stream-test",
		Metadata: claudeOAuthTestMetadata(),
		Attributes: map[string]string{
			"api_key":  "sk-ant-oat-skip-obfuscate-stream-test",
			"base_url": server.URL,
		},
	}

	executor := NewClaudeExecutor(cfg)
	payload := []byte(`{"model":"claude-sonnet-5","stream":true,"system":[{"type":"text","text":"this is confidential"}],"messages":[{"role":"user","content":"keep this secret"}]}`)
	streamResult, err := executor.ExecuteStream(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-sonnet-5",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatClaude})
	if err != nil {
		t.Fatalf("ExecuteStream error = %v", err)
	}
	for range streamResult.Chunks {
	}

	rawBody := string(seenBody)
	if strings.Contains(rawBody, "\u200B") {
		t.Fatalf("disabled cloaking must not insert zero-width spaces into ExecuteStream body, got: %s", rawBody)
	}
	if !strings.Contains(rawBody, "confidential") || !strings.Contains(rawBody, "secret") {
		t.Fatalf("expected cleartext preserved in ExecuteStream, got: %s", rawBody)
	}
}

func TestClaudeExecutor_PayloadReplacesSystemOnOriginalFableReaddsReportingBlock(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-fable-5-1","role":"assistant","content":[{"type":"text","text":"ok"}]}`))
	}))
	defer server.Close()

	cfg := &config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey: "sk-ant-oat-fable-replace-sys-test",
		}},
		Payload: config.PayloadConfig{
			Override: []config.PayloadRule{{
				Models: []config.PayloadModelRule{{Name: "claude-fable-5-1"}},
				Params: map[string]any{
					"system": "Custom replaced system prompt",
				},
			}},
		},
	}
	auth := &cliproxyauth.Auth{
		ID:       "auth-fable-replace-sys-test",
		Metadata: claudeOAuthTestMetadata(),
		Attributes: map[string]string{
			"api_key":  "sk-ant-oat-fable-replace-sys-test",
			"base_url": server.URL,
		},
	}

	executor := NewClaudeExecutor(cfg)
	payload := []byte(`{"model":"claude-fable-5-1","thinking":{"type":"adaptive"},"messages":[{"role":"user","content":"test"}]}`)
	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-fable-5-1",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatClaude})
	if err != nil {
		t.Fatalf("Execute error = %v", err)
	}

	hasReplacedSystem := false
	hasReporting := false
	for _, blk := range gjson.GetBytes(seenBody, "system").Array() {
		text := blk.Get("text").String()
		if text == "Custom replaced system prompt" {
			hasReplacedSystem = true
		}
		if text == claudeCodeFableReportingOutcomes {
			hasReporting = true
		}
	}
	if !hasReplacedSystem {
		t.Fatalf("expected custom replaced system prompt in system, got: %s", gjson.GetBytes(seenBody, "system").Raw)
	}
	if !hasReporting {
		t.Fatalf("expected Fable reporting outcomes block re-added in system, got: %s", gjson.GetBytes(seenBody, "system").Raw)
	}
}

func TestClaudeExecutor_UserTitlePromptWithoutSchemaTreatedAsNormalTurn(t *testing.T) {
	var seenHeaders http.Header
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		seenHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-sonnet-5","role":"assistant","content":[{"type":"text","text":"ok"}]}`))
	}))
	defer server.Close()

	cfg := &config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey: "sk-ant-oat-user-title-prompt-test",
			Cloak:  &config.CloakConfig{},
		}},
	}
	auth := &cliproxyauth.Auth{
		ID:       "auth-user-title-prompt-test",
		Metadata: claudeOAuthTestMetadata(),
		Attributes: map[string]string{
			"api_key":  "sk-ant-oat-user-title-prompt-test",
			"base_url": server.URL,
		},
	}

	executor := NewClaudeExecutor(cfg)
	// Normal user query with text "Return a short title for this blog post", but NO structured output schema
	payload := []byte(`{"model":"claude-sonnet-5","messages":[{"role":"user","content":"Return a short title for this blog post"}]}`)
	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-sonnet-5",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatClaude})
	if err != nil {
		t.Fatalf("Execute error = %v", err)
	}

	// Must NOT be treated as a title helper:
	// 1. Must carry 1h cache TTL and extended-cache-ttl beta
	has1h := false
	for _, blk := range gjson.GetBytes(seenBody, "system").Array() {
		if blk.Get("cache_control.ttl").String() == "1h" {
			has1h = true
			break
		}
	}
	if !has1h {
		t.Fatalf("user title query must carry 1h cache, got: %s", gjson.GetBytes(seenBody, "system").Raw)
	}
	if !strings.Contains(seenHeaders.Get("Anthropic-Beta"), "extended-cache-ttl-2025-04-11") {
		t.Fatalf("user title query must carry extended-cache-ttl beta, got: %s", seenHeaders.Get("Anthropic-Beta"))
	}
	// 2. Billing header must carry cc_prompt_id
	billingText := gjson.GetBytes(seenBody, "system.0.text").String()
	if !strings.Contains(billingText, "cc_prompt_id=") {
		t.Fatalf("user title query must carry cc_prompt_id, got: %s", billingText)
	}
}

func TestClaudeExecutor_PayloadOverrideRawPreservesExplicitFallbacks(t *testing.T) {
	var seenBody []byte
	var seenHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		seenHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-sonnet-5","role":"assistant","content":[{"type":"text","text":"ok"}]}`))
	}))
	defer server.Close()

	cfg := &config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey: "sk-ant-oat-payload-fable-test-5",
			Cloak:  &config.CloakConfig{},
		}},
		Payload: config.PayloadConfig{
			OverrideRaw: []config.PayloadRule{{
				Models: []config.PayloadModelRule{{Name: "claude-fable-5-1"}},
				Params: map[string]any{
					"model":     `"claude-sonnet-5"`,
					"fallbacks": `[{"model":"claude-opus-5"}]`,
				},
			}},
		},
	}
	auth := &cliproxyauth.Auth{
		ID:       "auth-payload-fable-test-5",
		Metadata: claudeOAuthTestMetadata(),
		Attributes: map[string]string{
			"api_key":  "sk-ant-oat-payload-fable-test-5",
			"base_url": server.URL,
		},
	}

	executor := NewClaudeExecutor(cfg)
	payload := []byte(`{"model":"claude-fable-5-1","thinking":{"type":"adaptive"},"messages":[{"role":"user","content":"test"}]}`)
	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-fable-5-1",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatClaude})
	if err != nil {
		t.Fatalf("Execute error = %v", err)
	}

	// Raw payload override setting fallbacks must be preserved!
	fallbacks := gjson.GetBytes(seenBody, "fallbacks").Array()
	if len(fallbacks) != 1 || fallbacks[0].Get("model").String() != "claude-opus-5" {
		t.Fatalf("explicit raw payload fallback override must be preserved, got: %s", gjson.GetBytes(seenBody, "fallbacks").Raw)
	}
	if !strings.Contains(seenHeaders.Get("Anthropic-Beta"), "server-side-fallback") {
		t.Fatalf("server-side-fallback beta must be present for explicit raw fallback, got: %s", seenHeaders.Get("Anthropic-Beta"))
	}
}

func TestClaudeExecutor_PayloadFilterFallbacksPreservesRemovalOnFable(t *testing.T) {
	var seenBody []byte
	var seenHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		seenHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-fable-5-1","role":"assistant","content":[{"type":"text","text":"ok"}]}`))
	}))
	defer server.Close()

	cfg := &config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey: "sk-ant-oat-payload-fable-filter-test",
			Cloak:  &config.CloakConfig{},
		}},
		Payload: config.PayloadConfig{
			Filter: []config.PayloadFilterRule{{
				Models: []config.PayloadModelRule{{Name: "claude-fable-5-1"}},
				Params: []string{"fallbacks"},
			}},
		},
	}
	auth := &cliproxyauth.Auth{
		ID:       "auth-payload-fable-filter-test",
		Metadata: claudeOAuthTestMetadata(),
		Attributes: map[string]string{
			"api_key":  "sk-ant-oat-payload-fable-filter-test",
			"base_url": server.URL,
		},
	}

	executor := NewClaudeExecutor(cfg)
	payload := []byte(`{"model":"claude-fable-5-1","thinking":{"type":"adaptive"},"messages":[{"role":"user","content":"test"}]}`)
	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-fable-5-1",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatClaude})
	if err != nil {
		t.Fatalf("Execute error = %v", err)
	}

	// fallbacks was filtered out by operator rule, must NOT be recreated!
	if gjson.GetBytes(seenBody, "fallbacks").Exists() {
		t.Fatalf("fallbacks must remain deleted after payload filter, got: %s", gjson.GetBytes(seenBody, "fallbacks").Raw)
	}
	if strings.Contains(seenHeaders.Get("Anthropic-Beta"), "server-side-fallback") {
		t.Fatalf("server-side-fallback beta must be absent when fallbacks is filtered, got: %s", seenHeaders.Get("Anthropic-Beta"))
	}
}

func TestClaudeExecutor_PayloadCustomReportingOutcomesPreservedOnRewrite(t *testing.T) {
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-sonnet-5","role":"assistant","content":[{"type":"text","text":"ok"}]}`))
	}))
	defer server.Close()

	cfg := &config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey: "sk-ant-oat-payload-fable-custom-reporting-test",
			Cloak:  &config.CloakConfig{},
		}},
		Payload: config.PayloadConfig{
			Override: []config.PayloadRule{{
				Models: []config.PayloadModelRule{{Name: "claude-fable-5-1"}},
				Params: map[string]any{
					"model": "claude-sonnet-5",
					"system": []map[string]any{
						{"type": "text", "text": "Custom user prompt containing Reporting outcomes heading in discussion."},
					},
				},
			}},
		},
	}
	auth := &cliproxyauth.Auth{
		ID:       "auth-payload-fable-custom-reporting-test",
		Metadata: claudeOAuthTestMetadata(),
		Attributes: map[string]string{
			"api_key":  "sk-ant-oat-payload-fable-custom-reporting-test",
			"base_url": server.URL,
		},
	}

	executor := NewClaudeExecutor(cfg)
	payload := []byte(`{"model":"claude-fable-5-1","messages":[{"role":"user","content":"test"}]}`)
	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-fable-5-1",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatClaude})
	if err != nil {
		t.Fatalf("Execute error = %v", err)
	}

	system := gjson.GetBytes(seenBody, "system").Array()
	hasCustom := false
	for _, blk := range system {
		if strings.Contains(blk.Get("text").String(), "Custom user prompt") {
			hasCustom = true
		}
	}
	if !hasCustom {
		t.Fatalf("custom user system prompt must NOT be deleted, got: %s", gjson.GetBytes(seenBody, "system").Raw)
	}
}
