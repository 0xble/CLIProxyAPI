package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
)

func TestNormalizeClaudeSamplingForUpstream_RemovesTemperature(t *testing.T) {
	payload := []byte(`{"temperature":0,"thinking":{"type":"adaptive"},"output_config":{"effort":"max"}}`)
	out := normalizeClaudeSamplingForUpstream(payload, false)

	if gjson.GetBytes(out, "temperature").Exists() {
		t.Fatalf("temperature should be removed")
	}
}

func TestNormalizeClaudeSamplingForUpstream_RemovesTemperatureWithThinkingEnabled(t *testing.T) {
	payload := []byte(`{"temperature":0.2,"thinking":{"type":"enabled","budget_tokens":2048}}`)
	out := normalizeClaudeSamplingForUpstream(payload, false)

	if gjson.GetBytes(out, "temperature").Exists() {
		t.Fatalf("temperature should be removed")
	}
}

func TestNormalizeClaudeSamplingForUpstream_RemovesTopPAndTopKForThinking(t *testing.T) {
	payload := []byte(`{"temperature":0.2,"top_p":0.9,"top_k":40,"thinking":{"type":"adaptive"}}`)
	out := normalizeClaudeSamplingForUpstream(payload, false)

	if gjson.GetBytes(out, "temperature").Exists() {
		t.Fatalf("temperature should be removed")
	}
	if gjson.GetBytes(out, "top_p").Exists() {
		t.Fatalf("top_p should be removed when thinking is active")
	}
	if gjson.GetBytes(out, "top_k").Exists() {
		t.Fatalf("top_k should be removed when thinking is active")
	}
}

func TestNormalizeClaudeSamplingForUpstream_NoThinkingRemovesTemperatureAndTopP(t *testing.T) {
	payload := []byte(`{"temperature":0,"top_p":0.9,"top_k":40,"messages":[{"role":"user","content":"hi"}]}`)
	out := normalizeClaudeSamplingForUpstream(payload, false)

	if gjson.GetBytes(out, "temperature").Exists() {
		t.Fatalf("temperature should be removed")
	}
	if gjson.GetBytes(out, "top_p").Exists() {
		t.Fatalf("top_p should be removed")
	}
	if got := gjson.GetBytes(out, "top_k").Int(); got != 40 {
		t.Fatalf("top_k = %v, want 40", got)
	}
}

func TestNormalizeClaudeSamplingForUpstream_AfterForcedToolChoiceRemovesTemperature(t *testing.T) {
	payload := []byte(`{"temperature":0,"thinking":{"type":"adaptive"},"output_config":{"effort":"max"},"tool_choice":{"type":"any"}}`)
	out := disableThinkingIfToolChoiceForced(payload)
	out = normalizeClaudeSamplingForUpstream(out, false)

	if gjson.GetBytes(out, "thinking").Exists() {
		t.Fatalf("thinking should be removed when tool_choice forces tool use")
	}
	if gjson.GetBytes(out, "temperature").Exists() {
		t.Fatalf("temperature should be removed")
	}
}

// The measured structured Haiku helper sends "temperature":1, and
// claudeCodeHelperShapeStructured keys on exactly that value. Stripping it would
// make CPA emit a shape no native client produces, so a confirmed native caller
// must keep it.
func TestNormalizeClaudeSamplingForUpstreamNativeKeepsMeasuredHelperTemperature(t *testing.T) {
	// Top-level key order and values mirror the measured structured helper.
	payload := []byte(`{"model":"claude-haiku-4-5-20251001","messages":[{"role":"user","content":[{"type":"text","text":"helper probe"}]}],"system":[{"type":"text","text":"Return a short title."}],"tools":[],"metadata":{"user_id":"u"},"max_tokens":32000,"thinking":{"type":"disabled"},"temperature":1,"output_config":{"format":{"type":"json_schema"}},"stream":true}`)
	if got := gjson.GetBytes(payload, "temperature"); !got.Exists() || got.Num != 1 {
		t.Fatalf("measured helper fixture should carry temperature=1, got %q", got.Raw)
	}

	out := normalizeClaudeSamplingForUpstream(payload, true)

	if got := gjson.GetBytes(out, "temperature"); !got.Exists() || got.Num != 1 {
		t.Fatalf("confirmed native must preserve the measured temperature, got %q", got.Raw)
	}
}

// Anthropic's real constraints, verified against the live API: with thinking
// active temperature must be 1, top_p must be >= 0.95 and top_k must be unset;
// otherwise temperature and top_p cannot both be specified. Preserving the
// native wire must never forward a combination that would 400.
func TestNormalizeClaudeSamplingForUpstreamNativeDropsOnlyRejectedCombinations(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		keep    map[string]float64
		dropped []string
	}{
		{
			name:    "thinking off keeps every accepted knob",
			payload: `{"temperature":0.5,"top_k":40}`,
			keep:    map[string]float64{"temperature": 0.5, "top_k": 40},
		},
		{
			name:    "thinking off drops top_p when temperature is also set",
			payload: `{"temperature":0.5,"top_p":0.9}`,
			keep:    map[string]float64{"temperature": 0.5},
			dropped: []string{"top_p"},
		},
		{
			name:    "thinking off keeps a lone top_p",
			payload: `{"top_p":0.9}`,
			keep:    map[string]float64{"top_p": 0.9},
		},
		{
			name:    "thinking disabled is not thinking",
			payload: `{"temperature":1,"thinking":{"type":"disabled"}}`,
			keep:    map[string]float64{"temperature": 1},
		},
		{
			name:    "thinking enabled keeps temperature 1",
			payload: `{"temperature":1,"thinking":{"type":"enabled","budget_tokens":1024}}`,
			keep:    map[string]float64{"temperature": 1},
		},
		{
			name:    "thinking enabled drops temperature that is not 1",
			payload: `{"temperature":0.5,"thinking":{"type":"enabled","budget_tokens":1024}}`,
			dropped: []string{"temperature"},
		},
		{
			name:    "thinking enabled keeps top_p at or above 0.95",
			payload: `{"top_p":0.99,"thinking":{"type":"enabled","budget_tokens":1024}}`,
			keep:    map[string]float64{"top_p": 0.99},
		},
		{
			name:    "thinking enabled drops top_p below 0.95",
			payload: `{"top_p":0.9,"thinking":{"type":"enabled","budget_tokens":1024}}`,
			dropped: []string{"top_p"},
		},
		{
			name:    "thinking enabled always drops top_k",
			payload: `{"top_k":40,"thinking":{"type":"enabled","budget_tokens":1024}}`,
			dropped: []string{"top_k"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := normalizeClaudeSamplingForUpstream([]byte(tc.payload), true)

			for field, want := range tc.keep {
				got := gjson.GetBytes(out, field)
				if !got.Exists() || got.Num != want {
					t.Fatalf("%s = %q, want %v preserved", field, got.Raw, want)
				}
			}
			for _, field := range tc.dropped {
				if got := gjson.GetBytes(out, field); got.Exists() {
					t.Fatalf("%s = %q, want dropped because Anthropic rejects it", field, got.Raw)
				}
			}
		})
	}
}

func TestRemapOAuthToolNames_AllClientNamesUseMCPAliases(t *testing.T) {
	for _, original := range []string{"Bash", "bash", "Glob", "glob"} {
		t.Run(original, func(t *testing.T) {
			body := []byte(`{"tools":[{"name":` + fmt.Sprintf("%q", original) + `,"description":"Run a client tool","input_schema":{"type":"object"}}]}`)
			out, reverseMap := remapOAuthToolNames(body)
			alias := gjson.GetBytes(out, "tools.0.name").String()
			if !helps.IsClaudeMCPToolName(alias) {
				t.Fatalf("tools.0.name = %q, want MCP alias", alias)
			}
			if reverseMap[alias] != original {
				t.Fatalf("reverseMap = %v, want %q -> %q", reverseMap, alias, original)
			}
			resp := []byte(`{"content":[{"type":"tool_use","id":"toolu_01","name":` + fmt.Sprintf("%q", alias) + `,"input":{}}]}`)
			reversed, errReverse := reverseRemapOAuthToolNames(resp, reverseMap)
			if errReverse != nil {
				t.Fatalf("reverseRemapOAuthToolNames() error = %v", errReverse)
			}
			if got := gjson.GetBytes(reversed, "content.0.name").String(); got != original {
				t.Fatalf("content.0.name = %q, want %q", got, original)
			}
		})
	}
}

func TestRemapOAuthToolNames_AllClientToolsAsMCP(t *testing.T) {
	body := []byte(`{
		"tools":[
			{"type":"web_search_20250305","name":"web_search","max_uses":2},
			{"name":"bash","description":"client shell tool","input_schema":{"type":"object"}},
			{"name":"Read","description":"client read tool","input_schema":{"type":"object"}},
			{"name":"mcp__context7__query-docs","description":"existing MCP tool","input_schema":{"type":"object"}},
			{"name":"search_web","description":"unknown one","input_schema":{"type":"object","properties":{"q":{"type":"string"}},"required":["q"]}},
			{"name":"Search_Web","description":"case-distinct unknown","input_schema":{"type":"object"}},
			{"name":"search_web","description":"repeated declaration","input_schema":{"type":"object"}}
		],
		"tool_choice":{"type":"tool","name":"search_web"},
		"messages":[
			{"role":"assistant","content":[
				{"type":"tool_use","id":"toolu_unknown","name":"search_web","input":{"q":"go"}},
				{"type":"tool_reference","tool_name":"Search_Web"}
			]},
			{"role":"user","content":[
				{"type":"tool_result","tool_use_id":"toolu_unknown","content":[{"type":"tool_reference","tool_name":"search_web"}]}
			]}
		]
	}`)

	out, reverseMap := remapOAuthToolNamesWithOptions(body, claudeMCPAliasOptions{secret: "credential-secret"})

	if got := gjson.GetBytes(out, "tools.0.name").String(); got != "web_search" {
		t.Fatalf("typed builtin = %q, want unchanged", got)
	}
	bashAlias := gjson.GetBytes(out, "tools.1.name").String()
	readAlias := gjson.GetBytes(out, "tools.2.name").String()
	if !helps.IsClaudeMCPToolName(bashAlias) || !helps.IsClaudeMCPToolName(readAlias) {
		t.Fatalf("former vetted names did not receive MCP aliases: bash=%q Read=%q", bashAlias, readAlias)
	}
	if got := gjson.GetBytes(out, "tools.1.description").String(); got != "client shell tool" {
		t.Fatalf("bash description = %q, want preserved", got)
	}
	if got := gjson.GetBytes(out, "tools.1.input_schema.type").String(); got != "object" {
		t.Fatalf("bash schema changed: %s", out)
	}
	if got := gjson.GetBytes(out, "tools.3.name").String(); got != "mcp__context7__query-docs" {
		t.Fatalf("existing MCP tool = %q, want unchanged", got)
	}

	searchAlias := gjson.GetBytes(out, "tools.4.name").String()
	caseAlias := gjson.GetBytes(out, "tools.5.name").String()
	if !helps.IsClaudeMCPToolName(searchAlias) || !helps.IsClaudeMCPToolName(caseAlias) {
		t.Fatalf("generated aliases are invalid: %q, %q", searchAlias, caseAlias)
	}
	if searchAlias == caseAlias {
		t.Fatalf("case-distinct names share alias %q", searchAlias)
	}
	if got := gjson.GetBytes(out, "tools.6.name").String(); got != searchAlias {
		t.Fatalf("repeated declaration alias = %q, want %q", got, searchAlias)
	}
	if !strings.HasSuffix(searchAlias, "_search_web") || !strings.HasSuffix(caseAlias, "_Search_Web") {
		t.Fatalf("generated aliases lost semantic suffixes: %q, %q", searchAlias, caseAlias)
	}
	if len(searchAlias) > 64 || len(caseAlias) > 64 {
		t.Fatalf("generated aliases exceed 64 characters: %q, %q", searchAlias, caseAlias)
	}
	if got := gjson.GetBytes(out, "tools.4.description").String(); got != "unknown one" {
		t.Fatalf("description = %q, want preserved", got)
	}
	if got := gjson.GetBytes(out, "tools.4.input_schema.required.0").String(); got != "q" {
		t.Fatalf("input schema was not preserved: %s", out)
	}
	if got := gjson.GetBytes(out, "tool_choice.name").String(); got != searchAlias {
		t.Fatalf("tool_choice.name = %q, want %q", got, searchAlias)
	}
	if got := gjson.GetBytes(out, "messages.0.content.0.name").String(); got != searchAlias {
		t.Fatalf("historical tool_use.name = %q, want %q", got, searchAlias)
	}
	if got := gjson.GetBytes(out, "messages.0.content.0.id").String(); got != "toolu_unknown" {
		t.Fatalf("tool_use.id = %q, want unchanged", got)
	}
	if got := gjson.GetBytes(out, "messages.0.content.1.tool_name").String(); got != caseAlias {
		t.Fatalf("tool_reference.tool_name = %q, want %q", got, caseAlias)
	}
	if got := gjson.GetBytes(out, "messages.1.content.0.content.0.tool_name").String(); got != searchAlias {
		t.Fatalf("nested tool_reference.tool_name = %q, want %q", got, searchAlias)
	}
	if reverseMap[searchAlias] != "search_web" || reverseMap[caseAlias] != "Search_Web" ||
		reverseMap[bashAlias] != "bash" || reverseMap[readAlias] != "Read" {
		t.Fatalf("reverseMap = %v, want exact client names", reverseMap)
	}

	response := []byte(fmt.Sprintf(`{"content":[
		{"type":"tool_use","id":"toolu_unknown","name":%q,"input":{}},
		{"type":"tool_reference","tool_name":%q},
		{"type":"tool_result","tool_use_id":"toolu_unknown","content":[{"type":"tool_reference","tool_name":%q}]}
	]}`, searchAlias, caseAlias, searchAlias))
	restored, errReverse := reverseRemapOAuthToolNames(response, reverseMap)
	if errReverse != nil {
		t.Fatalf("reverseRemapOAuthToolNames() error = %v", errReverse)
	}
	if got := gjson.GetBytes(restored, "content.0.name").String(); got != "search_web" {
		t.Fatalf("restored tool_use.name = %q, want search_web", got)
	}
	if got := gjson.GetBytes(restored, "content.1.tool_name").String(); got != "Search_Web" {
		t.Fatalf("restored tool_reference.tool_name = %q, want Search_Web", got)
	}
	if got := gjson.GetBytes(restored, "content.2.content.0.tool_name").String(); got != "search_web" {
		t.Fatalf("restored nested tool_reference = %q, want search_web", got)
	}

	streamLine := []byte(fmt.Sprintf(`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_unknown","name":%q,"input":{}}}`, searchAlias))
	restoredLine, errReverse := reverseRemapOAuthToolNamesFromStreamLine(streamLine, reverseMap)
	if errReverse != nil {
		t.Fatalf("reverseRemapOAuthToolNamesFromStreamLine() error = %v", errReverse)
	}
	if got := gjson.GetBytes(helps.JSONPayload(restoredLine), "content_block.name").String(); got != "search_web" {
		t.Fatalf("restored stream name = %q, want search_web: %s", got, restoredLine)
	}
}

func TestRemapOAuthToolNames_TypedCustomUsesMCPAlias(t *testing.T) {
	body := []byte(`{
		"tools":[
			{"type":"custom","name":"client_custom","description":"keep","input_schema":{"type":"object","properties":{"value":{"type":"string"}}}},
			{"type":"web_search_20250305","name":"web_search","max_uses":2},
			{"type":"client_extension_v1","name":"client_extension","description":"extension","input_schema":{"type":"object"}}
		],
		"tool_choice":{"type":"tool","name":"client_custom"},
		"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"toolu_custom","name":"client_custom","input":{}}]}]
	}`)
	out, reverseMap := remapOAuthToolNamesWithOptions(body, claudeMCPAliasOptions{secret: "caller-secret"})

	alias := gjson.GetBytes(out, "tools.0.name").String()
	if !helps.IsClaudeMCPToolName(alias) {
		t.Fatalf("typed custom alias = %q, want MCP name", alias)
	}
	if gjson.GetBytes(out, "tools.0.type").Exists() {
		t.Fatalf("typed custom type was not normalized away: %s", out)
	}
	if got := gjson.GetBytes(out, "tools.0.description").String(); got != "keep" {
		t.Fatalf("typed custom description = %q, want preserved", got)
	}
	if got := gjson.GetBytes(out, "tools.1.name").String(); got != "web_search" {
		t.Fatalf("server builtin name = %q, want unchanged", got)
	}
	extensionAlias := gjson.GetBytes(out, "tools.2.name").String()
	if !helps.IsClaudeMCPToolName(extensionAlias) || gjson.GetBytes(out, "tools.2.type").Exists() {
		t.Fatalf("unknown typed client tool was not normalized: %s", out)
	}
	if got := gjson.GetBytes(out, "tool_choice.name").String(); got != alias {
		t.Fatalf("tool_choice.name = %q, want %q", got, alias)
	}
	if got := gjson.GetBytes(out, "messages.0.content.0.name").String(); got != alias {
		t.Fatalf("historical tool_use.name = %q, want %q", got, alias)
	}
	if reverseMap[alias] != "client_custom" || reverseMap[extensionAlias] != "client_extension" {
		t.Fatalf("reverseMap = %v, want exact typed client names", reverseMap)
	}
}

func TestRemapOAuthToolNames_MCPAliasAvoidsClientCollision(t *testing.T) {
	const secret = "credential-secret"
	initialCandidate := helps.ClaudeMCPToolAlias(secret, "fetch_url", 0)
	body := []byte(fmt.Sprintf(`{"tools":[
		{"name":%q,"input_schema":{"type":"object"}},
		{"name":"fetch_url","input_schema":{"type":"object"}}
	]}`, initialCandidate))

	out, reverseMap := remapOAuthToolNamesWithOptions(body, claudeMCPAliasOptions{secret: secret})
	if got := gjson.GetBytes(out, "tools.0.name").String(); got != initialCandidate {
		t.Fatalf("existing MCP tool = %q, want %q", got, initialCandidate)
	}
	alias := gjson.GetBytes(out, "tools.1.name").String()
	if alias == initialCandidate {
		t.Fatalf("generated alias collided with client MCP name %q", alias)
	}
	if reverseMap[alias] != "fetch_url" {
		t.Fatalf("reverseMap = %v, want %q -> fetch_url", reverseMap, alias)
	}
}

func TestRemapOAuthToolNames_MCPAliasIsMandatory(t *testing.T) {
	body := []byte(`{"tools":[{"name":"search_web","input_schema":{"type":"object"}}]}`)
	out, reverseMap := remapOAuthToolNames(body)
	alias := gjson.GetBytes(out, "tools.0.name").String()
	if !helps.IsClaudeMCPToolName(alias) {
		t.Fatalf("tools.0.name = %q, want mandatory MCP alias", alias)
	}
	if reverseMap[alias] != "search_web" {
		t.Fatalf("reverseMap = %v, want alias -> search_web", reverseMap)
	}
}

func TestRemapOAuthToolNames_SemanticAliasRestoresLongOriginal(t *testing.T) {
	original := "Read.file/with a very long semantic name and Unicode 网页内容 that exceeds the wire limit"
	body := []byte(`{"tools":[{"name":` + fmt.Sprintf("%q", original) + `,"input_schema":{"type":"object"}}]}`)
	options := claudeMCPAliasOptions{secret: "stable-caller"}

	out, reverseMap := remapOAuthToolNamesWithOptions(body, options)
	alias := gjson.GetBytes(out, "tools.0.name").String()
	if !helps.IsClaudeMCPToolName(alias) || len(alias) > 64 {
		t.Fatalf("semantic alias is invalid or too long: len=%d name=%q", len(alias), alias)
	}
	if !strings.Contains(alias, "_Read_file_with_a_very_long") {
		t.Fatalf("semantic alias %q does not expose the truncated original meaning", alias)
	}
	if reverseMap[alias] != original {
		t.Fatalf("reverseMap lost exact original: got %q, want %q", reverseMap[alias], original)
	}

	second, _ := remapOAuthToolNamesWithOptions(body, options)
	if got := gjson.GetBytes(second, "tools.0.name").String(); got != alias {
		t.Fatalf("semantic alias is not stable across requests: %q != %q", got, alias)
	}
	response := []byte(`{"content":[{"type":"tool_use","id":"toolu_1","name":` + fmt.Sprintf("%q", alias) + `,"input":{}}]}`)
	restored, errReverse := reverseRemapOAuthToolNames(response, reverseMap)
	if errReverse != nil {
		t.Fatalf("reverseRemapOAuthToolNames() error = %v", errReverse)
	}
	if got := gjson.GetBytes(restored, "content.0.name").String(); got != original {
		t.Fatalf("restored tool name = %q, want exact original %q", got, original)
	}
}

func TestPrepareClaudeOAuthToolNamesForUpstream_PreservesMCPConvention(t *testing.T) {
	body := []byte(`{"tools":[
		{"name":"search_web","input_schema":{"type":"object"}},
		{"name":"mcp__context7__query-docs","input_schema":{"type":"object"}},
		{"name":"bash","input_schema":{"type":"object"}}
	],"tool_choice":{"type":"tool","name":"search_web"}}`)
	out, reverseMap := prepareClaudeOAuthToolNamesForUpstream(body, claudeMCPAliasOptions{secret: "credential-secret"})

	alias := gjson.GetBytes(out, "tools.0.name").String()
	if !helps.IsClaudeMCPToolName(alias) || strings.HasPrefix(alias, "proxy_") {
		t.Fatalf("unknown alias = %q, want bare mcp__ name", alias)
	}
	if got := gjson.GetBytes(out, "tools.1.name").String(); got != "mcp__context7__query-docs" {
		t.Fatalf("existing MCP name = %q, want unchanged", got)
	}
	bashAlias := gjson.GetBytes(out, "tools.2.name").String()
	if !helps.IsClaudeMCPToolName(bashAlias) || strings.HasPrefix(bashAlias, "proxy_") {
		t.Fatalf("former vetted tool = %q, want bare MCP alias", bashAlias)
	}
	if got := gjson.GetBytes(out, "tool_choice.name").String(); got != alias {
		t.Fatalf("tool_choice.name = %q, want %q", got, alias)
	}
	if reverseMap[alias] != "search_web" || reverseMap[bashAlias] != "bash" {
		t.Fatalf("reverseMap = %v, want exact alias restoration", reverseMap)
	}
}

func TestResolveClaudeMCPAliasOptions(t *testing.T) {
	if options := resolveClaudeMCPAliasOptions(context.Background()); options.secret == "" {
		t.Fatal("default caller alias secret is empty")
	}

	gin.SetMode(gin.TestMode)
	ginCtx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ginCtx.Set("userApiKey", "downstream-caller-one")
	callerCtx := context.WithValue(context.Background(), "gin", ginCtx)
	firstSecret := resolveClaudeMCPAliasOptions(callerCtx).secret
	secondSecret := resolveClaudeMCPAliasOptions(callerCtx).secret
	if firstSecret == "" || secondSecret != firstSecret {
		t.Fatalf("caller alias secret is unstable: %q != %q", firstSecret, secondSecret)
	}
	otherGinCtx, _ := gin.CreateTestContext(httptest.NewRecorder())
	otherGinCtx.Set("userApiKey", "downstream-caller-two")
	otherCtx := context.WithValue(context.Background(), "gin", otherGinCtx)
	if otherSecret := resolveClaudeMCPAliasOptions(otherCtx).secret; otherSecret == firstSecret {
		t.Fatalf("different downstream callers shared alias secret %q", firstSecret)
	}
}

func TestRemapOAuthToolNames_MixedCaseNamesRemainDistinct(t *testing.T) {
	body := []byte(`{"tools":[` +
		`{"name":"Bash","input_schema":{"type":"object"}},` +
		`{"name":"bash","input_schema":{"type":"object"}}` +
		`]}`)
	out, reverseMap := remapOAuthToolNames(body)
	upperAlias := gjson.GetBytes(out, "tools.0.name").String()
	lowerAlias := gjson.GetBytes(out, "tools.1.name").String()
	if !helps.IsClaudeMCPToolName(upperAlias) || !helps.IsClaudeMCPToolName(lowerAlias) || upperAlias == lowerAlias {
		t.Fatalf("mixed-case aliases = %q, %q, want distinct MCP names", upperAlias, lowerAlias)
	}
	if reverseMap[upperAlias] != "Bash" || reverseMap[lowerAlias] != "bash" {
		t.Fatalf("reverseMap = %v, want exact mixed-case names", reverseMap)
	}
}

// TestReverseRemapOAuthToolNamesFromStreamLine_HonorsPerRequestMap guards the
// SSE streaming code path against the same mixed-case bug.
func TestReverseRemapOAuthToolNamesFromStreamLine_HonorsPerRequestMap(t *testing.T) {
	reverseMap := map[string]string{"Glob": "glob"}

	// Bash block was never renamed, must pass through as-is.
	bashLine := []byte(`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_01","name":"Bash","input":{}}}`)
	out, errReverse := reverseRemapOAuthToolNamesFromStreamLine(bashLine, reverseMap)
	if errReverse != nil {
		t.Fatalf("reverseRemapOAuthToolNamesFromStreamLine() error = %v", errReverse)
	}
	if !bytes.Contains(out, []byte(`"name":"Bash"`)) {
		t.Fatalf("Bash should be preserved, got: %s", string(out))
	}
	if bytes.Contains(out, []byte(`"name":"bash"`)) {
		t.Fatalf("Bash must not be lowercased, got: %s", string(out))
	}

	// Glob block IS in the reverseMap, must be restored to `glob`.
	globLine := []byte(`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_02","name":"Glob","input":{}}}`)
	out, errReverse = reverseRemapOAuthToolNamesFromStreamLine(globLine, reverseMap)
	if errReverse != nil {
		t.Fatalf("reverseRemapOAuthToolNamesFromStreamLine() error = %v", errReverse)
	}
	if !bytes.Contains(out, []byte(`"name":"glob"`)) {
		t.Fatalf("Glob should be restored to glob, got: %s", string(out))
	}
}

func TestPrepareClaudeOAuthToolNamesForUpstream_AllCustomToolsWithHistory(t *testing.T) {
	body := []byte(`{"tools":[` +
		`{"name":"Bash","input_schema":{"type":"object","properties":{"cmd":{"type":"string"}}}},` +
		`{"name":"glob","input_schema":{"type":"object","properties":{"filePattern":{"type":"string"}}}}` +
		`],"messages":[{"role":"assistant","content":[` +
		`{"type":"tool_use","id":"toolu_01","name":"Bash","input":{}},` +
		`{"type":"tool_use","id":"toolu_02","name":"glob","input":{}}` +
		`]}]}`)

	out, reverseMap := prepareClaudeOAuthToolNamesForUpstream(body, claudeMCPAliasOptions{secret: "mixed-case-caller"})
	bashAlias := gjson.GetBytes(out, "tools.0.name").String()
	globAlias := gjson.GetBytes(out, "tools.1.name").String()
	if !helps.IsClaudeMCPToolName(bashAlias) || !helps.IsClaudeMCPToolName(globAlias) || bashAlias == globAlias {
		t.Fatalf("tool aliases = %q, %q, want distinct bare MCP names", bashAlias, globAlias)
	}
	if got := gjson.GetBytes(out, "messages.0.content.0.name").String(); got != bashAlias {
		t.Fatalf("messages.0.content.0.name = %q, want %q", got, bashAlias)
	}
	if got := gjson.GetBytes(out, "messages.0.content.1.name").String(); got != globAlias {
		t.Fatalf("messages.0.content.1.name = %q, want %q", got, globAlias)
	}
	if reverseMap[bashAlias] != "Bash" || reverseMap[globAlias] != "glob" {
		t.Fatalf("reverseMap = %v, want exact client names", reverseMap)
	}
}

func TestClaudeExecutor_ExecuteOpenAINonStreamRestoresOAuthToolNames(t *testing.T) {
	upstreamBody := strings.Join([]string{
		`event: message_start`,
		`data: {"type":"message_start","message":{"id":"msg_123","model":"claude-3-5-sonnet-20241022","usage":{"input_tokens":10,"output_tokens":1}}}`,
		`event: content_block_start`,
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_01","name":"Bash","input":{}}}`,
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"command\": \"echo hi\"}"}}`,
		`event: content_block_stop`,
		`data: {"type":"content_block_stop","index":0}`,
		`event: message_delta`,
		`data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":30}}`,
		`event: message_stop`,
		`data: {"type":"message_stop"}`,
		``,
	}, "\n")

	type upstreamRequest struct {
		toolName string
		stream   bool
	}
	upstreamRequests := make(chan upstreamRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, errRead := io.ReadAll(r.Body)
		if errRead != nil {
			http.Error(w, errRead.Error(), http.StatusBadRequest)
			return
		}
		toolName := gjson.GetBytes(body, "tools.0.name").String()
		upstreamRequests <- upstreamRequest{
			toolName: toolName,
			stream:   gjson.GetBytes(body, "stream").Bool(),
		}
		w.Header().Set("Content-Type", "text/event-stream")
		responseBody := strings.Replace(upstreamBody, `"name":"Bash"`, `"name":`+fmt.Sprintf("%q", toolName), 1)
		_, _ = w.Write([]byte(responseBody))
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{
		Attributes: map[string]string{
			"api_key":  "sk-ant-oat01-test",
			"base_url": server.URL,
		},
		Metadata: claudeOAuthTestMetadata(),
	}
	payload := []byte(`{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"run echo hi"}],` +
		`"tools":[{"type":"function","function":{"name":"bash","description":"run shell",` +
		`"parameters":{"type":"object","properties":{"command":{"type":"string"}},"required":["command"]}}}]}`)

	resp, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-3-5-sonnet-20241022",
		Payload: payload,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("openai"),
	})
	if err != nil {
		t.Fatalf("Execute error: %v", err)
	}

	upstream := <-upstreamRequests
	if !upstream.stream {
		t.Fatal("upstream stream = false, want true")
	}
	if !helps.IsClaudeMCPToolName(upstream.toolName) || !strings.HasSuffix(upstream.toolName, "_bash") {
		t.Fatalf("upstream tools.0.name = %q, want semantic MCP alias", upstream.toolName)
	}
	if got := gjson.GetBytes(resp.Payload, "choices.0.message.tool_calls.0.function.name").String(); got != "bash" {
		t.Fatalf("tool_calls.0.function.name = %q, want %q; payload=%s", got, "bash", string(resp.Payload))
	}
}

func TestClaudeExecutor_ExecuteOAuthCustomToolMCPAliasRoundTrip(t *testing.T) {
	var upstreamAlias string
	var upstreamBody []byte
	var upstreamHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		upstreamBody = bytes.Clone(body)
		upstreamHeaders = r.Header.Clone()
		upstreamAlias = gjson.GetBytes(body, "tools.0.name").String()
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"id":"msg_1","type":"message","role":"assistant","model":"claude-opus-4-6","content":[{"type":"tool_use","id":"toolu_1","name":%q,"input":{"query":"go"}}],"stop_reason":"tool_use","usage":{"input_tokens":1,"output_tokens":1}}`, upstreamAlias)
	}))
	defer server.Close()

	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{
		ID: "oauth-mcp-round-trip",
		Attributes: map[string]string{
			"api_key":  "sk-ant-oat-mcp-round-trip",
			"base_url": server.URL,
		},
		Metadata: claudeOAuthTestMetadata(),
	}
	payload := []byte(`{"model":"claude-opus-5","system":"messages-system-prompt","messages":[{"role":"user","content":"search"}],"tools":[{"name":"search_web","description":"search","input_schema":{"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}}]}`)
	resp, errExecute := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-opus-5",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatClaude})
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if !helps.IsClaudeMCPToolName(upstreamAlias) || strings.HasPrefix(upstreamAlias, "proxy_") || !strings.HasSuffix(upstreamAlias, "_search_web") {
		t.Fatalf("upstream tool name = %q, want semantic mcp__ alias", upstreamAlias)
	}
	if got := gjson.GetBytes(resp.Payload, "content.0.name").String(); got != "search_web" {
		t.Fatalf("client response tool name = %q, want search_web; payload=%s", got, resp.Payload)
	}
	if _, ok := claudeBillingCCHDigitsOffset(upstreamBody); !ok {
		t.Fatalf("Claude OAuth custom BaseURL body is missing CCH: %s", upstreamBody)
	}
	if got := upstreamHeaders.Get("User-Agent"); got != "claude-cli/2.1.258 (external, cli)" {
		t.Fatalf("Messages User-Agent = %q, want CLI identity", got)
	}
	wantBetas := claudeCodeCLIBetas(payload, nil, true)
	if got := upstreamHeaders.Get("Anthropic-Beta"); got != wantBetas {
		t.Fatalf("Messages Anthropic-Beta = %q, want %q", got, wantBetas)
	}
	if got := gjson.GetBytes(upstreamBody, "system.1.text").String(); got != claudeCodeCLIIdentity {
		t.Fatalf("Messages system.1.text = %q, want official CLI identity", got)
	}
	if got := gjson.GetBytes(upstreamBody, "system.#").Int(); got != 2 {
		t.Fatalf("Messages top-level system block count = %d, want 2", got)
	}
	content := gjson.GetBytes(upstreamBody, "messages.0.content").Array()
	if len(content) != 2 {
		t.Fatalf("Messages first user content has %d blocks, want currentDate and user text", len(content))
	}
	assertClaudeCodeCurrentDateBlock(t, content[0])
	assertEphemeralUserTextBlock(t, content[1], "search", "1h")
	assertClaudeMidConversationSystemMessage(t, upstreamBody, 1, "messages-system-prompt", "1h")
}

func TestClaudeExecutor_ExecuteStreamOAuthCustomToolMCPAliasRoundTrip(t *testing.T) {
	var upstreamAlias string
	var upstreamBody []byte
	var upstreamHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		upstreamBody = bytes.Clone(body)
		upstreamHeaders = r.Header.Clone()
		upstreamAlias = gjson.GetBytes(body, "tools.0.name").String()
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprintf(w, "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":%q,\"input\":{}}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n", upstreamAlias)
	}))
	defer server.Close()

	deviceIDs := []string{
		"0000000000000000000000000000000000000000000000000000000000000000",
	}
	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{
		ID: "oauth-mcp-stream-round-trip",
		Attributes: map[string]string{
			"api_key":  "sk-ant-oat-mcp-stream-round-trip",
			"base_url": server.URL,
		},
		Metadata: map[string]any{
			"account_uuid":                        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
			claudeauth.ClaudeDeviceIDsMetadataKey: deviceIDs,
		},
	}
	payload := []byte(`{"model":"claude-opus-5","system":"stream-system-prompt","messages":[{"role":"user","content":"fetch"}],"tools":[{"name":"fetch_url","description":"fetch","input_schema":{"type":"object"}}],"stream":true}`)
	result, errStream := executor.ExecuteStream(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-opus-5",
		Payload: payload,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatClaude,
		Metadata: map[string]any{
			cliproxyexecutor.ExecutionSessionMetadataKey: "stream-agent-conversation",
		},
	})
	if errStream != nil {
		t.Fatalf("ExecuteStream() error = %v", errStream)
	}
	var downstream bytes.Buffer
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			t.Fatalf("stream chunk error = %v", chunk.Err)
		}
		downstream.Write(chunk.Payload)
	}
	if !helps.IsClaudeMCPToolName(upstreamAlias) || !strings.HasSuffix(upstreamAlias, "_fetch_url") {
		t.Fatalf("upstream tool name = %q, want semantic mcp__ alias", upstreamAlias)
	}
	if _, ok := claudeBillingCCHDigitsOffset(upstreamBody); !ok {
		t.Fatalf("streaming Claude OAuth custom BaseURL body is missing CCH: %s", upstreamBody)
	}
	if got := upstreamHeaders.Get("User-Agent"); got != "claude-cli/2.1.258 (external, cli)" {
		t.Fatalf("streaming User-Agent = %q, want CLI identity", got)
	}
	wantBetas := claudeCodeCLIBetas(payload, nil, true)
	if got := upstreamHeaders.Get("Anthropic-Beta"); got != wantBetas {
		t.Fatalf("streaming Anthropic-Beta = %q, want %q", got, wantBetas)
	}
	if got := gjson.GetBytes(upstreamBody, "system.1.text").String(); got != claudeCodeCLIIdentity {
		t.Fatalf("streaming system.1.text = %q, want official CLI identity", got)
	}
	if got := gjson.GetBytes(upstreamBody, "system.#").Int(); got != 2 {
		t.Fatalf("streaming top-level system block count = %d, want 2", got)
	}
	content := gjson.GetBytes(upstreamBody, "messages.0.content").Array()
	if len(content) != 2 {
		t.Fatalf("streaming first user content has %d blocks, want currentDate and user text", len(content))
	}
	assertClaudeCodeCurrentDateBlock(t, content[0])
	assertEphemeralUserTextBlock(t, content[1], "fetch", "1h")
	assertClaudeMidConversationSystemMessage(t, upstreamBody, 1, "stream-system-prompt", "1h")
	assertClaudeCredentialIdentity(t, upstreamBody, upstreamHeaders, deviceIDs, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	if !strings.Contains(downstream.String(), `"name":"fetch_url"`) {
		t.Fatalf("downstream stream did not restore fetch_url: %s", downstream.String())
	}
	if strings.Contains(downstream.String(), upstreamAlias) {
		t.Fatalf("downstream leaked upstream alias %q: %s", upstreamAlias, downstream.String())
	}
}

func TestPrependClaudeSystemReminders_FollowsToolResultsAndIsIdempotent(t *testing.T) {
	payload := []byte(`{"messages":[` +
		`{"role":"assistant","content":[{"type":"tool_use","id":"toolu_1","name":"Read","input":{}}]},` +
		`{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"ok"},{"type":"text","text":"continue"}]}` +
		`]}`)

	texts := []string{"first guidance", "second guidance"}
	first := prependClaudeSystemRemindersToFirstUserMessage(payload, texts)
	second := prependClaudeSystemRemindersToFirstUserMessage(first, texts)
	if !bytes.Equal(first, second) {
		t.Fatalf("caller reminder insertion is not idempotent:\nfirst:  %s\nsecond: %s", first, second)
	}
	content := gjson.GetBytes(first, "messages.1.content").Array()
	if len(content) != 4 {
		t.Fatalf("content has %d blocks, want tool_result, two caller reminders, and user text", len(content))
	}
	if got := content[0].Get("type").String(); got != "tool_result" {
		t.Fatalf("content[0].type = %q, want tool_result", got)
	}
	for idx, text := range texts {
		if got := content[idx+1].Get("text").String(); got != claudeCallerSystemReminder(text) {
			t.Fatalf("content[%d].text = %q, want caller reminder %q", idx+1, got, text)
		}
	}
	if got := content[3].Get("text").String(); got != "continue" {
		t.Fatalf("content[3].text = %q, want user text", got)
	}
}

func TestInsertClaudeMidConversationSystemMessages_FollowsToolResultUserTurn(t *testing.T) {
	payload := []byte(`{"messages":[` +
		`{"role":"assistant","content":[{"type":"tool_use","id":"toolu_1","name":"Read","input":{}}]},` +
		`{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"ok"}]}` +
		`]}`)

	out := insertClaudeMidConversationSystemMessages(payload, []string{"guidance"})
	if got := gjson.GetBytes(out, "messages.#").Int(); got != 3 {
		t.Fatalf("message count = %d, want 3: %s", got, out)
	}
	blocks := gjson.GetBytes(out, "messages.1.content")
	if got := blocks.Get("0.type").String(); got != "tool_result" {
		t.Fatalf("first block type = %q, want tool_result: %s", got, out)
	}
	if got := blocks.Get("0.tool_use_id").String(); got != "toolu_1" {
		t.Fatalf("tool_use_id = %q, want toolu_1: %s", got, out)
	}
	assertClaudeMidConversationSystemMessage(t, out, 2, "guidance", "")
}

func TestInsertClaudeMidConversationSystemMessages_PrecedesExistingAssistantTurn(t *testing.T) {
	payload := []byte(`{"messages":[` +
		`{"role":"user","content":"hello"},` +
		`{"role":"assistant","content":"answer"},` +
		`{"role":"user","content":"continue"}` +
		`]}`)

	out := insertClaudeMidConversationSystemMessages(payload, []string{"guidance"})
	roles := gjson.GetBytes(out, "messages.#.role").Array()
	wantRoles := []string{"user", "system", "assistant", "user"}
	if len(roles) != len(wantRoles) {
		t.Fatalf("message count = %d, want %d: %s", len(roles), len(wantRoles), out)
	}
	for idx, wantRole := range wantRoles {
		if got := roles[idx].String(); got != wantRole {
			t.Fatalf("messages[%d].role = %q, want %q", idx, got, wantRole)
		}
	}
	assertClaudeMidConversationSystemMessage(t, out, 1, "guidance", "")
}

func TestInsertClaudeMidConversationSystemMessages_FollowsConsecutiveUserRun(t *testing.T) {
	payload := []byte(`{"messages":[` +
		`{"role":"user","content":"first"},` +
		`{"role":"user","content":"second"},` +
		`{"role":"assistant","content":"answer"}` +
		`]}`)

	out := insertClaudeMidConversationSystemMessages(payload, []string{"guidance"})
	roles := gjson.GetBytes(out, "messages.#.role").Array()
	wantRoles := []string{"user", "user", "system", "assistant"}
	if len(roles) != len(wantRoles) {
		t.Fatalf("message count = %d, want %d: %s", len(roles), len(wantRoles), out)
	}
	for idx, wantRole := range wantRoles {
		if got := roles[idx].String(); got != wantRole {
			t.Fatalf("messages[%d].role = %q, want %q", idx, got, wantRole)
		}
	}
	assertClaudeMidConversationSystemMessage(t, out, 2, "guidance", "")
}

func TestInsertClaudeMidConversationSystemMessages_IsIdempotent(t *testing.T) {
	payload := []byte(`{"messages":[{"role":"user","content":"hello"}]}`)
	texts := []string{"first guidance", "second guidance"}
	first := insertClaudeMidConversationSystemMessages(payload, texts)
	second := insertClaudeMidConversationSystemMessages(first, texts)
	if !bytes.Equal(first, second) {
		t.Fatalf("mid-conversation system insertion is not idempotent:\nfirst:  %s\nsecond: %s", first, second)
	}
	if got := gjson.GetBytes(first, "messages.#").Int(); got != 3 {
		t.Fatalf("message count = %d, want user and two system messages: %s", got, first)
	}
	assertClaudeMidConversationSystemMessage(t, first, 1, texts[0], "")
	assertClaudeMidConversationSystemMessage(t, first, 2, texts[1], "")
}

// TestClaudeCodeCLIBetas_MatchesObservedClientMatrix pins the Anthropic-Beta
// baseline to Claude Code 2.1.220 behavior captured against api.anthropic.com.
// The OAuth profile was reverified on 2026-08-03 with two distinct accounts.
func TestClaudeCodeCLIBetas_MatchesObservedClientMatrix(t *testing.T) {
	const constants = "claude-code-20250219,interleaved-thinking-2025-05-14,redact-thinking-2026-02-12,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05"

	tests := []struct {
		name      string
		body      string
		requested map[string]bool
		oauth     bool
		want      string
	}{
		{
			name: "legacy model without tools omits both conditional betas",
			body: `{"model":"claude-opus-4-6"}`,
			want: constants + ",effort-2025-11-24",
		},
		{
			name:      "context 1m sits right after claude-code, not at the end",
			body:      `{"model":"claude-opus-4-6"}`,
			requested: map[string]bool{claudeContext1MBeta: true},
			want: "claude-code-20250219,context-1m-2025-08-07," +
				"interleaved-thinking-2025-05-14,redact-thinking-2026-02-12," +
				"thinking-token-count-2026-05-13,context-management-2025-06-27," +
				"prompt-caching-scope-2026-01-05,effort-2025-11-24",
		},
		{
			name: "opus-5 1m variant reproduces the full observed order",
			body: `{"model":"claude-opus-5","tools":[{"name":"Read","defer_loading":true}]}`,
			requested: map[string]bool{
				claudeContext1MBeta:          true,
				claudeServerSideFallbackBeta: true,
				claudeFallbackCreditBeta:     true,
			},
			want: "claude-code-20250219,context-1m-2025-08-07," +
				"interleaved-thinking-2025-05-14,redact-thinking-2026-02-12," +
				"thinking-token-count-2026-05-13,context-management-2025-06-27," +
				"prompt-caching-scope-2026-01-05,mid-conversation-system-2026-04-07," +
				"advanced-tool-use-2025-11-20,effort-2025-11-24," +
				"server-side-fallback-2026-06-01,fallback-credit-2026-06-01",
		},
		{
			name:      "structured outputs trails effort",
			body:      `{"model":"claude-opus-4-6"}`,
			requested: map[string]bool{claudeStructuredOutputsBeta: true},
			want:      constants + ",effort-2025-11-24,structured-outputs-2025-12-15",
		},
		{
			name:      "unknown caller beta is not smuggled into the baseline",
			body:      `{"model":"claude-opus-4-6"}`,
			requested: map[string]bool{"totally-made-up-2030-01-01": true},
			want:      constants + ",effort-2025-11-24",
		},
		{
			name: "claude-sonnet-5 accepts role=system",
			body: `{"model":"claude-sonnet-5"}`,
			want: constants + ",mid-conversation-system-2026-04-07,effort-2025-11-24",
		},
		{
			name: "claude-opus-4-8 accepts role=system",
			body: `{"model":"claude-opus-4-8"}`,
			want: constants + ",mid-conversation-system-2026-04-07,effort-2025-11-24",
		},
		{
			name: "claude-fable-5 accepts role=system",
			body: `{"model":"claude-fable-5"}`,
			want: constants + ",mid-conversation-system-2026-04-07,effort-2025-11-24",
		},
		{
			name: "claude-opus-4-7 stays on the reminder path",
			body: `{"model":"claude-opus-4-7"}`,
			want: constants + ",effort-2025-11-24",
		},
		{
			name:  "oauth uses tool search and the current cache TTL trailer",
			body:  `{"model":"claude-opus-4-6","tools":[{"name":"Read","defer_loading":true}]}`,
			oauth: true,
			want: "claude-code-20250219,oauth-2025-04-20," +
				"interleaved-thinking-2025-05-14,redact-thinking-2026-02-12," +
				"thinking-token-count-2026-05-13,context-management-2025-06-27," +
				"prompt-caching-scope-2026-01-05,advanced-tool-use-2025-11-20," +
				"effort-2025-11-24,fallback-credit-2026-06-01," +
				"extended-cache-ttl-2025-04-11",
		},
		{
			name:  "oauth precedes context-1m",
			body:  `{"model":"claude-opus-5","tools":[{"name":"Read","defer_loading":true}]}`,
			oauth: true,
			requested: map[string]bool{
				claudeContext1MBeta:          true,
				claudeServerSideFallbackBeta: true,
				claudeFallbackCreditBeta:     true,
			},
			want: "claude-code-20250219,oauth-2025-04-20,context-1m-2025-08-07," +
				"interleaved-thinking-2025-05-14,redact-thinking-2026-02-12," +
				"thinking-token-count-2026-05-13,context-management-2025-06-27," +
				"prompt-caching-scope-2026-01-05,mid-conversation-system-2026-04-07," +
				"advanced-tool-use-2025-11-20,effort-2025-11-24," +
				"server-side-fallback-2026-06-01,fallback-credit-2026-06-01," +
				"extended-cache-ttl-2025-04-11",
		},
		{
			name: "api key path sends neither oauth beta",
			body: `{"model":"claude-opus-4-6"}`,
			want: constants + ",effort-2025-11-24",
		},
		{
			name: "claude-haiku-4-5-20251001 stays on the reminder path and omits effort",
			body: `{"model":"claude-haiku-4-5-20251001"}`,
			want: constants,
		},
		{
			name: "legacy model with inline tools no longer adds advanced tool use",
			body: `{"model":"claude-sonnet-4-6","tools":[{"name":"Read"}]}`,
			want: constants + ",effort-2025-11-24",
		},
		{
			name: "deferred tool adds advanced tool use",
			body: `{"model":"claude-sonnet-4-6","tools":[{"name":"Read","defer_loading":true}]}`,
			want: constants + ",advanced-tool-use-2025-11-20,effort-2025-11-24",
		},
		{
			name: "tool search server tool adds advanced tool use",
			body: `{"model":"claude-sonnet-4-6","tools":[{"type":"tool_search_tool_regex_20251119","name":"tool_search_tool_regex"},{"name":"Read"}]}`,
			want: constants + ",advanced-tool-use-2025-11-20,effort-2025-11-24",
		},
		{
			name: "tool use examples add advanced tool use",
			body: `{"model":"claude-sonnet-4-6","tools":[{"name":"Read","input_examples":[{"path":"a.go"}]}]}`,
			want: constants + ",advanced-tool-use-2025-11-20,effort-2025-11-24",
		},
		{
			name: "programmatic tool calling adds advanced tool use",
			body: `{"model":"claude-sonnet-4-6","tools":[{"name":"Read","allowed_callers":["code_execution_20250825"]}]}`,
			want: constants + ",advanced-tool-use-2025-11-20,effort-2025-11-24",
		},
		{
			name:      "requested advanced tool use is honored for inline tools",
			body:      `{"model":"claude-sonnet-4-6","tools":[{"name":"Read"}]}`,
			requested: map[string]bool{claudeAdvancedToolUseBeta: true},
			want:      constants + ",advanced-tool-use-2025-11-20,effort-2025-11-24",
		},
		{
			name: "role=system model without tools adds mid conversation system only",
			body: `{"model":"claude-opus-5"}`,
			want: constants + ",mid-conversation-system-2026-04-07,effort-2025-11-24",
		},
		{
			name: "role=system model with tool search adds both in wire order",
			body: `{"model":"claude-opus-5","tools":[{"name":"Read","defer_loading":true}]}`,
			want: constants + ",mid-conversation-system-2026-04-07,advanced-tool-use-2025-11-20,effort-2025-11-24",
		},
		{
			name: "empty tools array does not add advanced tool use",
			body: `{"model":"claude-opus-4-6","tools":[]}`,
			want: constants + ",effort-2025-11-24",
		},
		{
			name: "unknown future model keeps the optimistic role=system default",
			body: `{"model":"claude-future-9"}`,
			want: constants + ",mid-conversation-system-2026-04-07,effort-2025-11-24",
		},
		{
			name: "thinking display summarized drops redact-thinking",
			body: `{"model":"claude-opus-5","thinking":{"type":"adaptive","display":"summarized"}}`,
			want: "claude-code-20250219,interleaved-thinking-2025-05-14," +
				"thinking-token-count-2026-05-13,context-management-2025-06-27," +
				"prompt-caching-scope-2026-01-05,mid-conversation-system-2026-04-07," +
				"effort-2025-11-24",
		},
		{
			name: "thinking display omitted drops redact-thinking as well",
			body: `{"model":"claude-opus-4-6","thinking":{"type":"enabled","budget_tokens":2048,"display":"omitted"}}`,
			want: "claude-code-20250219,interleaved-thinking-2025-05-14," +
				"thinking-token-count-2026-05-13,context-management-2025-06-27," +
				"prompt-caching-scope-2026-01-05,effort-2025-11-24",
		},
		{
			name: "thinking without display keeps redact-thinking",
			body: `{"model":"claude-opus-4-6","thinking":{"type":"adaptive"}}`,
			want: constants + ",effort-2025-11-24",
		},
		{
			name: "blank display value keeps redact-thinking",
			body: `{"model":"claude-opus-4-6","thinking":{"type":"adaptive","display":"  "}}`,
			want: constants + ",effort-2025-11-24",
		},
		{
			name:      "advisor tool beta requested placed before advanced-tool-use",
			body:      `{"model":"claude-opus-5","tools":[{"name":"Read","defer_loading":true}]}`,
			requested: map[string]bool{"advisor-tool-2026-03-01": true},
			want:      constants + ",mid-conversation-system-2026-04-07,advisor-tool-2026-03-01,advanced-tool-use-2025-11-20,effort-2025-11-24",
		},
		{
			name: "body with advisor server tool automatically adds advisor-tool beta",
			body: `{"model":"claude-opus-5","tools":[{"type":"advisor_20260301","name":"advisor"}]}`,
			want: constants + ",mid-conversation-system-2026-04-07,advisor-tool-2026-03-01,effort-2025-11-24",
		},
		{
			// Captured 2026-09-02 from Claude Code 2.1.258 (cli entrypoint, OAuth,
			// auto mode on): 158 inline tools without tool search, advisor beta
			// enabled for the account, thinking adaptive without display.
			name:  "2.1.258 main thread capture with inline tools and afk-mode",
			body:  `{"model":"claude-fable-5-1","tools":[{"name":"Read"}],"thinking":{"type":"adaptive"}}`,
			oauth: true,
			requested: map[string]bool{
				claudeAdvisorToolBeta: true,
				claudeAFKModeBeta:     true,
			},
			want: "claude-code-20250219,oauth-2025-04-20," +
				"interleaved-thinking-2025-05-14,redact-thinking-2026-02-12," +
				"thinking-token-count-2026-05-13,context-management-2025-06-27," +
				"prompt-caching-scope-2026-01-05,mid-conversation-system-2026-04-07," +
				"advisor-tool-2026-03-01,effort-2025-11-24,fallback-credit-2026-06-01," +
				"afk-mode-2026-01-31,extended-cache-ttl-2025-04-11",
		},
		{
			name:      "afk-mode sits between fast-mode and extended-cache-ttl",
			body:      `{"model":"claude-opus-5","speed":"fast"}`,
			oauth:     true,
			requested: map[string]bool{claudeAFKModeBeta: true},
			want: "claude-code-20250219,oauth-2025-04-20," +
				"interleaved-thinking-2025-05-14,redact-thinking-2026-02-12," +
				"thinking-token-count-2026-05-13,context-management-2025-06-27," +
				"prompt-caching-scope-2026-01-05,mid-conversation-system-2026-04-07," +
				"effort-2025-11-24,fallback-credit-2026-06-01,fast-mode-2026-02-01," +
				"afk-mode-2026-01-31,extended-cache-ttl-2025-04-11",
		},
		{
			name:  "afk-mode is not added unless the caller sent it",
			body:  `{"model":"claude-opus-5"}`,
			oauth: true,
			want: "claude-code-20250219,oauth-2025-04-20," +
				"interleaved-thinking-2025-05-14,redact-thinking-2026-02-12," +
				"thinking-token-count-2026-05-13,context-management-2025-06-27," +
				"prompt-caching-scope-2026-01-05,mid-conversation-system-2026-04-07," +
				"effort-2025-11-24,fallback-credit-2026-06-01,extended-cache-ttl-2025-04-11",
		},
		{
			name: "thinking display updates emits thinking-display-updates beta and drops redact-thinking",
			body: `{"model":"claude-fable-5-1","thinking":{"type":"adaptive","display":"updates"}}`,
			want: "claude-code-20250219,interleaved-thinking-2025-05-14," +
				"thinking-token-count-2026-05-13,context-management-2025-06-27," +
				"prompt-caching-scope-2026-01-05,mid-conversation-system-2026-04-07," +
				"effort-2025-11-24,thinking-display-updates-2026-08-18",
		},
		{
			name: "body with fallbacks automatically adds server-side-fallback beta",
			body: `{"model":"claude-fable-5-1","fallbacks":[{"model":"claude-opus-5"}]}`,
			want: constants + ",mid-conversation-system-2026-04-07,effort-2025-11-24,server-side-fallback-2026-06-01",
		},
		{
			name:  "subagent request omits extended-cache-ttl beta",
			body:  `{"model":"claude-sonnet-5","system":[{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.258.0ab; cc_is_subagent=true;"}]}`,
			oauth: true,
			want: "claude-code-20250219,oauth-2025-04-20," +
				"interleaved-thinking-2025-05-14,redact-thinking-2026-02-12," +
				"thinking-token-count-2026-05-13,context-management-2025-06-27," +
				"prompt-caching-scope-2026-01-05,mid-conversation-system-2026-04-07," +
				"effort-2025-11-24,fallback-credit-2026-06-01",
		},
		{
			name:  "probe request max_tokens=1 omits effort and extended-cache-ttl betas",
			body:  `{"model":"claude-sonnet-5","max_tokens":1}`,
			oauth: true,
			want: "claude-code-20250219,oauth-2025-04-20," +
				"interleaved-thinking-2025-05-14,redact-thinking-2026-02-12," +
				"thinking-token-count-2026-05-13,context-management-2025-06-27," +
				"prompt-caching-scope-2026-01-05,mid-conversation-system-2026-04-07," +
				"fallback-credit-2026-06-01",
		},
		{
			name:      "haiku model omits effort beta even if requested",
			body:      `{"model":"claude-haiku-4-5-20251001"}`,
			requested: map[string]bool{"effort-2025-11-24": true},
			oauth:     true,
			want: "claude-code-20250219,oauth-2025-04-20," +
				"interleaved-thinking-2025-05-14,redact-thinking-2026-02-12," +
				"thinking-token-count-2026-05-13,context-management-2025-06-27," +
				"prompt-caching-scope-2026-01-05," +
				"fallback-credit-2026-06-01,extended-cache-ttl-2025-04-11",
		},
		{
			name:      "disabled thinking omits effort beta even if requested",
			body:      `{"model":"claude-sonnet-5","thinking":{"type":"disabled"}}`,
			requested: map[string]bool{"effort-2025-11-24": true},
			oauth:     true,
			want: "claude-code-20250219,oauth-2025-04-20," +
				"interleaved-thinking-2025-05-14,redact-thinking-2026-02-12," +
				"thinking-token-count-2026-05-13,context-management-2025-06-27," +
				"prompt-caching-scope-2026-01-05,mid-conversation-system-2026-04-07," +
				"fallback-credit-2026-06-01,extended-cache-ttl-2025-04-11",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := claudeCodeCLIBetas([]byte(tt.body), tt.requested, tt.oauth); got != tt.want {
				t.Fatalf("claudeCodeCLIBetas() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestWithClaudeAdvisorToolBeta_InsertsBeforeTrailingBetas pins the advisor
// insertion point against every beta that follows it on the 2.1.258 wire,
// including a caller-supplied afk-mode-2026-01-31.
func TestWithClaudeAdvisorToolBeta_InsertsBeforeTrailingBetas(t *testing.T) {
	const head = "claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14,mid-conversation-system-2026-04-07"
	tests := []struct {
		name  string
		betas string
		want  string
	}{
		{
			name:  "afk-mode only trailer",
			betas: head + ",afk-mode-2026-01-31,extended-cache-ttl-2025-04-11",
			want:  head + ",advisor-tool-2026-03-01,afk-mode-2026-01-31,extended-cache-ttl-2025-04-11",
		},
		{
			name:  "effort ahead of afk-mode",
			betas: head + ",effort-2025-11-24,fallback-credit-2026-06-01,afk-mode-2026-01-31,extended-cache-ttl-2025-04-11",
			want:  head + ",advisor-tool-2026-03-01,effort-2025-11-24,fallback-credit-2026-06-01,afk-mode-2026-01-31,extended-cache-ttl-2025-04-11",
		},
		{
			name:  "already present stays put",
			betas: head + ",advisor-tool-2026-03-01,effort-2025-11-24,afk-mode-2026-01-31",
			want:  head + ",advisor-tool-2026-03-01,effort-2025-11-24,afk-mode-2026-01-31",
		},
		{
			name:  "no trailer appends",
			betas: head,
			want:  head + ",advisor-tool-2026-03-01",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := withClaudeAdvisorToolBeta(tt.betas); got != tt.want {
				t.Fatalf("withClaudeAdvisorToolBeta() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestApplyClaudeHeaders_StreamTransportNegotiation(t *testing.T) {
	auth := &cliproxyauth.Auth{Attributes: map[string]string{"api_key": "key-stream-accept"}}
	body := []byte(`{"model":"claude-opus-4-6","stream":true}`)

	directReq := newClaudeHeaderTestRequest(t, http.Header{})
	if errApply := applyClaudeHeaders(directReq, auth, "key-stream-accept", true, nil, body, nil, http.Header{}, false); errApply != nil {
		t.Fatalf("applyClaudeHeaders() error = %v", errApply)
	}
	if got, want := directReq.Header.Get("Accept"), "application/json"; got != want {
		t.Fatalf("streaming Accept = %q, want %q to match the real client", got, want)
	}
	if got, want := directReq.Header.Get("Accept-Encoding"), "gzip, deflate, br, zstd"; got != want {
		t.Fatalf("streaming Accept-Encoding = %q, want %q to match the real client", got, want)
	}

	gatewayReq := httptest.NewRequest(http.MethodPost, "https://api.kimi.com/coding/v1/messages", nil)
	gatewayReq = gatewayReq.WithContext(directReq.Context())
	if errApply := applyClaudeHeaders(gatewayReq, auth, "key-stream-accept", true, nil, body, nil, http.Header{}, false); errApply != nil {
		t.Fatalf("applyClaudeHeaders() error = %v", errApply)
	}
	if got, want := gatewayReq.Header.Get("Accept"), "text/event-stream"; got != want {
		t.Fatalf("gateway streaming Accept = %q, want %q", got, want)
	}
	if got, want := gatewayReq.Header.Get("Accept-Encoding"), "identity"; got != want {
		t.Fatalf("gateway streaming Accept-Encoding = %q, want %q", got, want)
	}
}

func TestApplyClaudeHeaders_DefaultPreservesCallerBetas(t *testing.T) {
	incoming := http.Header{"Anthropic-Beta": []string{"caller-only-beta"}}
	auth := &cliproxyauth.Auth{Attributes: map[string]string{"api_key": "key-caller-betas"}}
	body := []byte(`{"model":"claude-opus-4-6"}`)

	// Default API-key mode preserves caller betas on direct Anthropic.
	directReq := newClaudeHeaderTestRequest(t, incoming)
	if errApply := applyClaudeHeaders(directReq, auth, "key-caller-betas", false, nil, body, nil, incoming, false); errApply != nil {
		t.Fatalf("applyClaudeHeaders() error = %v", errApply)
	}
	if got := directReq.Header.Get("Anthropic-Beta"); got != "caller-only-beta" {
		t.Fatalf("Anthropic-Beta = %q, want caller beta on api.anthropic.com", got)
	}

	// Other Anthropic-compatible upstreams keep caller betas functional.
	gatewayReq := httptest.NewRequest(http.MethodPost, "https://api.kimi.com/coding/v1/messages", nil)
	gatewayReq = gatewayReq.WithContext(directReq.Context())
	if errApply := applyClaudeHeaders(gatewayReq, auth, "key-caller-betas", false, nil, body, nil, incoming, false); errApply != nil {
		t.Fatalf("applyClaudeHeaders() error = %v", errApply)
	}
	if got := gatewayReq.Header.Get("Anthropic-Beta"); !strings.Contains(got, "caller-only-beta") {
		t.Fatalf("Anthropic-Beta = %q, want caller beta preserved on non-Anthropic upstream", got)
	}
}

// TestInjectClaudeCodeContextManagement pins the captured 2.1.220 object and
// the thinking and caller-ownership rules that control automatic injection.
func TestInjectClaudeCodeContextManagement(t *testing.T) {
	const captured = `{"edits":[{"type":"clear_thinking_20251015","keep":"all"}]}`

	for _, test := range []struct {
		name    string
		payload string
	}{
		{name: "enabled thinking", payload: `{"model":"claude-opus-5","thinking":{"type":"enabled"}}`},
		{name: "adaptive thinking", payload: `{"model":"claude-opus-5","thinking":{"type":"adaptive"}}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, automaticallyInjected := injectClaudeCodeContextManagement([]byte(test.payload))
			if !automaticallyInjected {
				t.Fatal("automatic context_management injection was not reported")
			}
			if diff := gjson.GetBytes(got, "context_management").Raw; diff != captured {
				t.Fatalf("context_management = %s, want the captured object %s", diff, captured)
			}
		})
	}

	callerOwned := []byte(`{"model":"claude-opus-4-6","context_management":{"edits":[]}}`)
	callerOwnedGot, automaticallyInjected := injectClaudeCodeContextManagement(callerOwned)
	if automaticallyInjected {
		t.Error("caller context_management was reported as automatically injected")
	}
	if !bytes.Equal(callerOwnedGot, callerOwned) {
		t.Fatalf("caller context_management was modified: %s", callerOwnedGot)
	}

	// Anthropic rejects clear_thinking_20251015 unless thinking is enabled or
	// adaptive, so an omitted thinking field is as ineligible as an explicit
	// disabled one.
	for _, test := range []struct {
		name    string
		payload string
	}{
		{name: "disabled thinking", payload: `{"model":"claude-opus-5","thinking":{"type":"disabled"}}`},
		{name: "omitted thinking", payload: `{"model":"claude-opus-4-6"}`},
		{name: "unknown thinking", payload: `{"model":"claude-opus-5","thinking":{"type":"unexpected"}}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			ineligible := []byte(test.payload)
			got, automaticallyInjected := injectClaudeCodeContextManagement(ineligible)
			if automaticallyInjected {
				t.Error("ineligible thinking context_management was reported as automatically injected")
			}
			if !bytes.Equal(got, ineligible) {
				t.Errorf("ineligible payload was modified: %s", got)
			}
			if cm := gjson.GetBytes(got, "context_management"); cm.Exists() {
				t.Errorf("context_management = %s, want absent", cm.Raw)
			}
		})
	}
}

// Anthropic rejects a request carrying the clear_thinking_20251015 strategy
// without enabled/adaptive thinking:
//
//	`clear_thinking_20251015` strategy requires `thinking` to be enabled or adaptive
//
// This walks the real execute.go ordering, where disableThinkingIfToolChoiceForced
// deletes the thinking field between injection and reconciliation.
func TestClaudeCodeContextManagementNeverOutlivesEligibleThinking(t *testing.T) {
	for _, test := range []struct {
		name    string
		payload string
		wantCM  bool
	}{
		{
			name:    "thinking omitted from the start",
			payload: `{"model":"claude-opus-5","messages":[]}`,
		},
		{
			name:    "forced tool_choice strips thinking after injection",
			payload: `{"model":"claude-opus-5","thinking":{"type":"enabled","budget_tokens":1024},"tool_choice":{"type":"any"},"messages":[]}`,
		},
		{
			name:    "thinking survives without forced tool_choice",
			payload: `{"model":"claude-opus-5","thinking":{"type":"enabled","budget_tokens":1024},"messages":[]}`,
			wantCM:  true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			body, injected := injectClaudeCodeContextManagement([]byte(test.payload))
			state := claudeCodeContextManagementState{eligible: true, automaticallyInjected: injected}
			body = disableThinkingIfToolChoiceForced(body)
			body = reconcileClaudeCodeContextManagement(body, state)

			thinkingEligible := gjson.GetBytes(body, "thinking.type").String() == "enabled" ||
				gjson.GetBytes(body, "thinking.type").String() == "adaptive"
			cm := gjson.GetBytes(body, "context_management")
			if cm.Exists() && !thinkingEligible {
				t.Fatalf("context_management = %s survived ineligible thinking; Anthropic would reject this: %s", cm.Raw, body)
			}
			if cm.Exists() != test.wantCM {
				t.Fatalf("context_management present = %v, want %v; body=%s", cm.Exists(), test.wantCM, body)
			}
		})
	}
}

func TestReconcileClaudeCodeContextManagement(t *testing.T) {
	withAutomatic := func(thinkingType string) string {
		return `{"thinking":{"type":"` + thinkingType + `"},"context_management":` + claudeCodeContextManagement + `}`
	}

	for _, test := range []struct {
		name    string
		payload string
		state   claudeCodeContextManagementState
		wantRaw string
	}{
		{
			name:    "removes unchanged automatic object when disabled",
			payload: withAutomatic("disabled"),
			state:   claudeCodeContextManagementState{eligible: true, automaticallyInjected: true},
		},
		{
			name:    "preserves rule owned automatic object when disabled",
			payload: withAutomatic("disabled"),
			state:   claudeCodeContextManagementState{eligible: true, automaticallyInjected: true, payloadRuleTouched: true},
			wantRaw: claudeCodeContextManagement,
		},
		{
			name:    "preserves changed automatic object when disabled",
			payload: `{"thinking":{"type":"disabled"},"context_management":{"edits":[{"type":"custom"}]}}`,
			state:   claudeCodeContextManagementState{eligible: true, automaticallyInjected: true},
			wantRaw: `{"edits":[{"type":"custom"}]}`,
		},
		{
			name:    "adds automatic object when enabled",
			payload: `{"thinking":{"type":"enabled"}}`,
			state:   claudeCodeContextManagementState{eligible: true},
			wantRaw: claudeCodeContextManagement,
		},
		{
			name:    "adds automatic object when adaptive",
			payload: `{"thinking":{"type":"adaptive"}}`,
			state:   claudeCodeContextManagementState{eligible: true},
			wantRaw: claudeCodeContextManagement,
		},
		{
			name:    "caller ownership prevents addition",
			payload: `{"thinking":{"type":"enabled"}}`,
			state:   claudeCodeContextManagementState{eligible: true, callerOwned: true},
		},
		{
			name:    "payload rule ownership prevents addition",
			payload: `{"thinking":{"type":"enabled"}}`,
			state:   claudeCodeContextManagementState{eligible: true, payloadRuleTouched: true},
		},
		{
			name:    "ineligible request prevents addition",
			payload: `{"thinking":{"type":"enabled"}}`,
		},
		{
			name:    "omitted thinking prevents addition",
			payload: `{}`,
			state:   claudeCodeContextManagementState{eligible: true},
		},
		{
			name:    "removes automatic object when thinking was stripped entirely",
			payload: `{"context_management":` + claudeCodeContextManagement + `}`,
			state:   claudeCodeContextManagementState{eligible: true, automaticallyInjected: true},
		},
		{
			name:    "keeps caller object when thinking was stripped entirely",
			payload: `{"context_management":` + claudeCodeContextManagement + `}`,
			state:   claudeCodeContextManagementState{eligible: true, callerOwned: true},
			wantRaw: claudeCodeContextManagement,
		},
		{
			name:    "unknown thinking prevents addition",
			payload: `{"thinking":{"type":"unexpected"}}`,
			state:   claudeCodeContextManagementState{eligible: true},
		},
		{
			name:    "invalid thinking prevents addition",
			payload: `{"thinking":{"type":123}}`,
			state:   claudeCodeContextManagementState{eligible: true},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := reconcileClaudeCodeContextManagement([]byte(test.payload), test.state)
			if raw := gjson.GetBytes(got, "context_management").Raw; raw != test.wantRaw {
				t.Fatalf("context_management = %s, want %s; body=%s", raw, test.wantRaw, got)
			}
		})
	}
}

func TestClaudeExecutorPayloadOverrideDisabledThinking(t *testing.T) {
	const model = "claude-opus-5"
	modelRules := []config.PayloadModelRule{{Name: model, Protocol: "claude"}}
	basePayload := []byte(`{"model":"claude-opus-5","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}`)

	for _, test := range []struct {
		name   string
		stream bool
	}{
		{name: "execute"},
		{name: "execute stream", stream: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := &config.Config{Payload: config.PayloadConfig{Override: []config.PayloadRule{{
				Models: modelRules,
				Params: map[string]any{"thinking.type": "disabled"},
			}}}}
			upstreamBody := executeClaudeContextManagementRequest(t, cfg, basePayload, test.stream)
			if got := gjson.GetBytes(upstreamBody, "thinking.type").String(); got != "disabled" {
				t.Fatalf("final upstream thinking.type = %q, want disabled; body=%s", got, upstreamBody)
			}
			if got := gjson.GetBytes(upstreamBody, "context_management"); got.Exists() {
				t.Errorf("final upstream context_management = %s with disabled thinking, want absent", got.Raw)
			}
		})
	}

	t.Run("caller context management is preserved", func(t *testing.T) {
		cfg := &config.Config{Payload: config.PayloadConfig{Override: []config.PayloadRule{{
			Models: modelRules,
			Params: map[string]any{"thinking.type": "disabled"},
		}}}}
		payload := []byte(`{"model":"claude-opus-5","max_tokens":16,"messages":[{"role":"user","content":"hi"}],"context_management":{"edits":[{"type":"caller_owned"}]}}`)
		upstreamBody := executeClaudeContextManagementRequest(t, cfg, payload, false)
		if got := gjson.GetBytes(upstreamBody, "context_management.edits.0.type").String(); got != "caller_owned" {
			t.Fatalf("caller context_management type = %q, want caller_owned; body=%s", got, upstreamBody)
		}
	})

	t.Run("payload override replacement is preserved", func(t *testing.T) {
		cfg := &config.Config{Payload: config.PayloadConfig{Override: []config.PayloadRule{{
			Models: modelRules,
			Params: map[string]any{
				"thinking.type":      "disabled",
				"context_management": map[string]any{"edits": []any{map[string]any{"type": "payload_rule"}}},
			},
		}}}}
		upstreamBody := executeClaudeContextManagementRequest(t, cfg, basePayload, false)
		if got := gjson.GetBytes(upstreamBody, "context_management.edits.0.type").String(); got != "payload_rule" {
			t.Fatalf("payload-rule context_management type = %q, want payload_rule; body=%s", got, upstreamBody)
		}
	})

	t.Run("exact automatic value remains payload rule owned", func(t *testing.T) {
		ownershipConfigs := []struct {
			name string
			cfg  *config.Config
		}{
			{
				name: "default",
				cfg: &config.Config{Payload: config.PayloadConfig{
					Default: []config.PayloadRule{{
						Models: modelRules,
						Params: map[string]any{"context_management": json.RawMessage(claudeCodeContextManagement)},
					}},
					Override: []config.PayloadRule{{
						Models: modelRules,
						Params: map[string]any{"thinking.type": "disabled"},
					}},
				}},
			},
			{
				name: "raw default",
				cfg: &config.Config{Payload: config.PayloadConfig{
					DefaultRaw: []config.PayloadRule{{
						Models: modelRules,
						Params: map[string]any{"context_management": claudeCodeContextManagement},
					}},
					Override: []config.PayloadRule{{
						Models: modelRules,
						Params: map[string]any{"thinking.type": "disabled"},
					}},
				}},
			},
			{
				name: "override",
				cfg: &config.Config{Payload: config.PayloadConfig{Override: []config.PayloadRule{{
					Models: modelRules,
					Params: map[string]any{
						"thinking.type":      "disabled",
						"context_management": json.RawMessage(claudeCodeContextManagement),
					},
				}}}},
			},
			{
				name: "raw override",
				cfg: &config.Config{Payload: config.PayloadConfig{
					Override: []config.PayloadRule{{
						Models: modelRules,
						Params: map[string]any{"thinking.type": "disabled"},
					}},
					OverrideRaw: []config.PayloadRule{{
						Models: modelRules,
						Params: map[string]any{"context_management": claudeCodeContextManagement},
					}},
				}},
			},
		}
		for _, ownership := range ownershipConfigs {
			for _, stream := range []bool{false, true} {
				name := ownership.name + " execute"
				if stream {
					name += " stream"
				}
				t.Run(name, func(t *testing.T) {
					upstreamBody := executeClaudeContextManagementRequest(t, ownership.cfg, basePayload, stream)
					if got := gjson.GetBytes(upstreamBody, "thinking.type").String(); got != "disabled" {
						t.Fatalf("final upstream thinking.type = %q, want disabled; body=%s", got, upstreamBody)
					}
					if got := gjson.GetBytes(upstreamBody, "context_management").Raw; got != claudeCodeContextManagement {
						t.Fatalf("%s context_management = %s, want payload-rule-owned %s; body=%s", ownership.name, got, claudeCodeContextManagement, upstreamBody)
					}
				})
			}
		}
	})

	t.Run("payload filter remains effective", func(t *testing.T) {
		cfg := &config.Config{Payload: config.PayloadConfig{Filter: []config.PayloadFilterRule{{
			Models: modelRules,
			Params: []string{"context_management"},
		}}}}
		upstreamBody := executeClaudeContextManagementRequest(t, cfg, basePayload, false)
		if got := gjson.GetBytes(upstreamBody, "context_management"); got.Exists() {
			t.Fatalf("filtered context_management = %s, want absent", got.Raw)
		}
	})

	for _, stream := range []bool{false, true} {
		// Anthropic rejects the automatic strategy once forced tool choice has
		// stripped thinking:
		//
		//	`clear_thinking_20251015` strategy requires `thinking` to be enabled or adaptive
		name := "forced tool choice drops automatic context management execute"
		if stream {
			name += " stream"
		}
		t.Run(name, func(t *testing.T) {
			payload := []byte(`{"model":"claude-opus-5","max_tokens":16,"messages":[{"role":"user","content":"hi"}],"thinking":{"type":"adaptive"},"tool_choice":{"type":"any"}}`)
			upstreamBody := executeClaudeContextManagementRequest(t, &config.Config{}, payload, stream)
			if got := gjson.GetBytes(upstreamBody, "thinking"); got.Exists() {
				t.Fatalf("forced tool choice thinking = %s, want absent", got.Raw)
			}
			if got := gjson.GetBytes(upstreamBody, "context_management"); got.Exists() {
				t.Fatalf("forced tool choice context_management = %s, want absent because Anthropic rejects it without thinking", got.Raw)
			}
			if got := gjson.GetBytes(upstreamBody, "tool_choice.type").String(); got != "any" {
				t.Fatalf("forced tool_choice.type = %q, want any", got)
			}
		})
	}
}

func TestClaudeExecutorPayloadOverrideReenablesThinking(t *testing.T) {
	const model = "claude-opus-5"
	modelRules := []config.PayloadModelRule{{Name: model, Protocol: "claude"}}
	basePayload := []byte(`{"model":"claude-opus-5","max_tokens":16,"messages":[{"role":"user","content":"hi"}],"thinking":{"type":"disabled"}}`)

	for _, test := range []struct {
		name         string
		thinkingType string
		stream       bool
	}{
		{name: "execute enabled", thinkingType: "enabled"},
		{name: "execute adaptive", thinkingType: "adaptive"},
		{name: "execute stream enabled", thinkingType: "enabled", stream: true},
		{name: "execute stream adaptive", thinkingType: "adaptive", stream: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := &config.Config{Payload: config.PayloadConfig{Override: []config.PayloadRule{{
				Models: modelRules,
				Params: map[string]any{"thinking.type": test.thinkingType},
			}}}}
			upstreamBody := executeClaudeContextManagementRequest(t, cfg, basePayload, test.stream)
			if got := gjson.GetBytes(upstreamBody, "thinking.type").String(); got != test.thinkingType {
				t.Fatalf("final upstream thinking.type = %q, want %q; body=%s", got, test.thinkingType, upstreamBody)
			}
			if got := gjson.GetBytes(upstreamBody, "context_management").Raw; got != claudeCodeContextManagement {
				t.Fatalf("final upstream context_management = %s, want %s after payload override to %s; body=%s", got, claudeCodeContextManagement, test.thinkingType, upstreamBody)
			}
		})
	}

	for _, stream := range []bool{false, true} {
		nameSuffix := "execute"
		if stream {
			nameSuffix = "execute stream"
		}

		t.Run("caller context management is preserved after re-enabling "+nameSuffix, func(t *testing.T) {
			cfg := &config.Config{Payload: config.PayloadConfig{Override: []config.PayloadRule{{
				Models: modelRules,
				Params: map[string]any{"thinking.type": "enabled"},
			}}}}
			payload := []byte(`{"model":"claude-opus-5","max_tokens":16,"messages":[{"role":"user","content":"hi"}],"thinking":{"type":"disabled"},"context_management":{"edits":[{"type":"caller_owned"}]}}`)
			upstreamBody := executeClaudeContextManagementRequest(t, cfg, payload, stream)
			if got := gjson.GetBytes(upstreamBody, "context_management.edits.0.type").String(); got != "caller_owned" {
				t.Fatalf("caller context_management type = %q, want caller_owned; body=%s", got, upstreamBody)
			}
		})

		t.Run("custom payload rule object is preserved after re-enabling "+nameSuffix, func(t *testing.T) {
			cfg := &config.Config{Payload: config.PayloadConfig{Override: []config.PayloadRule{{
				Models: modelRules,
				Params: map[string]any{
					"thinking.type":      "adaptive",
					"context_management": map[string]any{"edits": []any{map[string]any{"type": "payload_rule"}}},
				},
			}}}}
			upstreamBody := executeClaudeContextManagementRequest(t, cfg, basePayload, stream)
			if got := gjson.GetBytes(upstreamBody, "context_management.edits.0.type").String(); got != "payload_rule" {
				t.Fatalf("payload-rule context_management type = %q, want payload_rule; body=%s", got, upstreamBody)
			}
		})

		t.Run("context management filter remains authoritative after re-enabling "+nameSuffix, func(t *testing.T) {
			cfg := &config.Config{Payload: config.PayloadConfig{
				Override: []config.PayloadRule{{
					Models: modelRules,
					Params: map[string]any{"thinking.type": "enabled"},
				}},
				Filter: []config.PayloadFilterRule{{
					Models: modelRules,
					Params: []string{"context_management"},
				}},
			}}
			upstreamBody := executeClaudeContextManagementRequest(t, cfg, basePayload, stream)
			if got := gjson.GetBytes(upstreamBody, "thinking.type").String(); got != "enabled" {
				t.Fatalf("final upstream thinking.type = %q, want enabled; body=%s", got, upstreamBody)
			}
			if got := gjson.GetBytes(upstreamBody, "context_management"); got.Exists() {
				t.Fatalf("filtered context_management = %s after re-enabling, want absent; body=%s", got.Raw, upstreamBody)
			}
		})
	}
}

func TestValidateClaudeCallerSystemBlocksAcceptsTextOnly(t *testing.T) {
	tests := []struct {
		name   string
		system string
	}{
		{name: "string", system: `"S1"`},
		{name: "text blocks", system: `[{"type":"text","text":"S1"},{"type":"text","text":"S2"}]`},
		{name: "absent", system: ``},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := `{"model":"claude-opus-5"}`
			if test.system != "" {
				payload = `{"model":"claude-opus-5","system":` + test.system + `}`
			}
			if err := validateClaudeCallerSystemBlocks(gjson.Get(payload, "system")); err != nil {
				t.Fatalf("validateClaudeCallerSystemBlocks() error = %v, want nil", err)
			}
		})
	}
}

// Anthropic rejects every non-text block in both system slots, verified live on
// 2026-08-03: the top-level field answers "system.<i>.type: Input should be
// 'text'" and a role=system message answers "role 'system' supports text,
// tool_addition, and tool_removal blocks only". Cloaking has no third slot, so
// the request has to fail here instead of losing the caller's instructions.
func TestValidateClaudeCallerSystemBlocksRejectsNonTextBlock(t *testing.T) {
	tests := []struct {
		name      string
		system    string
		wantIndex string
		wantType  string
	}{
		{
			name:      "image",
			system:    `[{"type":"text","text":"S1"},{"type":"image","source":{"type":"base64","media_type":"image/png","data":"AAAA"}}]`,
			wantIndex: "system.1.type",
			wantType:  `"image"`,
		},
		{
			name:      "responses marker",
			system:    `[{"type":"input_file"}]`,
			wantIndex: "system.0.type",
			wantType:  `"input_file"`,
		},
		{
			name:      "missing type",
			system:    `[{"text":"S1"}]`,
			wantIndex: "system.0.type",
			wantType:  `"unknown"`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateClaudeCallerSystemBlocks(gjson.Parse(test.system))
			if err == nil {
				t.Fatal("validateClaudeCallerSystemBlocks() error = nil, want rejection")
			}
			var statusCoder interface{ StatusCode() int }
			if !errors.As(err, &statusCoder) || statusCoder.StatusCode() != http.StatusBadRequest {
				t.Fatalf("error status = %v, want 400", err)
			}
			var scoped interface{ IsRequestScoped() bool }
			if !errors.As(err, &scoped) || !scoped.IsRequestScoped() {
				t.Fatalf("error %v must be request scoped so no other credential is tried", err)
			}
			if got := err.Error(); !strings.Contains(got, test.wantIndex) || !strings.Contains(got, test.wantType) {
				t.Fatalf("error = %q, want it to name %s and %s", got, test.wantIndex, test.wantType)
			}
		})
	}
}

func TestApplyCloakingRejectsNonTextCallerSystemBlock(t *testing.T) {
	cfg := &config.Config{}
	auth := &cliproxyauth.Auth{Attributes: map[string]string{"api_key": "key-123", "cloak_mode": "always"}}
	payload := []byte(`{"model":"claude-opus-5","system":[{"type":"text","text":"S1"},{"type":"input_image"}],"messages":[{"role":"user","content":[{"type":"text","text":"U1"}]}]}`)

	out, cloaked, errCloaking := applyCloaking(context.Background(), cfg, auth, payload, "key-123", false, true)
	if errCloaking == nil {
		t.Fatal("applyCloaking() error = nil, want rejection")
	}
	if out != nil {
		t.Fatalf("applyCloaking() payload = %s, want nil", out)
	}
	if cloaked {
		t.Fatal("applyCloaking() cloaked = true, want false")
	}
}

// Strict mode never forwards caller system prompts, so an unusable block cannot
// lose information and must not fail the request.
func TestApplyCloakingStrictModeIgnoresNonTextCallerSystemBlock(t *testing.T) {
	cfg := &config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey: "key-123",
			Cloak:  &config.CloakConfig{StrictMode: true},
		}},
	}
	auth := &cliproxyauth.Auth{Attributes: map[string]string{"api_key": "key-123"}}
	payload := []byte(`{"model":"claude-opus-5","system":[{"type":"input_image"}],"messages":[{"role":"user","content":[{"type":"text","text":"U1"}]}]}`)

	out, cloaked, errCloaking := applyCloaking(context.Background(), cfg, auth, payload, "key-123", false, true)
	if errCloaking != nil {
		t.Fatalf("applyCloaking() error = %v, want nil", errCloaking)
	}
	if !cloaked {
		t.Fatal("applyCloaking() cloaked = false, want true")
	}
	if got := len(gjson.GetBytes(out, "system").Array()); got != 2 {
		t.Fatalf("system blocks = %d, want the 2 Claude Code blocks", got)
	}
}

// A cloaked direct-Anthropic count_tokens request relocates caller system blocks
// into messages, so a non-text block has no destination there either and must be
// rejected before any upstream call.
func TestClaudeExecutor_CountTokensRejectsNonTextCallerSystemBlock(t *testing.T) {
	upstreamCalled := false
	transport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		upstreamCalled = true
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"input_tokens":1}`)), Request: req}, nil
	})
	ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", http.RoundTripper(transport))
	auth := &cliproxyauth.Auth{Attributes: map[string]string{"api_key": "sk-ant-oat-count-system-block"}}
	payload := []byte(`{"model":"claude-opus-5","system":[{"type":"text","text":"S1"},{"type":"input_image"}],"messages":[{"role":"user","content":[{"type":"text","text":"x"}]}]}`)

	_, errCount := NewClaudeExecutor(&config.Config{}).countTokensUpstream(ctx, auth,
		cliproxyexecutor.Request{Model: "claude-opus-5", Payload: payload},
		cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatClaude})
	if errCount == nil {
		t.Fatal("countTokensUpstream() error = nil, want rejection")
	}
	var statusCoder interface{ StatusCode() int }
	if !errors.As(errCount, &statusCoder) || statusCoder.StatusCode() != http.StatusBadRequest {
		t.Fatalf("countTokensUpstream() error = %v, want 400", errCount)
	}
	if upstreamCalled {
		t.Fatal("countTokensUpstream() called upstream, want local rejection")
	}
}

// The native gate selects the 1h cache pool only for OAuth credentials and pushes
// extended-cache-ttl-2025-04-11 exactly when that selection produced a 1h body ttl.
// Body ttl and the beta must therefore always travel together.
func TestClaudeExecutor_CacheTTLIsPairedWithExtendedCacheTTLBeta(t *testing.T) {
	tests := []struct {
		name     string
		apiKey   string
		wantTTL  string
		wantBeta bool
	}{
		{
			name:     "oauth credential selects the 1h pool",
			apiKey:   "sk-ant-oat-cache-ttl-pairing",
			wantTTL:  "1h",
			wantBeta: true,
		},
		{
			name:     "api key credential keeps the default pool",
			apiKey:   "key-cache-ttl-pairing",
			wantTTL:  "",
			wantBeta: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var seenBody []byte
			var seenHeaders http.Header
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seenBody, _ = io.ReadAll(r.Body)
				seenHeaders = r.Header.Clone()
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-opus-4-6","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
			}))
			defer server.Close()

			executor := NewClaudeExecutor(&config.Config{})
			auth := &cliproxyauth.Auth{
				ID: "cache-ttl-pairing",
				Attributes: map[string]string{
					"api_key":    test.apiKey,
					"base_url":   server.URL,
					"cloak_mode": "always",
				},
				Metadata: claudeOAuthTestMetadata(),
			}
			_, errExecute := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
				Model:   "claude-opus-4-6",
				Payload: []byte(`{"model":"claude-opus-4-6","messages":[{"role":"user","content":[{"type":"text","text":"x"}]}]}`),
			}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatClaude})
			if errExecute != nil {
				t.Fatalf("Execute() error = %v", errExecute)
			}

			gotTTL := gjson.GetBytes(seenBody, "system.1.cache_control.ttl").String()
			if gotTTL != test.wantTTL {
				t.Fatalf("system[1].cache_control.ttl = %q, want %q: %s", gotTTL, test.wantTTL, seenBody)
			}
			if got := gjson.GetBytes(seenBody, "system.1.cache_control.type").String(); got != "ephemeral" {
				t.Fatalf("system[1].cache_control.type = %q, want ephemeral: %s", got, seenBody)
			}
			gotBeta := strings.Contains(seenHeaders.Get("Anthropic-Beta"), claudeExtendedCacheTTLBeta)
			if gotBeta != test.wantBeta {
				t.Fatalf("extended-cache-ttl declared = %v, want %v: %s", gotBeta, test.wantBeta, seenHeaders.Get("Anthropic-Beta"))
			}
			// The pairing invariant itself: a 1h body ttl without the beta, or the beta
			// without a 1h body ttl, is a combination native never produces.
			if (gotTTL == "1h") != gotBeta {
				t.Fatalf("body ttl %q and extended-cache-ttl beta %v disagree", gotTTL, gotBeta)
			}
		})
	}
}

func TestClaudeExecutor_PreservesNativeAgentAndEnvironmentHeaders(t *testing.T) {
	tests := []struct {
		name            string
		incomingHeaders http.Header
		wantHeaders     map[string]string
		wantAbsent      []string
	}{
		{
			name: "preserves canonical agent and parent agent headers",
			incomingHeaders: http.Header{
				"X-Claude-Code-Agent-Id":        {"subagent-001"},
				"X-Claude-Code-Parent-Agent-Id": {"parent-agent-root"},
			},
			wantHeaders: map[string]string{
				"X-Claude-Code-Agent-Id":        "subagent-001",
				"X-Claude-Code-Parent-Agent-Id": "parent-agent-root",
			},
		},
		{
			name: "preserves lowercased agent and environment headers",
			incomingHeaders: http.Header{
				"x-claude-code-agent-id":            {"agent-xyz"},
				"x-claude-remote-container-id":      {"container-123"},
				"x-claude-remote-session-id":        {"remote-sess-456"},
				"x-client-app":                      {"custom-sdk"},
				"x-anthropic-additional-protection": {"true"},
			},
			wantHeaders: map[string]string{
				"X-Claude-Code-Agent-Id":            "agent-xyz",
				"X-Claude-Remote-Container-Id":      "container-123",
				"X-Claude-Remote-Session-Id":        "remote-sess-456",
				"X-Client-App":                      "custom-sdk",
				"X-Anthropic-Additional-Protection": "true",
			},
		},
		{
			name: "does not fabricate agent header when absent",
			incomingHeaders: http.Header{
				"User-Agent": {"test-client"},
			},
			wantAbsent: []string{
				"X-Claude-Code-Agent-Id",
				"X-Claude-Code-Parent-Agent-Id",
				"X-Claude-Remote-Container-Id",
				"X-Claude-Remote-Session-Id",
				"X-Client-App",
				"X-Anthropic-Additional-Protection",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var seenHeaders http.Header
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seenHeaders = r.Header.Clone()
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"id":"msg_agent","type":"message","model":"claude-opus-4-6","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
			}))
			defer server.Close()

			executor := NewClaudeExecutor(&config.Config{})
			auth := &cliproxyauth.Auth{
				ID: "agent-header-test",
				Attributes: map[string]string{
					"api_key":    "sk-ant-test-key",
					"base_url":   server.URL,
					"cloak_mode": "always",
				},
				Metadata: claudeOAuthTestMetadata(),
			}

			_, errExecute := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
				Model:   "claude-opus-4-6",
				Payload: []byte(`{"model":"claude-opus-4-6","messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`),
			}, cliproxyexecutor.Options{
				SourceFormat: sdktranslator.FormatClaude,
				Headers:      tt.incomingHeaders,
			})
			if errExecute != nil {
				t.Fatalf("Execute() error = %v", errExecute)
			}

			for wantKey, wantVal := range tt.wantHeaders {
				if got := seenHeaders.Get(wantKey); got != wantVal {
					t.Errorf("header %s = %q, want %q", wantKey, got, wantVal)
				}
			}
			for _, absentKey := range tt.wantAbsent {
				if got := seenHeaders.Get(absentKey); got != "" {
					t.Errorf("header %s = %q, want absent", absentKey, got)
				}
			}
		})
	}
}

func TestIsClaudeFable51Model_DigitBoundary(t *testing.T) {
	valid := []string{
		"claude-fable-5-1",
		"claude-fable-5.1",
		"claude-fable-5-1-20260901",
		"claude-mythos-5-1",
		"claude-mythos-5.1",
		"claude-mythos-5-1-preview",
	}
	for _, m := range valid {
		if !isClaudeFable51Model(m) {
			t.Errorf("expected %q to be recognized as Fable 5.1", m)
		}
	}

	invalid := []string{
		"claude-fable-5-10",
		"claude-fable-5.10",
		"claude-mythos-5-10",
		"claude-sonnet-5",
		"claude-opus-5",
		"claude-haiku-4-5",
	}
	for _, m := range invalid {
		if isClaudeFable51Model(m) {
			t.Errorf("expected %q NOT to be recognized as Fable 5.1", m)
		}
	}
}

func TestClaudeExecutor_ProbeStripsCaller1hTTLAndBetas(t *testing.T) {
	var seenHeaders http.Header
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHeaders = r.Header.Clone()
		seenBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-sonnet-5","role":"assistant","content":[{"type":"text","text":"ok"}]}`))
	}))
	defer server.Close()

	cfg := &config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey: "sk-ant-oat-probe-ttl-test",
		}},
	}
	auth := &cliproxyauth.Auth{
		ID:       "auth-probe-ttl-test",
		Metadata: claudeOAuthTestMetadata(),
		Attributes: map[string]string{
			"api_key":  "sk-ant-oat-probe-ttl-test",
			"base_url": server.URL,
		},
	}

	executor := NewClaudeExecutor(cfg)
	// Probe request with caller-supplied 1h TTL and forbidden betas
	payload := []byte(`{
		"model": "claude-sonnet-5",
		"max_tokens": 1,
		"messages": [{
			"role": "user",
			"content": [
				{"type": "text", "text": "quota", "cache_control": {"type": "ephemeral", "ttl": "1h"}}
			]
		}]
	}`)
	incomingHeaders := http.Header{}
	incomingHeaders.Set("Anthropic-Beta", "extended-cache-ttl-2025-04-11,server-side-fallback-2026-06-01,thinking-display-updates-2026-08-18,effort-2025-11-24")

	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-sonnet-5",
		Payload: payload,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatClaude,
		Headers:      incomingHeaders,
	})
	if err != nil {
		t.Fatalf("Execute error = %v", err)
	}

	// 1. Verify body cache_control does not have ttl: "1h"
	rawBody := string(seenBody)
	if strings.Contains(rawBody, `"ttl":"1h"`) || strings.Contains(rawBody, `"ttl": "1h"`) {
		t.Fatalf("probe body must have ttl stripped, got: %s", rawBody)
	}

	// 2. Verify forbidden betas are stripped from header
	betas := seenHeaders.Get("Anthropic-Beta")
	for _, forbidden := range []string{
		"extended-cache-ttl-2025-04-11",
		"server-side-fallback-2026-06-01",
		"thinking-display-updates-2026-08-18",
		"effort-2025-11-24",
	} {
		if strings.Contains(betas, forbidden) {
			t.Errorf("probe Anthropic-Beta must not contain %s, got: %s", forbidden, betas)
		}
	}
}

func TestClaudeExecutor_SubagentPreservesCaller1hTTLAndExtendedCacheBeta(t *testing.T) {
	var seenHeaders http.Header
	var seenBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHeaders = r.Header.Clone()
		seenBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-sonnet-5","role":"assistant","content":[{"type":"text","text":"ok"}]}`))
	}))
	defer server.Close()

	cfg := &config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey: "sk-ant-oat-subagent-ttl-test",
		}},
	}
	auth := &cliproxyauth.Auth{
		ID:       "auth-subagent-ttl-test",
		Metadata: claudeOAuthTestMetadata(),
		Attributes: map[string]string{
			"api_key":  "sk-ant-oat-subagent-ttl-test",
			"base_url": server.URL,
		},
	}

	executor := NewClaudeExecutor(cfg)
	payload := []byte(`{
		"model": "claude-sonnet-5",
		"messages": [{
			"role": "user",
			"content": [
				{"type": "text", "text": "subagent work", "cache_control": {"type": "ephemeral", "ttl": "1h"}}
			]
		}]
	}`)
	incomingHeaders := http.Header{}
	incomingHeaders.Set("X-Claude-Code-Agent-Id", "agent-sub-123")
	incomingHeaders.Set("Anthropic-Beta", "extended-cache-ttl-2025-04-11")

	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-sonnet-5",
		Payload: payload,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatClaude,
		Headers:      incomingHeaders,
	})
	if err != nil {
		t.Fatalf("Execute error = %v", err)
	}

	// 1. Verify body cache_control preserves ttl: "1h"
	rawBody := string(seenBody)
	if !strings.Contains(rawBody, `"ttl":"1h"`) && !strings.Contains(rawBody, `"ttl": "1h"`) {
		t.Fatalf("subagent body must preserve ttl: 1h when requested, got: %s", rawBody)
	}

	// 2. Verify extended-cache-ttl beta is preserved in header
	betas := seenHeaders.Get("Anthropic-Beta")
	if !strings.Contains(betas, "extended-cache-ttl-2025-04-11") {
		t.Errorf("subagent Anthropic-Beta must preserve extended-cache-ttl when requested, got: %s", betas)
	}
}

func TestClaudeExecutor_DisabledThinkingStripsDisplayBeta(t *testing.T) {
	var seenHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-sonnet-5","role":"assistant","content":[{"type":"text","text":"ok"}]}`))
	}))
	defer server.Close()

	cfg := &config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey: "sk-ant-oat-disabled-thinking-beta-test",
		}},
	}
	auth := &cliproxyauth.Auth{
		ID:       "auth-disabled-thinking-beta-test",
		Metadata: claudeOAuthTestMetadata(),
		Attributes: map[string]string{
			"api_key":  "sk-ant-oat-disabled-thinking-beta-test",
			"base_url": server.URL,
		},
	}

	executor := NewClaudeExecutor(cfg)
	payload := []byte(`{
		"model": "claude-sonnet-5",
		"thinking": {"type": "disabled"},
		"messages": [{
			"role": "user",
			"content": "hello"
		}]
	}`)
	incomingHeaders := http.Header{}
	incomingHeaders.Set("Anthropic-Beta", "thinking-display-updates-2026-08-18,effort-2025-11-24")

	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-sonnet-5",
		Payload: payload,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatClaude,
		Headers:      incomingHeaders,
	})
	if err != nil {
		t.Fatalf("Execute error = %v", err)
	}

	betas := seenHeaders.Get("Anthropic-Beta")
	if strings.Contains(betas, "thinking-display-updates-2026-08-18") {
		t.Errorf("disabled thinking must not send thinking-display-updates beta, got: %s", betas)
	}
	if strings.Contains(betas, "effort-2025-11-24") {
		t.Errorf("disabled thinking must not send effort beta, got: %s", betas)
	}
}

func TestClaudeExecutor_CloakModePrefersStoredPrevReqOverCallerFake(t *testing.T) {
	var seenBodies [][]byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seenBodies = append(seenBodies, body)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("request-id", "req_real_upstream_001")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-sonnet-5","role":"assistant","content":[{"type":"text","text":"ok"}]}`))
	}))
	defer server.Close()

	cfg := &config.Config{
		ClaudeKey: []config.ClaudeKey{{
			APIKey: "sk-ant-oat-cloak-prev-req-test",
			Cloak:  &config.CloakConfig{},
		}},
	}
	auth := &cliproxyauth.Auth{
		ID:       "auth-cloak-prev-req-test",
		Metadata: claudeOAuthTestMetadata(),
		Attributes: map[string]string{
			"api_key":  "sk-ant-oat-cloak-prev-req-test",
			"base_url": server.URL,
		},
	}

	executor := NewClaudeExecutor(cfg)
	headers := http.Header{"Session-Id": []string{"sess-test-001"}}

	// Turn 1: normal turn, establishes real upstream request-id req_real_upstream_001
	_, err := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-sonnet-5",
		Payload: []byte(`{"model":"claude-sonnet-5","messages":[{"role":"user","content":"turn 1"}]}`),
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatClaude,
		Headers:      headers,
	})
	if err != nil {
		t.Fatalf("Turn 1 Execute error = %v", err)
	}

	// Turn 2: a non-native caller in cloak mode sends a fake cc_prev_req in system
	fakeCallerPayload := []byte(`{
		"model": "claude-sonnet-5",
		"system": [
			{"type": "text", "text": "x-anthropic-billing-header: cc_version=2.1.258.000; cc_entrypoint=cli; cch=00000; cc_prev_req=req_fake_caller_999; cc_prompt_id=aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee;"},
			{"type": "text", "text": "custom instructions"}
		],
		"messages": [
			{"role":"user","content":"turn 1"},
			{"role":"assistant","content":"ok"},
			{"role":"user","content":"turn 2"}
		]
	}`)

	_, err2 := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-sonnet-5",
		Payload: fakeCallerPayload,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatClaude,
		Headers:      headers,
	})
	if err2 != nil {
		t.Fatalf("Turn 2 Execute error = %v", err2)
	}

	if len(seenBodies) < 2 {
		t.Fatalf("expected at least 2 requests, got %d", len(seenBodies))
	}
	turn2System := gjson.GetBytes(seenBodies[1], "system.0.text").String()
	if !strings.Contains(turn2System, "cc_prev_req=req_real_upstream_001") {
		t.Fatalf("CPA in cloak mode must use real storedPrevReq req_real_upstream_001, got: %s", turn2System)
	}
	if strings.Contains(turn2System, "req_fake_caller_999") {
		t.Fatalf("CPA must not use fake caller cc_prev_req, got: %s", turn2System)
	}
}
