package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

const endpointChangeMessage = "credentials must be re-entered when changing endpoint"

// TestManagementProviderPatchRoundTrip preserves every credential-bearing leaf
// when a panel sends the masked entry returned by GET back as PATCH value.
func TestManagementProviderPatchRoundTrip(t *testing.T) {
	type providerCase struct {
		name   string
		path   string
		seed   string
		secret []string
		field  string
	}
	cases := []providerCase{
		{"claude", "/v0/management/claude-api-key", `[{"api-key":"patch-claude-api-key-0001","base-url":"https://claude.patch.invalid","proxy-url":"http://proxy-user:patch-claude-proxy-0001@proxy.patch.invalid:8080","headers":{"X-Api-Key":"patch-claude-header-0001","Authorization":"Bearer patch-claude-auth-0001"},"prefix":"claude-team"}]`, []string{"patch-claude-api-key-0001", "patch-claude-proxy-0001", "patch-claude-header-0001", "patch-claude-auth-0001"}, "priority"},
		{"gemini", "/v0/management/gemini-api-key", `[{"api-key":"patch-gemini-api-key-0001","base-url":"https://gemini.patch.invalid","proxy-url":"http://proxy-user:patch-gemini-proxy-0001@proxy.patch.invalid:8080","headers":{"X-Api-Key":"patch-gemini-header-0001","Authorization":"Bearer patch-gemini-auth-0001"},"prefix":"gemini-team"}]`, []string{"patch-gemini-api-key-0001", "patch-gemini-proxy-0001", "patch-gemini-header-0001", "patch-gemini-auth-0001"}, "priority"},
		{"codex", "/v0/management/codex-api-key", `[{"api-key":"patch-codex-api-key-0001","base-url":"https://codex.patch.invalid","proxy-url":"http://proxy-user:patch-codex-proxy-0001@proxy.patch.invalid:8080","headers":{"X-Api-Key":"patch-codex-header-0001","Authorization":"Bearer patch-codex-auth-0001"},"prefix":"codex-team"}]`, []string{"patch-codex-api-key-0001", "patch-codex-proxy-0001", "patch-codex-header-0001", "patch-codex-auth-0001"}, "priority"},
		{"xai", "/v0/management/xai-api-key", `[{"api-key":"patch-xai-api-key-0001","base-url":"https://xai.patch.invalid","proxy-url":"http://proxy-user:patch-xai-proxy-0001@proxy.patch.invalid:8080","headers":{"X-Api-Key":"patch-xai-header-0001","Authorization":"Bearer patch-xai-auth-0001"},"prefix":"xai-team"}]`, []string{"patch-xai-api-key-0001", "patch-xai-proxy-0001", "patch-xai-header-0001", "patch-xai-auth-0001"}, "priority"},
		{"meta", "/v0/management/meta-api-key", `[{"api-key":"patch-meta-api-key-0001","base-url":"https://meta.patch.invalid","proxy-url":"http://proxy-user:patch-meta-proxy-0001@proxy.patch.invalid:8080","headers":{"X-Api-Key":"patch-meta-header-0001","Authorization":"Bearer patch-meta-auth-0001"},"prefix":"meta-team"}]`, []string{"patch-meta-api-key-0001", "patch-meta-proxy-0001", "patch-meta-header-0001", "patch-meta-auth-0001"}, "priority"},
		{"vertex", "/v0/management/vertex-api-key", `[{"api-key":"patch-vertex-api-key-0001","base-url":"https://vertex.patch.invalid","proxy-url":"http://proxy-user:patch-vertex-proxy-0001@proxy.patch.invalid:8080","headers":{"X-Api-Key":"patch-vertex-header-0001","Authorization":"Bearer patch-vertex-auth-0001"},"prefix":"vertex-team"}]`, []string{"patch-vertex-api-key-0001", "patch-vertex-proxy-0001", "patch-vertex-header-0001", "patch-vertex-auth-0001"}, "priority"},
		{"interactions", "/v0/management/interactions-api-key", `[{"api-key":"patch-interactions-api-key-0001","base-url":"https://interactions.patch.invalid","proxy-url":"http://proxy-user:patch-interactions-proxy-0001@proxy.patch.invalid:8080","headers":{"X-Api-Key":"patch-interactions-header-0001","Authorization":"Bearer patch-interactions-auth-0001"},"prefix":"interactions-team"}]`, []string{"patch-interactions-api-key-0001", "patch-interactions-proxy-0001", "patch-interactions-header-0001", "patch-interactions-auth-0001"}, "priority"},
		{"openai-compatibility", "/v0/management/openai-compatibility", `[{"name":"patch-openai-compat","base-url":"https://openai.patch.invalid","priority":1,"api-key-entries":[{"api-key":"patch-openai-api-key-0001","proxy-url":"http://proxy-user:patch-openai-proxy-0001@proxy.patch.invalid:8080","headers":{"X-Api-Key":"patch-openai-header-0001","Authorization":"Bearer patch-openai-auth-0001"}}]}]`, []string{"patch-openai-api-key-0001", "patch-openai-proxy-0001", "patch-openai-header-0001", "patch-openai-auth-0001"}, "priority"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newRoundTripEnv(t)
			if rec := e.do(http.MethodPut, tc.path, tc.seed); rec.Code != http.StatusOK {
				t.Fatalf("seed status=%d body=%s", rec.Code, rec.Body.String())
			}
			entry := getManagementEntry(t, e, tc.path)
			body := map[string]any{"index": 0, "value": entry}
			body["value"].(map[string]any)[tc.field] = 9
			encoded, _ := json.Marshal(body)
			if rec := e.do(http.MethodPatch, tc.path, string(encoded)); rec.Code != http.StatusOK {
				t.Fatalf("PATCH status=%d body=%s", rec.Code, rec.Body.String())
			}
			saved := e.persisted()
			for _, secret := range tc.secret {
				if !strings.Contains(saved, secret) {
					t.Errorf("PATCH lost %q\n%s", secret, saved)
				}
			}
		})
	}
}

func getManagementEntry(t *testing.T, e *roundTripEnv, path string) map[string]any {
	t.Helper()
	rec := e.do(http.MethodGet, path, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", rec.Code, rec.Body.String())
	}
	var envelope map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	for _, value := range envelope {
		if items, ok := value.([]any); ok && len(items) > 0 {
			entry, ok := items[0].(map[string]any)
			if !ok {
				t.Fatalf("entry is %T", items[0])
			}
			return entry
		}
	}
	t.Fatalf("GET %s did not return an entry: %s", path, rec.Body.String())
	return nil
}

func TestManagementProviderPatchRejectsMaskedOrOmittedSecretOnEndpointChange(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		seed   string
		secret string
	}{
		{"claude", "/v0/management/claude-api-key", `[{"api-key":"endpoint-claude-old-0001","base-url":"https://old.endpoint.invalid"}]`, "endpoint-claude-old-0001"},
		{"gemini", "/v0/management/gemini-api-key", `[{"api-key":"endpoint-gemini-old-0001","base-url":"https://old.endpoint.invalid"}]`, "endpoint-gemini-old-0001"},
		{"codex", "/v0/management/codex-api-key", `[{"api-key":"endpoint-codex-old-0001","base-url":"https://old.endpoint.invalid"}]`, "endpoint-codex-old-0001"},
		{"xai", "/v0/management/xai-api-key", `[{"api-key":"endpoint-xai-old-0001","base-url":"https://old.endpoint.invalid"}]`, "endpoint-xai-old-0001"},
		{"meta", "/v0/management/meta-api-key", `[{"api-key":"endpoint-meta-old-0001","base-url":"https://old.endpoint.invalid"}]`, "endpoint-meta-old-0001"},
		{"vertex", "/v0/management/vertex-api-key", `[{"api-key":"endpoint-vertex-old-0001","base-url":"https://old.endpoint.invalid"}]`, "endpoint-vertex-old-0001"},
		{"interactions", "/v0/management/interactions-api-key", `[{"api-key":"endpoint-interactions-old-0001","base-url":"https://old.endpoint.invalid"}]`, "endpoint-interactions-old-0001"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newRoundTripEnv(t)
			if rec := e.do(http.MethodPut, tc.path, tc.seed); rec.Code != http.StatusOK {
				t.Fatalf("seed status=%d body=%s", rec.Code, rec.Body.String())
			}
			before := e.persisted()
			masked := getManagementEntry(t, e, tc.path)
			masked["base-url"] = "https://new.endpoint.invalid"
			encoded, _ := json.Marshal(map[string]any{"index": 0, "value": masked})
			rec := e.do(http.MethodPatch, tc.path, string(encoded))
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), endpointChangeMessage) {
				t.Fatalf("masked endpoint change status=%d body=%s", rec.Code, rec.Body.String())
			}
			if got := e.persisted(); got != before || !strings.Contains(got, tc.secret) {
				t.Fatalf("rejected masked endpoint change mutated storage: %s", got)
			}

			omitted := map[string]any{"base-url": "https://new.endpoint.invalid"}
			encoded, _ = json.Marshal(map[string]any{"index": 0, "value": omitted})
			rec = e.do(http.MethodPatch, tc.path, string(encoded))
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), endpointChangeMessage) {
				t.Fatalf("omitted endpoint change status=%d body=%s", rec.Code, rec.Body.String())
			}
			if got := e.persisted(); got != before {
				t.Fatalf("rejected omitted endpoint change mutated storage: %s", got)
			}
		})
	}
}

func TestManagementOpenAICompatPatchRoundTripKeepsAPIKeyEntries(t *testing.T) {
	e := newRoundTripEnv(t)
	seed := `[{"name":"compat-entry","base-url":"https://compat.old.invalid","api-key-entries":[{"api-key":"compat-key-old-0001","proxy-url":"http://u:compat-proxy-old-0001@compat.proxy.invalid:8080","headers":{"X-Api-Key":"compat-header-old-0001","Authorization":"Bearer compat-auth-old-0001"}}]}]`
	if rec := e.do(http.MethodPut, "/v0/management/openai-compatibility", seed); rec.Code != http.StatusOK {
		t.Fatalf("seed status=%d body=%s", rec.Code, rec.Body.String())
	}
	entry := getManagementEntry(t, e, "/v0/management/openai-compatibility")
	entry["prefix"] = "compat-team"
	encoded, _ := json.Marshal(map[string]any{"index": 0, "value": entry})
	if rec := e.do(http.MethodPatch, "/v0/management/openai-compatibility", string(encoded)); rec.Code != http.StatusOK {
		t.Fatalf("PATCH status=%d body=%s", rec.Code, rec.Body.String())
	}
	for _, want := range []string{"compat-key-old-0001", "compat-proxy-old-0001", "compat-header-old-0001", "compat-auth-old-0001", "compat-team"} {
		if !strings.Contains(e.persisted(), want) {
			t.Errorf("OpenAI compatibility PATCH lost %q", want)
		}
	}
}

func TestManagementProviderPatchRejectsUnresolvedMask(t *testing.T) {
	e := newRoundTripEnv(t)
	seed := `[{"api-key":"unresolved-claude-key-0001","base-url":"https://one.endpoint.invalid"}]`
	if rec := e.do(http.MethodPut, "/v0/management/claude-api-key", seed); rec.Code != http.StatusOK {
		t.Fatalf("seed status=%d body=%s", rec.Code, rec.Body.String())
	}
	before := e.persisted()
	body := `{"index":0,"value":{"api-key":"***ZZZZ","prefix":"changed"}}`
	if rec := e.do(http.MethodPatch, "/v0/management/claude-api-key", body); rec.Code != http.StatusBadRequest {
		t.Fatalf("unresolved mask status=%d body=%s", rec.Code, rec.Body.String())
	}
	if got := e.persisted(); got != before {
		t.Fatalf("unresolved mask mutated storage: %s", got)
	}
}

func TestManagementProviderPatchEndpointChangeAcceptsExplicitReplacement(t *testing.T) {
	e := newRoundTripEnv(t)
	seed := `[{"api-key":"endpoint-replace-old-0001","base-url":"https://old.endpoint.invalid"}]`
	if rec := e.do(http.MethodPut, "/v0/management/claude-api-key", seed); rec.Code != http.StatusOK {
		t.Fatalf("seed status=%d body=%s", rec.Code, rec.Body.String())
	}
	body := `{"index":0,"value":{"api-key":"endpoint-replace-new-0001","base-url":"https://new.endpoint.invalid"}}`
	if rec := e.do(http.MethodPatch, "/v0/management/claude-api-key", body); rec.Code != http.StatusOK {
		t.Fatalf("explicit replacement status=%d body=%s", rec.Code, rec.Body.String())
	}
	saved := e.persisted()
	if strings.Contains(saved, "endpoint-replace-old-0001") || !strings.Contains(saved, "endpoint-replace-new-0001") || !strings.Contains(saved, "new.endpoint.invalid") {
		t.Fatalf("explicit endpoint replacement was not persisted: %s", saved)
	}
}
