package auth

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	log "github.com/sirupsen/logrus"
)

func TestUpstreamFailureLogsStableCredentialIndex(t *testing.T) {
	for _, status := range []int{0, 429} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			hook := setupTestLoggerHook(t)
			auth := &Auth{ID: "attribution-auth", Provider: "claude", Attributes: map[string]string{"api_key": "synthetic-key"}}
			index := auth.EnsureIndex()
			warnLogUpstreamFailure(context.Background(), nil, "claude", "attribution-test-model", auth, time.Millisecond,
				statusErrorLogTestError{message: "synthetic failure", statusCode: status})
			entries := hook.AllEntries()
			if len(entries) != 1 || entries[0].Data["auth_index"] != index {
				t.Fatalf("upstream failure lost stable credential index: %#v", entries)
			}
		})
	}
}

func TestManagerLogsStableCredentialAttributionAtInfo(t *testing.T) {
	for _, operation := range []string{"execute", "stream", "count"} {
		t.Run(operation, func(t *testing.T) {
			hook := setupTestLoggerHook(t)
			log.SetLevel(log.InfoLevel)
			manager := NewManager(nil, &RoundRobinSelector{}, nil)
			manager.RegisterExecutor(scriptedFailoverExecutor{provider: "claude"})
			const model = "attribution-test-model"
			indices := make(map[string]bool)
			keys := []string{"synthetic-key-first-shared", "synthetic-key-second-shared"}
			for i, key := range keys {
				auth, err := manager.Register(WithSkipPersist(context.Background()), &Auth{
					ID: fmt.Sprintf("attribution-%s-%d", operation, i), Provider: "claude", Status: StatusActive,
					Attributes: map[string]string{"api_key": key},
				})
				if err != nil {
					t.Fatal(err)
				}
				indices[auth.Index] = false
				registry.GetGlobalRegistry().RegisterClient(auth.ID, "claude", []*registry.ModelInfo{{ID: model}})
				t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(auth.ID) })
			}
			ctx := logging.WithRequestID(context.Background(), "attribution-request")
			for range keys {
				req := cliproxyexecutor.Request{Model: model}
				switch operation {
				case "execute":
					if _, err := manager.Execute(ctx, []string{"claude"}, req, cliproxyexecutor.Options{}); err != nil {
						t.Fatal(err)
					}
				case "count":
					if _, err := manager.ExecuteCount(ctx, []string{"claude"}, req, cliproxyexecutor.Options{}); err != nil {
						t.Fatal(err)
					}
				case "stream":
					stream, err := manager.ExecuteStream(ctx, []string{"claude"}, req, cliproxyexecutor.Options{})
					if err != nil {
						t.Fatal(err)
					}
					for chunk := range stream.Chunks {
						if chunk.Err != nil {
							t.Fatal(chunk.Err)
						}
					}
				}
			}
			selections := 0
			for _, entry := range hook.AllEntries() {
				if entry.Message != "Selected upstream credential" {
					continue
				}
				selections++
				index, _ := entry.Data["auth_index"].(string)
				if seen, ok := indices[index]; !ok || seen || index == "" {
					t.Fatalf("missing, duplicate, or unknown auth_index %q", index)
				}
				indices[index] = true
				if entry.Data["request_id"] != "attribution-request" || entry.Data["provider"] != "claude" || entry.Data["model"] != model || entry.Data["request_class"] != "unclassified" {
					t.Fatalf("incorrect attribution fields: %#v", entry.Data)
				}
				rendered, err := (&logging.LogFormatter{}).Format(entry)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(rendered), `auth_index="`+index+`"`) {
					t.Fatalf("formatter dropped auth_index: %s", rendered)
				}
				for _, key := range keys {
					if strings.Contains(string(rendered), key) {
						t.Fatal("selection log exposed an API key")
					}
				}
			}
			if selections != len(keys) || len(indices) != len(keys) {
				t.Fatalf("got %d selection events and %d distinct indices, want %d", selections, len(indices), len(keys))
			}
		})
	}
}

// TestRequestClassAttribution verifies background/interactive/unclassified are logged distinctly
// based on trafficClassKey presence (not conflated), plus no key leak in selection logs.
func TestRequestClassAttribution(t *testing.T) {
	hook := setupTestLoggerHook(t)
	log.SetLevel(log.InfoLevel)
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.RegisterExecutor(scriptedFailoverExecutor{provider: "claude"})
	const model = "class-test-model"
	auth, err := manager.Register(WithSkipPersist(context.Background()), &Auth{
		ID: "class-test-auth", Provider: "claude", Status: StatusActive,
		Attributes: map[string]string{"api_key": "synthetic-key-class"},
	})
	if err != nil {
		t.Fatal(err)
	}
	registry.GetGlobalRegistry().RegisterClient(auth.ID, "claude", []*registry.ModelInfo{{ID: model}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(auth.ID) })

	cases := []struct {
		name  string
		ctx   context.Context
		class string
	}{
		{"unclassified", logging.WithRequestID(context.Background(), "class-unclassified"), "unclassified"},
		{"interactive", context.WithValue(logging.WithRequestID(context.Background(), "class-interactive"), trafficClassKey{}, false), "interactive"},
		{"background", context.WithValue(logging.WithRequestID(context.Background(), "class-background"), trafficClassKey{}, true), "background"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := cliproxyexecutor.Request{Model: model}
			if _, err := manager.Execute(c.ctx, []string{"claude"}, req, cliproxyexecutor.Options{}); err != nil {
				t.Fatal(err)
			}
		})
	}

	seen := map[string]bool{}
	for _, entry := range hook.AllEntries() {
		if entry.Message != "Selected upstream credential" {
			continue
		}
		rc, _ := entry.Data["request_class"].(string)
		seen[rc] = true
		if rc != "unclassified" && rc != "interactive" && rc != "background" {
			t.Fatalf("unexpected request_class %q", rc)
		}
		// no identity/key leak
		rendered, err := (&logging.LogFormatter{}).Format(entry)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(rendered), "synthetic-key-class") || strings.Contains(string(rendered), "class-test-auth") {
			t.Fatal("selection log exposed identity or key")
		}
	}
	for _, want := range []string{"unclassified", "interactive", "background"} {
		if !seen[want] {
			t.Fatalf("missing request_class %q in logs: %#v", want, seen)
		}
	}
}
