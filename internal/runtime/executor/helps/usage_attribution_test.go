package helps

import (
	"context"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/usage"
)

// Completion records already provide per-attempt attribution. Keep using this
// existing index rather than introducing a second identity or logging key suffixes.
func TestUsageReporterCompletionPreservesStableCredentialAttribution(t *testing.T) {
	ctx := logging.WithRequestID(context.Background(), "attribution-request")
	indices := make(map[string]bool)
	for _, key := range []string{"synthetic-key-first-shared", "synthetic-key-second-shared"} {
		auth := &cliproxyauth.Auth{
			ID: "synthetic-auth-id", Provider: "claude",
			Attributes: map[string]string{"api_key": key},
		}
		index := auth.EnsureIndex()
		if index == "" || indices[index] {
			t.Fatal("distinct credentials must have distinct nonempty indices")
		}
		indices[index] = true
		for _, failed := range []bool{false, true} {
			reporter := NewUsageReporter(ctx, "claude", "attribution-test-model", auth)
			record := reporter.buildRecord(usage.Detail{TotalTokens: 10}, failed, usage.Failure{})
			if record.AuthIndex != index || record.TraceID != "attribution-request" || record.Provider != "claude" || record.Failed != failed {
				t.Fatalf("completion lost credential/request attribution: index=%q trace=%q provider=%q failed=%v", record.AuthIndex, record.TraceID, record.Provider, record.Failed)
			}
		}
	}
}
