package helps

import (
	"net/http"
	"testing"
	"time"
)

func TestClaudeQuotaResetEvidence(t *testing.T) {
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	shortReset := now.Add(2 * time.Hour).Format(time.RFC3339)
	weeklyReset := now.Add(6 * 24 * time.Hour).Format(time.RFC3339)
	for _, tc := range []struct {
		name   string
		header http.Header
		want   time.Duration
	}{
		{
			name: "five-hour rejection cannot inherit a weekly unified reset",
			header: http.Header{
				"Anthropic-Ratelimit-Unified-5h-Status": {"rejected"},
				"Anthropic-Ratelimit-Unified-5h-Reset":  {shortReset},
				"Anthropic-Ratelimit-Unified-7d-Status": {"allowed"},
				"Anthropic-Ratelimit-Unified-Reset":     {weeklyReset},
			},
			want: 2 * time.Hour,
		},
		{
			name: "unclassified weekly reset is not evidence of exhaustion",
			header: http.Header{
				"Anthropic-Ratelimit-Unified-Reset": {weeklyReset},
			},
		},
		{
			name: "explicit weekly rejection preserves the provider reset",
			header: http.Header{
				"Anthropic-Ratelimit-Unified-7d-Status": {"rejected"},
				"Anthropic-Ratelimit-Unified-7d-Reset":  {weeklyReset},
			},
			want: 6 * 24 * time.Hour,
		},
		{
			name: "weekly representative claim supports a unified reset",
			header: http.Header{
				"Anthropic-Ratelimit-Unified-Representative-Claim": {"seven_day"},
				"Anthropic-Ratelimit-Unified-Reset":                {weeklyReset},
			},
			want: 6 * 24 * time.Hour,
		},
		{
			name: "allowed weekly window does not support a conflicting claim",
			header: http.Header{
				"Anthropic-Ratelimit-Unified-Representative-Claim": {"seven_day"},
				"Anthropic-Ratelimit-Unified-7d-Status":            {"allowed"},
				"Anthropic-Ratelimit-Unified-Reset":                {weeklyReset},
			},
		},
		{
			name: "implausible five-hour reset is ignored",
			header: http.Header{
				"Anthropic-Ratelimit-Unified-5h-Status": {"rejected"},
				"Anthropic-Ratelimit-Unified-5h-Reset":  {weeklyReset},
				"Retry-After":                           {"120"},
			},
			want: 2 * time.Minute,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.header.Set("Anthropic-Ratelimit-Unified-Status", "rejected")
			got := parseClaudeRateLimitResetWithFuzz(tc.header, now, 0, 0)
			if tc.want == 0 {
				if got != nil {
					t.Fatalf("reset = %v, want no authoritative reset", *got)
				}
			} else if got == nil || *got != tc.want {
				t.Fatalf("reset = %v, want %v", got, tc.want)
			}
		})
	}
}
