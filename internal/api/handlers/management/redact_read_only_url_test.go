package management

import "testing"

func TestRedactReadOnlyProxyURL(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"plain text unchanged", "weighted-round-robin", "weighted-round-robin"},
		{"proxy userinfo stripped", "socks5://u:synthetic-secret@proxy.example.invalid:1080", "socks5://proxy.example.invalid:1080"},
		{"opaque turn userinfo stripped", "turn:u:synthetic-secret@turn.example.invalid:3478", "turn:turn.example.invalid:3478"},
		{"note with email and link kept", "contact ops@example.com or see https://docs.example/runbook", "contact ops@example.com or see https://docs.example/runbook"},
		{"note with credential URL redacted in place", "fallback http://u:synthetic-secret@proxy.example.invalid then retry", "fallback http://proxy.example.invalid then retry"},
		{"malformed URL with userinfo fails closed", "http://u:synthetic-secret@[bad", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := redactReadOnlyProxyURL(tc.in); got != tc.want {
				t.Fatalf("redactReadOnlyProxyURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
