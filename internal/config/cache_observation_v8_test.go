package config

import (
	"strings"
	"testing"
)

// TestCacheObservationSurvivesV8Layout guards CPA-002: the v8 layout must keep
// an active cache-observation block instead of commenting it out, so an
// unrelated management save cannot silently disable observation.
func TestCacheObservationSurvivesV8Layout(t *testing.T) {
	const raw = `config-version: 8
server:
  port: 8317
cache-observation:
  session-id: synthetic-session
  expires-at: "2099-01-01T00:00:00Z"
  max-attempts: 3
`
	for _, migrate := range []bool{false, true} {
		normalized, _, err := NormalizeConfigLayout([]byte(raw), migrate)
		if err != nil {
			t.Fatalf("migrate=%v: NormalizeConfigLayout: %v", migrate, err)
		}
		if strings.Contains(string(normalized), "# cache-observation") || !strings.Contains(string(normalized), "cache-observation:") {
			t.Fatalf("migrate=%v: cache-observation not preserved:\n%s", migrate, normalized)
		}
		cfg, err := ParseConfigBytes(normalized)
		if err != nil {
			t.Fatalf("migrate=%v: ParseConfigBytes: %v", migrate, err)
		}
		if cfg.CacheObservation == nil || cfg.CacheObservation.SessionID != "synthetic-session" || cfg.CacheObservation.MaxAttempts != 3 {
			t.Fatalf("migrate=%v: CacheObservation = %+v", migrate, cfg.CacheObservation)
		}
	}
	if err := ValidateV8Config([]byte(raw)); err != nil {
		t.Fatalf("ValidateV8Config rejected cache-observation: %v", err)
	}
}
