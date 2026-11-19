package config

import (
	"fmt"
	"strings"
	"testing"
)

func TestCodexKeysCreditResetDay(t *testing.T) {
	for _, day := range []int{0, 1, 31, -1, 32} {
		t.Run(fmt.Sprint(day), func(t *testing.T) {
			data := []byte(fmt.Sprintf(`config-version: 8
api-keys:
  codex:
    - name: monthly
      base-url: https://api.openai.com/v1
      keys:
        - api-key: test
          credit-reset-day: %d
        - api-key: unconfigured
`, day))
			validateErr := ValidateV8Config(data)
			cfg, err := ParseConfigBytes(data)
			if day < 0 || day > 31 {
				if err == nil || !strings.Contains(err.Error(), "credit-reset-day") || validateErr == nil {
					t.Fatalf("invalid day %d: parse=%v, validate=%v", day, err, validateErr)
				}
				return
			}
			if err != nil || validateErr != nil {
				t.Fatalf("valid day %d: parse=%v, validate=%v", day, err, validateErr)
			}
			if len(cfg.CodexKey) != 2 || cfg.CodexKey[0].CreditResetDay != day || cfg.CodexKey[1].CreditResetDay != 0 {
				t.Fatalf("reset day did not remain per key: %+v", cfg.CodexKey)
			}
		})
	}
}
