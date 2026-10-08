package executor

import (
	"context"
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
	"sync"
	"testing"
	"time"
)

func TestApplyClaudeHeaders_FastModeBetaIsConditional(t *testing.T) {
	baseline := claudeCodeCLIBetas([]byte(`{"model":"claude-opus-5"}`), nil, false)
	betasWithoutFastMode := baseline
	betasWithFastMode := baseline + "," + claudeFastModeBeta

	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "omitted speed excludes fast mode beta",
			body: `{"model":"claude-opus-5"}`,
			want: betasWithoutFastMode,
		},
		{
			name: "fast speed appends fast mode beta",
			body: `{"model":"claude-opus-5","speed":"fast"}`,
			want: betasWithFastMode,
		},
		{
			name: "explicit body beta appends fast mode beta",
			body: `{"model":"claude-opus-5","betas":["fast-mode-2026-02-01"]}`,
			want: betasWithFastMode,
		},
	}

	auth := &cliproxyauth.Auth{Attributes: map[string]string{"api_key": "key-fast-mode-beta", "cloak_mode": "always"}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extraBetas, body := extractAndRemoveBetas([]byte(tt.body))
			req := newClaudeHeaderTestRequest(t, nil)
			if errApply := applyClaudeHeaders(req, auth, "key-fast-mode-beta", false, extraBetas, body, nil, nil, false); errApply != nil {
				t.Fatalf("applyClaudeHeaders() error = %v", errApply)
			}
			if got := req.Header.Get("Anthropic-Beta"); got != tt.want {
				t.Fatalf("Anthropic-Beta = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestApplyClaudeHeaders_UsesConfiguredBaselineFingerprint(t *testing.T) {
	resetClaudeDeviceProfileCache()
	stabilize := true

	cfg := &config.Config{
		ClaudeHeaderDefaults: config.ClaudeHeaderDefaults{
			UserAgent:              "claude-cli/2.1.70 (external, cli)",
			PackageVersion:         "0.80.0",
			RuntimeVersion:         "v24.5.0",
			OS:                     "MacOS",
			Arch:                   "arm64",
			Timeout:                "900",
			StabilizeDeviceProfile: &stabilize,
		},
	}
	auth := &cliproxyauth.Auth{
		ID: "auth-baseline",
		Attributes: map[string]string{
			"api_key":                            "key-baseline",
			"cloak_mode":                         "always",
			"header:User-Agent":                  "evil-client/9.9",
			"header:X-Stainless-Os":              "Linux",
			"header:X-Stainless-Arch":            "x64",
			"header:X-Stainless-Package-Version": "9.9.9",
		},
	}
	incoming := http.Header{
		"User-Agent":                  []string{"curl/8.7.1"},
		"X-Stainless-Package-Version": []string{"0.10.0"},
		"X-Stainless-Runtime-Version": []string{"v18.0.0"},
		"X-Stainless-Os":              []string{"Linux"},
		"X-Stainless-Arch":            []string{"x64"},
	}

	req := newClaudeHeaderTestRequest(t, incoming)
	applyClaudeHeaders(req, auth, "key-baseline", false, nil, nil, cfg, nil, false)

	assertClaudeFingerprint(t, req.Header, "evil-client/9.9", "9.9.9", "v24.5.0", "Linux", "x64")
	if got := req.Header.Get("X-Stainless-Timeout"); got != "900" {
		t.Fatalf("X-Stainless-Timeout = %q, want %q", got, "900")
	}
}

func TestApplyClaudeHeaders_RejectsUnmeasuredClaudeCLIFingerprints(t *testing.T) {
	resetClaudeDeviceProfileCache()
	stabilize := true

	cfg := &config.Config{
		ClaudeHeaderDefaults: config.ClaudeHeaderDefaults{
			UserAgent:              "claude-cli/2.1.60 (external, cli)",
			PackageVersion:         "0.70.0",
			RuntimeVersion:         "v22.0.0",
			OS:                     "MacOS",
			Arch:                   "arm64",
			StabilizeDeviceProfile: &stabilize,
		},
	}
	auth := &cliproxyauth.Auth{
		ID: "auth-upgrade",
		Attributes: map[string]string{
			"api_key":    "key-upgrade",
			"cloak_mode": "always",
		},
	}

	firstReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"claude-cli/2.1.62 (external, cli)"},
		"X-Stainless-Package-Version": []string{"0.74.0"},
		"X-Stainless-Runtime-Version": []string{"v24.3.0"},
		"X-Stainless-Os":              []string{"Linux"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(firstReq, auth, "key-upgrade", false, nil, nil, cfg, nil, true)
	assertClaudeFingerprint(t, firstReq.Header, "claude-cli/2.1.60 (external, cli)", "0.70.0", "v22.0.0", "MacOS", "arm64")

	thirdPartyReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"lobe-chat/1.0"},
		"X-Stainless-Package-Version": []string{"0.10.0"},
		"X-Stainless-Runtime-Version": []string{"v18.0.0"},
		"X-Stainless-Os":              []string{"Windows"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(thirdPartyReq, auth, "key-upgrade", false, nil, nil, cfg, nil, false)
	assertClaudeFingerprint(t, thirdPartyReq.Header, "claude-cli/2.1.60 (external, cli)", "0.70.0", "v22.0.0", "MacOS", "arm64")

	higherReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"claude-cli/2.1.63 (external, cli)"},
		"X-Stainless-Package-Version": []string{"0.75.0"},
		"X-Stainless-Runtime-Version": []string{"v24.4.0"},
		"X-Stainless-Os":              []string{"MacOS"},
		"X-Stainless-Arch":            []string{"arm64"},
	})
	applyClaudeHeaders(higherReq, auth, "key-upgrade", false, nil, nil, cfg, nil, true)
	assertClaudeFingerprint(t, higherReq.Header, "claude-cli/2.1.60 (external, cli)", "0.70.0", "v22.0.0", "MacOS", "arm64")

	lowerReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"claude-cli/2.1.61 (external, cli)"},
		"X-Stainless-Package-Version": []string{"0.73.0"},
		"X-Stainless-Runtime-Version": []string{"v24.2.0"},
		"X-Stainless-Os":              []string{"Windows"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(lowerReq, auth, "key-upgrade", false, nil, nil, cfg, nil, true)
	assertClaudeFingerprint(t, lowerReq.Header, "claude-cli/2.1.60 (external, cli)", "0.70.0", "v22.0.0", "MacOS", "arm64")
}

func TestApplyClaudeHeaders_DoesNotDowngradeConfiguredBaselineOnFirstClaudeClient(t *testing.T) {
	resetClaudeDeviceProfileCache()
	stabilize := true

	cfg := &config.Config{
		ClaudeHeaderDefaults: config.ClaudeHeaderDefaults{
			UserAgent:              "claude-cli/2.1.70 (external, cli)",
			PackageVersion:         "0.80.0",
			RuntimeVersion:         "v24.5.0",
			OS:                     "MacOS",
			Arch:                   "arm64",
			StabilizeDeviceProfile: &stabilize,
		},
	}
	auth := &cliproxyauth.Auth{
		ID: "auth-baseline-floor",
		Attributes: map[string]string{
			"api_key": "key-baseline-floor",
		},
	}

	olderClaudeReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"claude-cli/2.1.62 (external, cli)"},
		"X-Stainless-Package-Version": []string{"0.74.0"},
		"X-Stainless-Runtime-Version": []string{"v24.3.0"},
		"X-Stainless-Os":              []string{"Linux"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(olderClaudeReq, auth, "key-baseline-floor", false, nil, nil, cfg, nil, true)
	assertClaudeFingerprint(t, olderClaudeReq.Header, "claude-cli/2.1.70 (external, cli)", "0.80.0", "v24.5.0", "MacOS", "arm64")

	newerClaudeReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"claude-cli/2.1.71 (external, cli)"},
		"X-Stainless-Package-Version": []string{"0.81.0"},
		"X-Stainless-Runtime-Version": []string{"v24.6.0"},
		"X-Stainless-Os":              []string{"Linux"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(newerClaudeReq, auth, "key-baseline-floor", false, nil, nil, cfg, nil, true)
	assertClaudeFingerprint(t, newerClaudeReq.Header, "claude-cli/2.1.70 (external, cli)", "0.80.0", "v24.5.0", "MacOS", "arm64")
}

func TestApplyClaudeHeaders_UpgradesCachedSoftwareFingerprintWhenBaselineAdvances(t *testing.T) {
	resetClaudeDeviceProfileCache()
	stabilize := true

	oldCfg := &config.Config{
		ClaudeHeaderDefaults: config.ClaudeHeaderDefaults{
			UserAgent:              "claude-cli/2.1.70 (external, cli)",
			PackageVersion:         "0.80.0",
			RuntimeVersion:         "v24.5.0",
			OS:                     "MacOS",
			Arch:                   "arm64",
			StabilizeDeviceProfile: &stabilize,
		},
	}
	newCfg := &config.Config{
		ClaudeHeaderDefaults: config.ClaudeHeaderDefaults{
			UserAgent:              "claude-cli/2.1.77 (external, cli)",
			PackageVersion:         "0.87.0",
			RuntimeVersion:         "v24.8.0",
			OS:                     "MacOS",
			Arch:                   "arm64",
			StabilizeDeviceProfile: &stabilize,
		},
	}
	auth := &cliproxyauth.Auth{
		ID: "auth-baseline-reload",
		Attributes: map[string]string{
			"api_key":    "key-baseline-reload",
			"cloak_mode": "always",
		},
	}

	officialReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"claude-cli/2.1.71 (external, cli)"},
		"X-Stainless-Package-Version": []string{"0.81.0"},
		"X-Stainless-Runtime-Version": []string{"v24.6.0"},
		"X-Stainless-Os":              []string{"Linux"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(officialReq, auth, "key-baseline-reload", false, nil, nil, oldCfg, nil, true)
	assertClaudeFingerprint(t, officialReq.Header, "claude-cli/2.1.70 (external, cli)", "0.80.0", "v24.5.0", "MacOS", "arm64")

	thirdPartyReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"curl/8.7.1"},
		"X-Stainless-Package-Version": []string{"0.10.0"},
		"X-Stainless-Runtime-Version": []string{"v18.0.0"},
		"X-Stainless-Os":              []string{"Linux"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(thirdPartyReq, auth, "key-baseline-reload", false, nil, nil, newCfg, nil, false)
	assertClaudeFingerprint(t, thirdPartyReq.Header, "claude-cli/2.1.77 (external, cli)", "0.87.0", "v24.8.0", "MacOS", "arm64")
}

func TestApplyClaudeHeaders_LearnsOfficialFingerprintAfterCustomBaselineFallback(t *testing.T) {
	resetClaudeDeviceProfileCache()
	stabilize := true

	cfg := &config.Config{
		ClaudeHeaderDefaults: config.ClaudeHeaderDefaults{
			UserAgent:              "my-gateway/1.0",
			PackageVersion:         "custom-pkg",
			RuntimeVersion:         "custom-runtime",
			OS:                     "MacOS",
			Arch:                   "arm64",
			StabilizeDeviceProfile: &stabilize,
		},
	}
	auth := &cliproxyauth.Auth{
		ID: "auth-custom-baseline-learning",
		Attributes: map[string]string{
			"api_key":    "key-custom-baseline-learning",
			"cloak_mode": "always",
		},
	}

	thirdPartyReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"curl/8.7.1"},
		"X-Stainless-Package-Version": []string{"0.10.0"},
		"X-Stainless-Runtime-Version": []string{"v18.0.0"},
		"X-Stainless-Os":              []string{"Linux"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(thirdPartyReq, auth, "key-custom-baseline-learning", false, nil, nil, cfg, nil, false)
	assertClaudeFingerprint(t, thirdPartyReq.Header, "my-gateway/1.0", "custom-pkg", "custom-runtime", "MacOS", "arm64")

	officialReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"claude-cli/2.1.77 (external, cli)"},
		"X-Stainless-Package-Version": []string{"0.87.0"},
		"X-Stainless-Runtime-Version": []string{"v24.8.0"},
		"X-Stainless-Os":              []string{"Linux"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(officialReq, auth, "key-custom-baseline-learning", false, nil, nil, cfg, nil, true)
	assertClaudeFingerprint(t, officialReq.Header, "my-gateway/1.0", "custom-pkg", "custom-runtime", "MacOS", "arm64")

	postLearningThirdPartyReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"curl/8.7.1"},
		"X-Stainless-Package-Version": []string{"0.10.0"},
		"X-Stainless-Runtime-Version": []string{"v18.0.0"},
		"X-Stainless-Os":              []string{"Linux"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(postLearningThirdPartyReq, auth, "key-custom-baseline-learning", false, nil, nil, cfg, nil, false)
	assertClaudeFingerprint(t, postLearningThirdPartyReq.Header, "my-gateway/1.0", "custom-pkg", "custom-runtime", "MacOS", "arm64")
}

func TestResolveClaudeDeviceProfile_RechecksCacheBeforeStoringCandidate(t *testing.T) {
	resetClaudeDeviceProfileCache()
	stabilize := true

	cfg := &config.Config{
		ClaudeHeaderDefaults: config.ClaudeHeaderDefaults{
			UserAgent:              "claude-cli/2.1.60 (external, cli)",
			PackageVersion:         "0.70.0",
			RuntimeVersion:         "v22.0.0",
			OS:                     "MacOS",
			Arch:                   "arm64",
			StabilizeDeviceProfile: &stabilize,
		},
	}
	auth := &cliproxyauth.Auth{
		ID: "auth-racy-upgrade",
		Attributes: map[string]string{
			"api_key": "key-racy-upgrade",
		},
	}

	lowPaused := make(chan struct{})
	releaseLow := make(chan struct{})
	var pauseOnce sync.Once
	var releaseOnce sync.Once

	helps.ClaudeDeviceProfileBeforeCandidateStore = func(candidate helps.ClaudeDeviceProfile) {
		if candidate.UserAgent != "claude-cli/2.1.60 (external, cli)" {
			return
		}
		pause := false
		pauseOnce.Do(func() {
			pause = true
			close(lowPaused)
		})
		if pause {
			<-releaseLow
		}
	}
	t.Cleanup(func() {
		helps.ClaudeDeviceProfileBeforeCandidateStore = nil
		releaseOnce.Do(func() { close(releaseLow) })
	})

	lowResultCh := make(chan helps.ClaudeDeviceProfile, 1)
	go func() {
		lowResultCh <- helps.ResolveClaudeDeviceProfile(auth, "key-racy-upgrade", http.Header{
			"User-Agent":                  []string{"claude-cli/2.1.60 (external, cli)"},
			"X-Stainless-Package-Version": []string{"0.70.0"},
			"X-Stainless-Runtime-Version": []string{"v22.0.0"},
			"X-Stainless-Os":              []string{"Linux"},
			"X-Stainless-Arch":            []string{"x64"},
		}, cfg)
	}()

	select {
	case <-lowPaused:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for lower candidate to pause before storing")
	}

	highResult := helps.ResolveClaudeDeviceProfile(auth, "key-racy-upgrade", http.Header{
		"User-Agent":                  []string{"claude-cli/2.1.60 (external, cli)"},
		"X-Stainless-Package-Version": []string{"0.70.0"},
		"X-Stainless-Runtime-Version": []string{"v22.0.0"},
		"X-Stainless-Os":              []string{"MacOS"},
		"X-Stainless-Arch":            []string{"arm64"},
	}, cfg)
	releaseOnce.Do(func() { close(releaseLow) })

	select {
	case lowResult := <-lowResultCh:
		if lowResult.UserAgent != "claude-cli/2.1.60 (external, cli)" {
			t.Fatalf("lowResult.UserAgent = %q, want %q", lowResult.UserAgent, "claude-cli/2.1.60 (external, cli)")
		}
		if lowResult.PackageVersion != "0.70.0" {
			t.Fatalf("lowResult.PackageVersion = %q, want %q", lowResult.PackageVersion, "0.70.0")
		}
		if lowResult.OS != "MacOS" || lowResult.Arch != "arm64" {
			t.Fatalf("lowResult platform = %s/%s, want %s/%s", lowResult.OS, lowResult.Arch, "MacOS", "arm64")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for lower candidate result")
	}

	if highResult.UserAgent != "claude-cli/2.1.60 (external, cli)" {
		t.Fatalf("highResult.UserAgent = %q, want %q", highResult.UserAgent, "claude-cli/2.1.60 (external, cli)")
	}
	if highResult.OS != "MacOS" || highResult.Arch != "arm64" {
		t.Fatalf("highResult platform = %s/%s, want %s/%s", highResult.OS, highResult.Arch, "MacOS", "arm64")
	}

	cached := helps.ResolveClaudeDeviceProfile(auth, "key-racy-upgrade", http.Header{
		"User-Agent": []string{"curl/8.7.1"},
	}, cfg)
	if cached.UserAgent != "claude-cli/2.1.60 (external, cli)" {
		t.Fatalf("cached.UserAgent = %q, want %q", cached.UserAgent, "claude-cli/2.1.60 (external, cli)")
	}
	if cached.PackageVersion != "0.70.0" {
		t.Fatalf("cached.PackageVersion = %q, want %q", cached.PackageVersion, "0.70.0")
	}
	if cached.OS != "MacOS" || cached.Arch != "arm64" {
		t.Fatalf("cached platform = %s/%s, want %s/%s", cached.OS, cached.Arch, "MacOS", "arm64")
	}
}

func TestApplyClaudeHeaders_ThirdPartyBaselineThenOfficialUpgradeKeepsPinnedPlatform(t *testing.T) {
	resetClaudeDeviceProfileCache()
	stabilize := true

	cfg := &config.Config{
		ClaudeHeaderDefaults: config.ClaudeHeaderDefaults{
			UserAgent:              "claude-cli/2.1.70 (external, cli)",
			PackageVersion:         "0.80.0",
			RuntimeVersion:         "v24.5.0",
			OS:                     "MacOS",
			Arch:                   "arm64",
			StabilizeDeviceProfile: &stabilize,
		},
	}
	auth := &cliproxyauth.Auth{
		ID: "auth-third-party-then-official",
		Attributes: map[string]string{
			"api_key":    "key-third-party-then-official",
			"cloak_mode": "always",
		},
	}

	thirdPartyReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"curl/8.7.1"},
		"X-Stainless-Package-Version": []string{"0.10.0"},
		"X-Stainless-Runtime-Version": []string{"v18.0.0"},
		"X-Stainless-Os":              []string{"Linux"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(thirdPartyReq, auth, "key-third-party-then-official", false, nil, nil, cfg, nil, false)
	assertClaudeFingerprint(t, thirdPartyReq.Header, "claude-cli/2.1.70 (external, cli)", "0.80.0", "v24.5.0", "MacOS", "arm64")

	officialReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"claude-cli/2.1.77 (external, cli)"},
		"X-Stainless-Package-Version": []string{"0.87.0"},
		"X-Stainless-Runtime-Version": []string{"v24.8.0"},
		"X-Stainless-Os":              []string{"Linux"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(officialReq, auth, "key-third-party-then-official", false, nil, nil, cfg, nil, true)
	assertClaudeFingerprint(t, officialReq.Header, "claude-cli/2.1.70 (external, cli)", "0.80.0", "v24.5.0", "MacOS", "arm64")
}

func TestApplyClaudeHeaders_DisableDeviceProfileStabilization(t *testing.T) {
	resetClaudeDeviceProfileCache()

	stabilize := false
	cfg := &config.Config{
		ClaudeHeaderDefaults: config.ClaudeHeaderDefaults{
			UserAgent:              "claude-cli/2.1.60 (external, cli)",
			PackageVersion:         "0.70.0",
			RuntimeVersion:         "v22.0.0",
			OS:                     "MacOS",
			Arch:                   "arm64",
			StabilizeDeviceProfile: &stabilize,
		},
	}
	auth := &cliproxyauth.Auth{
		ID: "auth-disable-stability",
		Attributes: map[string]string{
			"api_key":    "key-disable-stability",
			"cloak_mode": "always",
		},
	}

	firstReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"claude-cli/2.1.62 (external, cli)"},
		"X-Stainless-Package-Version": []string{"0.74.0"},
		"X-Stainless-Runtime-Version": []string{"v24.3.0"},
		"X-Stainless-Os":              []string{"Linux"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(firstReq, auth, "key-disable-stability", false, nil, nil, cfg, nil, true)
	assertClaudeFingerprint(t, firstReq.Header, "claude-cli/2.1.60 (external, cli)", "0.70.0", "v22.0.0", "MacOS", "arm64")

	thirdPartyReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"lobe-chat/1.0"},
		"X-Stainless-Package-Version": []string{"0.10.0"},
		"X-Stainless-Runtime-Version": []string{"v18.0.0"},
		"X-Stainless-Os":              []string{"Windows"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(thirdPartyReq, auth, "key-disable-stability", false, nil, nil, cfg, nil, false)
	assertClaudeFingerprint(t, thirdPartyReq.Header, "claude-cli/2.1.60 (external, cli)", "0.70.0", "v22.0.0", "MacOS", "arm64")

	lowerReq := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"claude-cli/2.1.61 (external, cli)"},
		"X-Stainless-Package-Version": []string{"0.73.0"},
		"X-Stainless-Runtime-Version": []string{"v24.2.0"},
		"X-Stainless-Os":              []string{"Windows"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(lowerReq, auth, "key-disable-stability", false, nil, nil, cfg, nil, true)
	assertClaudeFingerprint(t, lowerReq.Header, "claude-cli/2.1.60 (external, cli)", "0.70.0", "v22.0.0", "MacOS", "arm64")
}

func TestApplyClaudeHeaders_LegacyModePreservesConfiguredUserAgentOverrideForClaudeClients(t *testing.T) {
	resetClaudeDeviceProfileCache()

	stabilize := false
	cfg := &config.Config{
		ClaudeHeaderDefaults: config.ClaudeHeaderDefaults{
			UserAgent:              "claude-cli/2.1.60 (external, cli)",
			PackageVersion:         "0.70.0",
			RuntimeVersion:         "v22.0.0",
			StabilizeDeviceProfile: &stabilize,
		},
	}
	auth := &cliproxyauth.Auth{
		ID: "auth-legacy-ua-override",
		Attributes: map[string]string{
			"api_key":           "key-legacy-ua-override",
			"header:User-Agent": "config-ua/1.0",
		},
	}

	req := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent":                  []string{"claude-cli/2.1.62 (external, cli)"},
		"X-Stainless-Package-Version": []string{"0.74.0"},
		"X-Stainless-Runtime-Version": []string{"v24.3.0"},
		"X-Stainless-Os":              []string{"Linux"},
		"X-Stainless-Arch":            []string{"x64"},
	})
	applyClaudeHeaders(req, auth, "key-legacy-ua-override", false, nil, nil, cfg, nil, true)

	assertClaudeFingerprint(t, req.Header, "config-ua/1.0", "0.70.0", "v22.0.0", "MacOS", "arm64")
}

func TestApplyClaudeHeaders_LegacyThirdPartyUsesStableConfiguredOSArch(t *testing.T) {
	resetClaudeDeviceProfileCache()

	stabilize := false
	cfg := &config.Config{
		ClaudeHeaderDefaults: config.ClaudeHeaderDefaults{
			UserAgent:              "claude-cli/2.1.60 (external, cli)",
			PackageVersion:         "0.70.0",
			RuntimeVersion:         "v22.0.0",
			OS:                     "Windows",
			Arch:                   "x64",
			StabilizeDeviceProfile: &stabilize,
		},
	}
	auth := &cliproxyauth.Auth{
		ID: "auth-legacy-runtime-os-arch",
		Attributes: map[string]string{
			"api_key":    "key-legacy-runtime-os-arch",
			"cloak_mode": "always",
		},
	}

	req := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent": []string{"curl/8.7.1"},
	})
	applyClaudeHeaders(req, auth, "key-legacy-runtime-os-arch", false, nil, nil, cfg, nil, false)

	assertClaudeFingerprint(t, req.Header, "claude-cli/2.1.60 (external, cli)", "0.70.0", "v22.0.0", "Windows", "x64")
}

func TestApplyClaudeHeaders_UnsetStabilizationUsesStableConfiguredOSArch(t *testing.T) {
	resetClaudeDeviceProfileCache()

	cfg := &config.Config{
		ClaudeHeaderDefaults: config.ClaudeHeaderDefaults{
			UserAgent:      "claude-cli/2.1.60 (external, cli)",
			PackageVersion: "0.70.0",
			RuntimeVersion: "v22.0.0",
			OS:             "Linux",
			Arch:           "x64",
		},
	}
	auth := &cliproxyauth.Auth{
		ID: "auth-unset-runtime-os-arch",
		Attributes: map[string]string{
			"api_key":    "key-unset-runtime-os-arch",
			"cloak_mode": "always",
		},
	}

	req := newClaudeHeaderTestRequest(t, http.Header{
		"User-Agent": []string{"curl/8.7.1"},
	})
	applyClaudeHeaders(req, auth, "key-unset-runtime-os-arch", false, nil, nil, cfg, nil, false)

	assertClaudeFingerprint(t, req.Header, "claude-cli/2.1.60 (external, cli)", "0.70.0", "v22.0.0", "Linux", "x64")
}

func TestApplyClaudeHeaders_UsesOAuthAuthorizationAndBrowserFingerprint(t *testing.T) {
	auth := &cliproxyauth.Auth{Attributes: map[string]string{"api_key": "sk-ant-oat-header-test"}}
	req := newClaudeHeaderTestRequest(t, nil)
	if errHeaders := applyClaudeHeaders(req, auth, "sk-ant-oat-header-test", false, nil, nil, &config.Config{}, nil, false, "11111111-2222-4333-8444-555555555555"); errHeaders != nil {
		t.Fatalf("applyClaudeHeaders() error = %v", errHeaders)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer sk-ant-oat-header-test" {
		t.Fatalf("Authorization = %q, want OAuth bearer", got)
	}
	if got := req.Header.Get("x-api-key"); got != "" {
		t.Fatalf("x-api-key = %q, want empty for OAuth", got)
	}
	if got := req.Header.Get("Anthropic-Dangerous-Direct-Browser-Access"); got != "true" {
		t.Fatalf("Anthropic-Dangerous-Direct-Browser-Access = %q, want true", got)
	}
	if got := req.Header.Get("Anthropic-Beta"); !strings.Contains(got, "oauth-2025-04-20") {
		t.Fatalf("Anthropic-Beta = %q, want OAuth beta", got)
	}
}

func TestApplyClaudeHeaders_EmptyAPIKey_OmitsAuthHeaders(t *testing.T) {
	auth := &cliproxyauth.Auth{
		Provider: "claude",
		Attributes: map[string]string{
			"auth_kind":           "apikey",
			"base_url":            "https://custom-claude.example.com",
			"header:Custom-Token": "custom-secret",
		},
	}
	req, err := http.NewRequest(http.MethodPost, "https://custom-claude.example.com/v1/messages", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	// Preset preexisting client headers to ensure they get stripped for empty API key
	req.Header.Set("Authorization", "Bearer preexisting-bearer")
	req.Header.Set("x-api-key", "preexisting-key")

	if errHeaders := applyClaudeHeaders(req, auth, "", false, nil, nil, &config.Config{}, nil, false); errHeaders != nil {
		t.Fatalf("applyClaudeHeaders() error = %v", errHeaders)
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Fatalf("Authorization = %q, want empty for empty API key", got)
	}
	if got := req.Header.Get("x-api-key"); got != "" {
		t.Fatalf("x-api-key = %q, want empty for empty API key", got)
	}
	if got := req.Header.Get("Custom-Token"); got != "custom-secret" {
		t.Fatalf("Custom-Token = %q, want custom-secret", got)
	}

	// Also verify PrepareRequest
	req2, _ := http.NewRequest(http.MethodPost, "https://custom-claude.example.com/v1/messages", nil)
	req2.Header.Set("Authorization", "Bearer preexisting-bearer")
	req2.Header.Set("x-api-key", "preexisting-key")
	exec := &ClaudeExecutor{}
	if errPrep := exec.PrepareRequest(req2, auth); errPrep != nil {
		t.Fatalf("PrepareRequest() error = %v", errPrep)
	}
	if got := req2.Header.Get("Authorization"); got != "" {
		t.Fatalf("PrepareRequest Authorization = %q, want empty", got)
	}
	if got := req2.Header.Get("x-api-key"); got != "" {
		t.Fatalf("PrepareRequest x-api-key = %q, want empty", got)
	}
	if got := req2.Header.Get("Custom-Token"); got != "custom-secret" {
		t.Fatalf("PrepareRequest Custom-Token = %q, want custom-secret", got)
	}
}

func TestClaudeExecutor_NonClaudeRequestUsesClaudeCode220CLIFingerprint(t *testing.T) {
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
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":    "key-sdk-fingerprint",
		"base_url":   server.URL,
		"cloak_mode": "always",
	}}
	payload := []byte(`{"model":"claude-opus-4-6","messages":[{"role":"user","content":[{"type":"text","text":"x"}]}]}`)

	_, errExecute := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-opus-4-6",
		Payload: payload,
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatClaude})
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}

	assertClaudeFingerprint(t, seenHeaders, "claude-cli/2.1.258 (external, cli)", "0.112.1", "v26.3.0", "MacOS", "arm64")
	if got := seenHeaders.Get("X-App"); got != "cli" {
		t.Fatalf("X-App = %q, want cli", got)
	}
	if want := claudeCodeCLIBetas(payload, nil, false); seenHeaders.Get("Anthropic-Beta") != want {
		t.Fatalf("Anthropic-Beta = %q, want %q", seenHeaders.Get("Anthropic-Beta"), want)
	}

	system := gjson.GetBytes(seenBody, "system").Array()
	if len(system) != 2 {
		t.Fatalf("system block count = %d, want 2: %s", len(system), seenBody)
	}
	if got := system[0].Get("text").String(); got != "x-anthropic-billing-header: cc_version=2.1.258.1e2; cc_entrypoint=cli;" {
		t.Fatalf("billing header = %q, want 2.1.258 CLI fingerprint", got)
	}
	if got := system[1].Get("text").String(); got != claudeCodeCLIIdentity {
		t.Fatalf("system[1].text = %q, want official CLI identity", got)
	}
	if got := system[1].Get("cache_control.type").String(); got != "ephemeral" {
		t.Fatalf("system[1].cache_control.type = %q, want ephemeral", got)
	}
	// This credential is an API key, and native only selects the 1h cache pool for
	// OAuth. The body ttl therefore has to stay absent, matching the fact that
	// claudeCodeCLIBetas does not emit extended-cache-ttl-2025-04-11 here either.
	if system[1].Get("cache_control.ttl").Exists() {
		t.Fatalf("API-key request must not carry a 1h body ttl: %s", system[1].Raw)
	}
	if betas := seenHeaders.Get("Anthropic-Beta"); strings.Contains(betas, claudeExtendedCacheTTLBeta) {
		t.Fatalf("API-key request must not declare extended-cache-ttl: %s", betas)
	}
	content := gjson.GetBytes(seenBody, "messages.0.content").Array()
	if len(content) != 2 {
		t.Fatalf("messages[0].content has %d blocks, want currentDate and user text", len(content))
	}
	assertClaudeCodeCurrentDateBlock(t, content[0])
	assertEphemeralUserTextBlock(t, content[1], "x", "")

	userID := gjson.GetBytes(seenBody, "metadata.user_id").String()
	if !helps.IsValidUserID(userID) {
		t.Fatalf("metadata.user_id = %q, want Claude Code JSON shape", userID)
	}
	if got, want := gjson.Get(userID, "session_id").String(), seenHeaders.Get("X-Claude-Code-Session-Id"); got != want {
		t.Fatalf("metadata session_id = %q, header session ID = %q", got, want)
	}
}

func TestClaudeExecutor_ConfirmedClaudeCodeRequestPreservesInteractiveIdentity(t *testing.T) {
	var seenBody []byte
	var seenHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		seenHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-opus-4-6","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer server.Close()

	const sessionID = "11111111-2222-4333-8444-555555555555"
	const userID = `{"device_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","account_uuid":"","session_id":"11111111-2222-4333-8444-555555555555"}`
	payload := []byte(`{"model":"claude-opus-4-6","system":[{"type":"text","text":"interactive-system","cache_control":{"type":"ephemeral"}}],"messages":[{"role":"user","content":"x"}],"metadata":{"user_id":` + fmt.Sprintf("%q", userID) + `}}`)
	incoming := http.Header{
		"User-Agent":                  {"claude-cli/2.1.258 (external, cli)"},
		"X-App":                       {"cli"},
		"Anthropic-Beta":              {"claude-code-20250219,interleaved-thinking-2025-05-14,redact-thinking-2026-02-12,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,effort-2025-11-24"},
		"X-Claude-Code-Session-Id":    {sessionID},
		"X-Stainless-Package-Version": {"0.112.1"},
		"X-Stainless-Runtime-Version": {"v26.3.0"},
		"X-Stainless-Os":              {"MacOS"},
		"X-Stainless-Arch":            {"arm64"},
	}
	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":  "key-confirmed-client",
		"base_url": server.URL,
	}}

	_, errExecute := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-opus-4-6",
		Payload: payload,
	}, cliproxyexecutor.Options{
		SourceFormat:    sdktranslator.FormatClaude,
		OriginalRequest: payload,
		Headers:         incoming,
	})
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}

	assertClaudeFingerprint(t, seenHeaders, "claude-cli/2.1.258 (external, cli)", "0.112.1", "v26.3.0", "MacOS", "arm64")
	if got := gjson.GetBytes(seenBody, "system.0.text").String(); got != "interactive-system" {
		t.Fatalf("system.0.text = %q, want confirmed client system preserved", got)
	}
	if got := gjson.GetBytes(seenBody, "system.#").Int(); got != 1 {
		t.Fatalf("system block count = %d, want 1", got)
	}
	if got := gjson.GetBytes(seenBody, "metadata.user_id").String(); got != userID {
		t.Fatalf("metadata.user_id = %q, want preserved %q", got, userID)
	}
	if got := seenHeaders.Get("Anthropic-Beta"); got != incoming.Get("Anthropic-Beta") {
		t.Fatalf("Anthropic-Beta = %q, want preserved %q", got, incoming.Get("Anthropic-Beta"))
	}
}

func TestClaudeExecutor_ConfirmedClaudeCodeWithoutCacheControlPreservesContent(t *testing.T) {
	tests := []struct {
		name   string
		stream bool
	}{
		{name: "non-stream"},
		{name: "stream", stream: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var seenBody []byte
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seenBody, _ = io.ReadAll(r.Body)
				if tt.stream {
					w.Header().Set("Content-Type", "text/event-stream")
					_, _ = w.Write([]byte("event: message_stop\n" + `data: {"type":"message_stop"}` + "\n\n"))
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-opus-4-6","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
			}))
			defer server.Close()

			const sessionID = "11111111-2222-4333-8444-555555555555"
			const userID = `{"device_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","account_uuid":"","session_id":"11111111-2222-4333-8444-555555555555"}`
			payload := []byte(`{"model":"claude-opus-4-6","messages":[{"role":"user","content":"x"}],"metadata":{"user_id":` + fmt.Sprintf("%q", userID) + `}}`)
			incoming := http.Header{
				"User-Agent":               {"claude-cli/2.1.258 (external, cli)"},
				"X-App":                    {"cli"},
				"Anthropic-Beta":           {"claude-code-20250219"},
				"X-Claude-Code-Session-Id": {sessionID},
			}
			executor := NewClaudeExecutor(&config.Config{})
			auth := &cliproxyauth.Auth{Attributes: map[string]string{
				"api_key":  "key-confirmed-markerless",
				"base_url": server.URL,
			}}
			req := cliproxyexecutor.Request{Model: "claude-opus-4-6", Payload: payload}
			opts := cliproxyexecutor.Options{
				Stream:          tt.stream,
				SourceFormat:    sdktranslator.FormatClaude,
				OriginalRequest: payload,
				Headers:         incoming,
			}

			if tt.stream {
				result, errStream := executor.ExecuteStream(context.Background(), auth, req, opts)
				if errStream != nil {
					t.Fatalf("ExecuteStream() error = %v", errStream)
				}
				for chunk := range result.Chunks {
					if chunk.Err != nil {
						t.Fatalf("stream chunk error = %v", chunk.Err)
					}
				}
			} else if _, errExecute := executor.Execute(context.Background(), auth, req, opts); errExecute != nil {
				t.Fatalf("Execute() error = %v", errExecute)
			}

			content := gjson.GetBytes(seenBody, "messages.0.content")
			if content.Type != gjson.String || content.String() != "x" {
				t.Fatalf("messages.0.content = %s, want native string content preserved; body=%s", content.Raw, seenBody)
			}
			if gjson.GetBytes(seenBody, "messages.0.content.0.cache_control").Exists() {
				t.Fatalf("confirmed markerless native request received synthetic cache_control: %s", seenBody)
			}
		})
	}
}

func TestClaudeExecutor_ConfirmedVSCodeAgentSDKRequestPreservesIdentity(t *testing.T) {
	helps.ResetClaudeDeviceProfileCache()
	var seenBody []byte
	var seenHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		seenHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-opus-4-6","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer server.Close()

	const sessionID = "22222222-3333-4444-8555-666666666666"
	const userID = `{"device_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","account_uuid":"","session_id":"22222222-3333-4444-8555-666666666666"}`
	const vscodeUA = "claude-cli/2.1.258 (external, claude-vscode, agent-sdk/0.3.220)"
	const billingHeader = "x-anthropic-billing-header: cc_version=2.1.258.9cb; cc_entrypoint=claude-vscode;"
	payload := []byte(`{"model":"claude-opus-4-6","system":[{"type":"text","text":` + fmt.Sprintf("%q", billingHeader) + `},{"type":"text","text":"You are a Claude agent, built on Anthropic's Claude Agent SDK.","cache_control":{"type":"ephemeral","ttl":"1h"}},{"type":"text","text":"vscode-agent-system"}],"messages":[{"role":"user","content":"x"}],"metadata":{"user_id":` + fmt.Sprintf("%q", userID) + `}}`)
	incoming := http.Header{
		"User-Agent":     {vscodeUA},
		"X-App":          {"cli"},
		"Anthropic-Beta": {"claude-code-20250219,interleaved-thinking-2025-05-14"},
		"Anthropic-Dangerous-Direct-Browser-Access": {"true"},
		"X-Claude-Code-Session-Id":                  {sessionID},
		"X-Stainless-Package-Version":               {"0.112.1"},
		"X-Stainless-Runtime-Version":               {"v26.3.0"},
		"X-Stainless-Os":                            {"MacOS"},
		"X-Stainless-Arch":                          {"arm64"},
	}
	stabilize := true
	executor := NewClaudeExecutor(&config.Config{ClaudeHeaderDefaults: config.ClaudeHeaderDefaults{StabilizeDeviceProfile: &stabilize}})
	auth := &cliproxyauth.Auth{ID: "auth-vscode-agent-sdk", Attributes: map[string]string{
		"api_key":  "key-vscode-agent-sdk",
		"base_url": server.URL,
	}}

	_, errExecute := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-opus-4-6",
		Payload: payload,
	}, cliproxyexecutor.Options{
		SourceFormat:    sdktranslator.FormatClaude,
		OriginalRequest: payload,
		Headers:         incoming,
	})
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}

	assertClaudeFingerprint(t, seenHeaders, vscodeUA, "0.112.1", "v26.3.0", "MacOS", "arm64")
	if got := seenHeaders.Get("Anthropic-Dangerous-Direct-Browser-Access"); got != "true" {
		t.Fatalf("Anthropic-Dangerous-Direct-Browser-Access = %q, want preserved true", got)
	}
	if got := seenHeaders.Get("X-Claude-Code-Session-Id"); got != sessionID {
		t.Fatalf("X-Claude-Code-Session-Id = %q, want preserved %q", got, sessionID)
	}
	if got := gjson.GetBytes(seenBody, "system.0.text").String(); got != billingHeader {
		t.Fatalf("system.0.text = %q, want VSCode attribution preserved", got)
	}
	if got := gjson.GetBytes(seenBody, "system.1.text").String(); got != "You are a Claude agent, built on Anthropic's Claude Agent SDK." {
		t.Fatalf("system.1.text = %q, want VSCode Agent SDK identity preserved", got)
	}
	if got := gjson.GetBytes(seenBody, "system.1.cache_control.ttl").String(); got != "1h" {
		t.Fatalf("system.1.cache_control.ttl = %q, want preserved 1h", got)
	}
	if got := gjson.GetBytes(seenBody, "system.2.text").String(); got != "vscode-agent-system" {
		t.Fatalf("system.2.text = %q, want VSCode Agent SDK system preserved", got)
	}
	if got := gjson.GetBytes(seenBody, "system.#").Int(); got != 3 {
		t.Fatalf("system block count = %d, want 3", got)
	}
	if got := gjson.GetBytes(seenBody, "metadata.user_id").String(); got != userID {
		t.Fatalf("metadata.user_id = %q, want preserved %q", got, userID)
	}
}

func TestClaudeExecutor_CopiedVSCodeAgentSDKHeadersWithoutMetadataAreCloaked(t *testing.T) {
	var seenBody []byte
	var seenHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		seenHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-opus-4-6","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer server.Close()

	payload := []byte(`{"model":"claude-opus-5","system":"spoofed-system","messages":[{"role":"user","content":"x"}]}`)
	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":    "key-spoofed-client",
		"base_url":   server.URL,
		"cloak_mode": "always",
	}}
	_, errExecute := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-opus-5",
		Payload: payload,
	}, cliproxyexecutor.Options{
		SourceFormat:    sdktranslator.FormatClaude,
		OriginalRequest: payload,
		Headers: http.Header{
			"User-Agent":     {"claude-cli/2.1.258 (external, claude-vscode, agent-sdk/0.3.220)"},
			"X-App":          {"cli"},
			"Anthropic-Beta": {"claude-code-20250219"},
		},
	})
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}

	if got := seenHeaders.Get("User-Agent"); got != "claude-cli/2.1.258 (external, cli)" {
		t.Fatalf("User-Agent = %q, want CLI cloak", got)
	}
	if got := gjson.GetBytes(seenBody, "system.#").Int(); got != 2 {
		t.Fatalf("system block count = %d, want billing and CLI identity only", got)
	}
	content := gjson.GetBytes(seenBody, "messages.0.content").Array()
	if len(content) != 2 {
		t.Fatalf("messages[0].content has %d blocks, want currentDate and user text", len(content))
	}
	assertClaudeCodeCurrentDateBlock(t, content[0])
	assertEphemeralUserTextBlock(t, content[1], "x", "")
	assertClaudeMidConversationSystemMessage(t, seenBody, 1, "spoofed-system", "")
}

func TestClaudeExecutor_AgentSDKEntrypointWithStrongSignalsUsesCLICloak(t *testing.T) {
	var seenBody []byte
	var seenHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		seenHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-opus-4-6","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer server.Close()

	payload := []byte(`{"model":"claude-opus-4-6","system":"agent-sdk-system","messages":[{"role":"user","content":"x"}],"metadata":{"user_id":"agent-sdk-user"}}`)
	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"api_key":    "key-agent-sdk-client",
		"base_url":   server.URL,
		"cloak_mode": "always",
	}}
	_, errExecute := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-opus-4-6",
		Payload: payload,
	}, cliproxyexecutor.Options{
		SourceFormat:    sdktranslator.FormatClaude,
		OriginalRequest: payload,
		Headers: http.Header{
			"User-Agent":     {"claude-cli/2.1.258 (external, sdk-ts, agent-sdk/0.3.220)"},
			"X-App":          {"cli"},
			"Anthropic-Beta": {"claude-code-20250219"},
		},
	})
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}

	if got := seenHeaders.Get("User-Agent"); got != "claude-cli/2.1.258 (external, cli)" {
		t.Fatalf("User-Agent = %q, want CLI cloak", got)
	}
	if got := gjson.GetBytes(seenBody, "system.0.text").String(); !strings.Contains(got, "cc_entrypoint=cli;") {
		t.Fatalf("billing attribution = %q, want cli", got)
	}
	if got := gjson.GetBytes(seenBody, "system.1.text").String(); got != claudeCodeCLIIdentity {
		t.Fatalf("system.1.text = %q, want official CLI identity", got)
	}
}

func TestClaudeExecutor_ConfirmedVSCodeOAuthPreservesToolNames(t *testing.T) {
	var seenBody []byte
	var seenHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBody, _ = io.ReadAll(r.Body)
		seenHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","model":"claude-opus-4-6","role":"assistant","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer server.Close()

	const userID = `{"device_id":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","account_uuid":"","session_id":"33333333-4444-4555-8666-777777777777"}`
	payload := []byte(`{"model":"claude-opus-4-6","system":[{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.258.9cb; cc_entrypoint=claude-vscode; cch=00000;"}],"tools":[{"name":"bash","description":"known native name must pass through","input_schema":{"type":"object"}},{"name":"search_web","description":"unknown native name must pass through","input_schema":{"type":"object"}}],"messages":[{"role":"user","content":"x"}],"metadata":{"user_id":` + fmt.Sprintf("%q", userID) + `}}`)
	deviceIDs := []string{
		"0000000000000000000000000000000000000000000000000000000000000000",
	}
	executor := NewClaudeExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{
		Attributes: map[string]string{
			"api_key":  "sk-ant-oat-native-vscode",
			"base_url": server.URL,
		},
		Metadata: map[string]any{
			"account_uuid":      "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
			"claude_device_ids": deviceIDs,
			"cloak_mode":        "always",
		},
	}
	_, errExecute := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "claude-opus-4-6",
		Payload: payload,
	}, cliproxyexecutor.Options{
		SourceFormat:    sdktranslator.FormatClaude,
		OriginalRequest: payload,
		Headers: http.Header{
			"User-Agent":                  {"claude-cli/2.1.258 (external, claude-vscode, agent-sdk/0.3.220)"},
			"X-App":                       {"cli"},
			"Anthropic-Beta":              {"claude-code-20250219"},
			"X-Stainless-Package-Version": {"0.112.1"},
			"X-Stainless-Runtime-Version": {"v26.3.0"},
		},
	})
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}

	if got := gjson.GetBytes(seenBody, "tools.0.name").String(); got != "bash" {
		t.Fatalf("tools.0.name = %q, want confirmed native known name preserved", got)
	}
	if got := gjson.GetBytes(seenBody, "tools.1.name").String(); got != "search_web" {
		t.Fatalf("tools.1.name = %q, want confirmed native unknown name preserved", got)
	}
	assertClaudeCredentialIdentity(t, seenBody, seenHeaders, deviceIDs, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	upstreamUserID := gjson.GetBytes(seenBody, "metadata.user_id").String()
	if upstreamDeviceID := gjson.Get(upstreamUserID, "device_id").String(); upstreamDeviceID == strings.Repeat("c", 64) {
		t.Fatalf("device_id = %q, want native device replaced by credential pool", upstreamDeviceID)
	}
	if got := gjson.Get(upstreamUserID, "session_id").String(); got != "33333333-4444-4555-8666-777777777777" {
		t.Fatalf("session_id = %q, want downstream agent session", got)
	}
	if got := seenHeaders.Get("X-Claude-Code-Session-Id"); got != "33333333-4444-4555-8666-777777777777" {
		t.Fatalf("X-Claude-Code-Session-Id = %q, want downstream agent session", got)
	}
}

func TestClaudeDeviceProfileStabilizationEnabled_DefaultFalse(t *testing.T) {
	if helps.ClaudeDeviceProfileStabilizationEnabled(nil) {
		t.Fatal("expected nil config to default to disabled stabilization")
	}
	if helps.ClaudeDeviceProfileStabilizationEnabled(&config.Config{}) {
		t.Fatal("expected unset stabilize-device-profile to default to disabled stabilization")
	}
}
