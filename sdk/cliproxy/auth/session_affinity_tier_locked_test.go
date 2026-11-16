package auth

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// Tier-locked affinity keeps a session on one credential, but only within the highest available
// priority tier: priority encodes spending order (prepaid API keys before subscriptions), so a
// binding must never hold a session below a tier that has become available again.
func TestManagerSessionAffinityTierLocked(t *testing.T) {
	for _, testCase := range []struct {
		name           string
		providerSuffix string
		pick           func(*Manager, context.Context, string, string, cliproxyexecutor.Options) (*Auth, error)
	}{
		{
			name:           "single provider",
			providerSuffix: "single",
			pick: func(manager *Manager, ctx context.Context, provider, model string, opts cliproxyexecutor.Options) (*Auth, error) {
				auth, _, errPick := manager.pickNext(ctx, provider, model, opts, nil)
				return auth, errPick
			},
		},
		{
			name:           "mixed provider",
			providerSuffix: "mixed",
			pick: func(manager *Manager, ctx context.Context, provider, model string, opts cliproxyexecutor.Options) (*Auth, error) {
				auth, _, _, errPick := manager.pickNextMixed(ctx, []string{provider}, model, opts, nil)
				return auth, errPick
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			ctx := context.Background()
			provider := "tier-locked-" + testCase.providerSuffix
			model := "tier-locked-model"
			keyA, keyB, sub := provider+"-key-a", provider+"-key-b", provider+"-sub"

			manager := NewManager(nil, nil, nil)
			affinity := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
				Fallback:   &WeightedRoundRobinSelector{},
				TTL:        time.Hour,
				TierLocked: true,
				// Ignored when tier-locked: a stale binding must never refuse failover.
				RebindOn: SessionAffinityRebindOnNever,
			})
			defer affinity.Stop()
			manager.SetSelector(affinity)
			manager.RegisterExecutor(schedulerTestExecutor{provider: provider})

			for _, auth := range []*Auth{
				{ID: keyA, Provider: provider, Status: StatusActive, Attributes: map[string]string{"priority": "10"}},
				{ID: keyB, Provider: provider, Status: StatusActive, Attributes: map[string]string{"priority": "10"}},
				{ID: sub, Provider: provider, Status: StatusActive, Attributes: map[string]string{"priority": "0"}},
			} {
				if _, errRegister := manager.Register(WithSkipPersist(ctx), auth); errRegister != nil {
					t.Fatalf("Register(%s): %v", auth.ID, errRegister)
				}
				registry.GetGlobalRegistry().RegisterClient(auth.ID, provider, []*registry.ModelInfo{{ID: model}})
				t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(auth.ID) })
			}

			session := func(id string) cliproxyexecutor.Options {
				headers := http.Header{}
				headers.Set("X-Session-ID", id)
				return cliproxyexecutor.Options{Headers: headers, Metadata: map[string]any{}}
			}
			pick := func(label string, opts cliproxyexecutor.Options) *Auth {
				t.Helper()
				auth, errPick := testCase.pick(manager, ctx, provider, model, opts)
				if errPick != nil {
					t.Fatalf("%s: pick: %v", label, errPick)
				}
				if auth == nil {
					t.Fatalf("%s: pick returned nil auth", label)
				}
				return auth
			}
			coolDown := func(authID string) {
				manager.MarkResult(ctx, Result{
					AuthID: authID, Provider: provider, Model: model, Success: false,
					Error: &Error{HTTPStatus: http.StatusTooManyRequests, Message: "quota"},
				})
			}

			// Sticky within the tier: weighted round robin alone would alternate keyA and keyB.
			first := pick("cold binding", session("s1"))
			if first.ID != keyA && first.ID != keyB {
				t.Fatalf("cold binding = %q, want a priority-10 key", first.ID)
			}
			for i := 0; i < 4; i++ {
				if got := pick("repeat", session("s1")); got.ID != first.ID {
					t.Fatalf("repeat %d = %q, want sticky %q", i, got.ID, first.ID)
				}
			}
			other := keyA
			if first.ID == keyA {
				other = keyB
			}

			// Cooldown fails over within the tier, not down to the subscription.
			coolDown(first.ID)
			if got := pick("failover within tier", session("s1")); got.ID != other {
				t.Fatalf("failover = %q, want same-tier %q", got.ID, other)
			}
			if got := pick("rebound after failover", session("s1")); got.ID != other {
				t.Fatalf("after failover = %q, want rebound %q", got.ID, other)
			}

			// The whole tier cools down: fall to the next tier and stick there.
			coolDown(other)
			if got := pick("next tier", session("s1")); got.ID != sub {
				t.Fatalf("tier exhausted = %q, want %q", got.ID, sub)
			}
			if got := pick("next tier repeat", session("s1")); got.ID != sub {
				t.Fatalf("tier exhausted repeat = %q, want %q", got.ID, sub)
			}

			// A recovered higher tier reclaims the session on its next request.
			expireSessionAffinityPriorityModelCooldown(t, manager, keyA, model)
			if got := pick("tier recovery", session("s1")); got.ID != keyA {
				t.Fatalf("after higher tier recovered = %q, want %q", got.ID, keyA)
			}
			if got := pick("tier recovery repeat", session("s1")); got.ID != keyA {
				t.Fatalf("after higher tier recovered repeat = %q, want sticky %q", got.ID, keyA)
			}
		})
	}
}

func TestSessionAffinityTierLockedIgnoresRebindNever(t *testing.T) {
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback:   &RoundRobinSelector{},
		TierLocked: true,
		RebindOn:   SessionAffinityRebindOnNever,
	})
	defer selector.Stop()
	if !selector.tierLocked || selector.rebindOnNever || selector.rebindOnQuotaOnly {
		t.Fatalf("tier-locked selector = {tierLocked:%v never:%v quota:%v}, want tier-locked with rebind any",
			selector.tierLocked, selector.rebindOnNever, selector.rebindOnQuotaOnly)
	}
}
