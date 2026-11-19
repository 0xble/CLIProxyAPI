package claude

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

type trafficHandlerClock struct {
	now    time.Time
	waited time.Duration
}

func (c *trafficHandlerClock) Now() time.Time { return c.now }
func (c *trafficHandlerClock) Wait(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.now = c.now.Add(d)
	c.waited += d
	return nil
}

func TestTrafficShapingBackgroundHTTPDeferral(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		for _, upstreamFailure := range []bool{false, true} {
			name := "nonstream"
			if streaming {
				name = "stream"
			}
			if upstreamFailure {
				name += "_after_upstream_error"
			}
			t.Run(name, func(t *testing.T) {
				const classHeader = "X-Hermes-Request-Class"
				model := "claude-traffic-http-" + name
				shapedID, failingID := model+"-shaped", model+"-failing"
				selector := coreauth.NewSessionAffinitySelectorWithConfig(coreauth.SessionAffinityConfig{Fallback: &coreauth.FillFirstSelector{}, RebindOn: "never"})
				defer selector.Stop()
				manager := coreauth.NewManager(nil, selector, nil)
				clock := &trafficHandlerClock{now: time.Now()}
				manager.SetContinuityClockForTest(clock)
				var shapedCalls, failingCalls int
				upstreamErr := &issue7521UpstreamError{status: http.StatusBadGateway, body: "earlier upstream failure"}
				attempt := func(a *coreauth.Auth, opts coreexecutor.Options) error {
					if opts.Headers.Get(classHeader) != "" {
						t.Error("request-class hint forwarded to upstream")
					}
					if a.ID == failingID {
						failingCalls++
						return upstreamErr
					}
					shapedCalls++
					return nil
				}
				manager.RegisterExecutor(&issue7521ClaudeExecutor{
					executeFn: func(_ context.Context, a *coreauth.Auth, _ coreexecutor.Request, opts coreexecutor.Options) (coreexecutor.Response, error) {
						return coreexecutor.Response{Payload: []byte(`{"ok":true}`)}, attempt(a, opts)
					},
					streamFn: func(_ context.Context, a *coreauth.Auth, _ coreexecutor.Request, opts coreexecutor.Options) (*coreexecutor.StreamResult, error) {
						return nil, attempt(a, opts)
					},
				})
				register := func(a *coreauth.Auth) {
					t.Helper()
					if _, err := manager.Register(context.Background(), a); err != nil {
						t.Fatal(err)
					}
					registry.GetGlobalRegistry().RegisterClient(a.ID, "claude", []*registry.ModelInfo{{ID: model}})
					t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(a.ID) })
				}
				register(&coreauth.Auth{ID: shapedID, Provider: "claude", Status: coreauth.StatusActive, Metadata: map[string]any{
					coreauth.MetadataQuotaGuard: map[string]any{"reserve_percent": 15, "reset_window": "24h", "final_reserve_percent": 5,
						"traffic_shaping": map[string]any{"requests_per_hour": 1}},
				}})
				if _, err := manager.Execute(context.Background(), []string{"claude"}, coreexecutor.Request{Model: model}, coreexecutor.Options{}); err != nil || shapedCalls != 1 {
					t.Fatalf("failed to seed hourly cap: calls=%d err=%v", shapedCalls, err)
				}
				if upstreamFailure {
					register(&coreauth.Auth{ID: failingID, Provider: "claude", Status: coreauth.StatusActive})
				}
				handler := NewClaudeCodeAPIHandler(handlers.NewBaseAPIHandlers(&sdkconfig.SDKConfig{}, manager))
				router := gin.New()
				router.POST("/v1/messages", handler.ClaudeMessages)
				body := `{"model":"` + model + `","messages":[{"role":"user","content":"hi"}],"stream":` + strconv.FormatBool(streaming) + `}`
				req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set(classHeader, "background")
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, req)
				if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") != "3540" || !strings.Contains(rec.Body.String(), "background request deferred") {
					t.Fatalf("want 503 with policy Retry-After; got %d, headers %v, body %s", rec.Code, rec.Header(), rec.Body.String())
				}
				wantFailingCalls := 0
				if upstreamFailure {
					wantFailingCalls = 1
				}
				if clock.waited != time.Minute || shapedCalls != 1 || failingCalls != wantFailingCalls {
					t.Fatalf("wrong defer path: waited %s, shaped calls %d, failing calls %d (want %d)", clock.waited, shapedCalls, failingCalls, wantFailingCalls)
				}
			})
		}
	}
}
