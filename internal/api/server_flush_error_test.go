package api

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/api/middleware"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/httpwire"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
)

type unconsumedBodyFlushErrorWriter struct {
	*httptest.ResponseRecorder
	flushes int
}

func (w *unconsumedBodyFlushErrorWriter) FlushError() error {
	w.flushes++
	return io.ErrClosedPipe
}

func TestServerUnconsumedBodyFlushError(t *testing.T) {
	for _, encoding := range []string{"identity", "gzip", "zstd"} {
		t.Run(encoding, func(t *testing.T) {
			cfg := &config.Config{}
			enabled := true
			cfg.ServerResponseCompression.Enabled = &enabled
			cfg.ServerResponseCompression.MinBytes = 1
			var sawLoggingWrapper bool
			server := newTestServerWithConfig(t, cfg,
				WithRequestLoggerFactory(func(*config.Config, string) logging.RequestLogger {
					return logging.NewFileRequestLogger(false, t.TempDir(), t.TempDir(), 1)
				}),
				WithMiddleware(func(c *gin.Context) {
					c.Next()
					_, sawLoggingWrapper = c.Writer.(*middleware.ResponseWriterWrapper)
				}),
			)
			called := false
			server.engine.POST("/flush-transport-error", func(c *gin.Context) {
				called = true
				c.Header("Content-Type", "text/event-stream")
				if _, errWrite := c.Writer.WriteString("data: test\n\n"); errWrite != nil {
					t.Fatalf("write before flush: %v", errWrite)
				}
				if errFlush := httpwire.FlushResponse(c.Writer); !errors.Is(errFlush, io.ErrClosedPipe) {
					t.Errorf("full-chain flush error = %v, want closed pipe", errFlush)
				}
			})
			// A nonempty unread body activates both unconsumed-body wrappers.
			request := httptest.NewRequest(http.MethodPost, "/flush-transport-error", strings.NewReader("unread"))
			request.Header.Set("Accept-Encoding", encoding)
			writer := &unconsumedBodyFlushErrorWriter{ResponseRecorder: httptest.NewRecorder()}
			server.server.Handler.ServeHTTP(writer, request)
			if !called || !sawLoggingWrapper {
				t.Fatalf("full server middleware chain not exercised: handler=%t logger=%t", called, sawLoggingWrapper)
			}
			if writer.flushes != 1 {
				t.Fatalf("error-aware transport flushes = %d, want 1", writer.flushes)
			}
			if got := writer.Header().Get("Connection"); got != "close" {
				t.Fatalf("unconsumed body Connection = %q, want close", got)
			}
			wantEncoding := encoding
			if encoding == "identity" {
				wantEncoding = ""
			}
			if got := writer.Header().Get("Content-Encoding"); got != wantEncoding {
				t.Fatalf("Content-Encoding = %q, want %q", got, wantEncoding)
			}
		})
	}
}

func TestUnconsumedBodyHTTPWriterLegacyFlush(t *testing.T) {
	transport := httptest.NewRecorder()
	writer := &unconsumedBodyHTTPResponseWriter{ResponseWriter: transport}
	writer.Flush()
	if !transport.Flushed {
		t.Fatal("legacy Flush did not reach transport")
	}
}
