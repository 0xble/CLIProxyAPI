package helps

import (
	"bytes"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
)

// openPipeBody is a response body whose writer stays open after the payload,
// like an upstream that emits its terminal event but keeps the connection.
type openPipeBody struct {
	*io.PipeReader
}

func zstdPayload(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	encoder, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatalf("zstd writer: %v", err)
	}
	if _, err = encoder.Write(bytes.Repeat([]byte("data: response.completed\n\n"), 64)); err != nil {
		t.Fatalf("zstd write: %v", err)
	}
	if err = encoder.Close(); err != nil {
		t.Fatalf("zstd close: %v", err)
	}
	return buf.Bytes()
}

func TestDecodeResponseBodyZstdCloseDoesNotBlockOnOpenUpstream(t *testing.T) {
	payload := zstdPayload(t)
	for _, tc := range []struct {
		name   string
		header http.Header
	}{
		{"declared", http.Header{"Content-Encoding": []string{"zstd"}}},
		{"magic-byte", http.Header{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reader, writer := io.Pipe()
			defer writer.Close()
			go func() { _, _ = writer.Write(payload) }()
			decoded, err := DecodeResponseBody(openPipeBody{reader}, tc.header)
			if err != nil {
				t.Fatalf("DecodeResponseBody: %v", err)
			}
			buf := make([]byte, 16)
			if _, err = io.ReadFull(decoded, buf); err != nil {
				t.Fatalf("read decoded prefix: %v", err)
			}
			done := make(chan struct{})
			go func() {
				_ = decoded.Close()
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("Close blocked while the upstream connection stayed open")
			}
		})
	}
}
