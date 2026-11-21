package watcher

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

// Exercise the real OS watcher: synthetic events cannot detect a lost inode watch.
func TestConfigWatchSurvivesRepeatedAtomicReplacement(t *testing.T) {
	for _, sharedDir := range []bool{false, true} {
		t.Run(fmt.Sprintf("shared_auth_directory_%t", sharedDir), func(t *testing.T) {
			dir := t.TempDir()
			authDir := dir
			if !sharedDir {
				authDir = filepath.Join(dir, "auth")
				if err := os.Mkdir(authDir, 0o700); err != nil { t.Fatal(err) }
			}
			path := filepath.Join(dir, "config.yaml")
			write := func(retry int) {
				t.Helper()
				raw := fmt.Sprintf("auth-dir: %q\nrequest-retry: %d\n", filepath.ToSlash(authDir), retry)
				tmp := filepath.Join(dir, ".config-replacement")
				if err := os.WriteFile(tmp, []byte(raw), 0o600); err != nil { t.Fatal(err) }
				if err := os.Rename(tmp, path); err != nil { t.Fatal(err) }
			}
			write(1)
			applied := make(chan int, 16)
			w, err := NewWatcher(path, authDir, func(cfg *config.Config) { applied <- cfg.RequestRetry })
			if err != nil { t.Fatal(err) }
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(func() { cancel(); _ = w.Stop() })
			w.SetConfig(&config.Config{AuthDir: authDir, RequestRetry: 1})
			if err := w.Start(ctx); err != nil { t.Fatal(err) }
			// Start publishes the current config once; only later values prove a reload.
			for _, want := range []int{2, 3} {
				write(want)
				deadline := time.After(5 * time.Second)
				for got := -1; got != want; {
					select {
					case got = <-applied:
						if got > want { t.Fatalf("applied retry=%d, want %d", got, want) }
					case <-deadline:
						t.Fatalf("atomic replacement retry=%d was not reloaded", want)
					}
				}
			}
		})
	}
}
