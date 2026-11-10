package auth

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/claude"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func writeLoginPolicyMetadataFixture(t *testing.T, path string, metadata map[string]any) {
	t.Helper()
	doc := ojson.NewDocString("{}")
	for key, value := range metadata {
		if errSet := doc.Set(key, value); errSet != nil {
			t.Fatal(errSet)
		}
	}
	writeLoginPolicyFixture(t, path, doc.String())
}

func TestFileTokenStoreLoginPolicyClaudeLegacyOperatorMetadata(t *testing.T) {
	for _, predecessor := range []string{"email", "account-hashed", "nonlegacy"} {
		t.Run(predecessor, func(t *testing.T) {
			dir := t.TempDir()
			const email = "user@example.test"
			oldName := claude.CredentialFileName(email, "", "")
			organization := "organization-a"
			if predecessor == "account-hashed" {
				oldName = claude.CredentialFileName(email, "", "account-a")
				organization = ""
			} else if predecessor == "nonlegacy" {
				oldName = "claude-nonlegacy.json"
			}
			prior := map[string]any{
				"type": "claude", "email": email, "account_uuid": "account-a", "organization_uuid": organization,
				"proxy_url": "http://127.0.0.1:8080", "headers": map[string]any{"X-Operator": "old"},
				"excluded_models": []any{"excluded-model"}, "model_aliases": map[string]any{"source": "alias"},
				"request_retry": float64(7), "weight": float64(5), "prefix": "team", "disabled": true,
				"access_token": "old-access", "refresh_token": "old-refresh", "id_token": "old-id",
				"expired": "old-expiration", "last_refresh": "old-refresh-time", "session_id": "old-session",
			}
			oldPath := filepath.Join(dir, oldName)
			writeLoginPolicyMetadataFixture(t, oldPath, prior)
			name := claude.CredentialFileName(email, "organization-a", "account-a")
			record := &coreauth.Auth{ID: name, FileName: name, Provider: "claude", Metadata: map[string]any{
				"type": "claude", "email": email, "account_uuid": "account-a", "organization_uuid": "organization-a",
				"access_token": "new-access", "refresh_token": "new-refresh",
			}}
			wantHeaders := prior["headers"]
			if predecessor != "email" {
				wantHeaders = map[string]any{"X-Operator": "new"}
				record.Metadata["headers"] = wantHeaders
			}
			store := NewFileTokenStore()
			store.SetBaseDir(dir)
			path, errSave := store.Save(coreauth.WithAuthCreationIntent(context.Background()), record)
			if errSave != nil {
				t.Fatal(errSave)
			}
			saved := readLoginPolicyFixture(t, path)
			for _, key := range []string{"proxy_url", "excluded_models", "model_aliases", "request_retry"} {
				if predecessor == "nonlegacy" {
					if _, copied := saved[key]; copied {
						t.Errorf("nonlegacy predecessor copied %s", key)
					}
				} else if !reflect.DeepEqual(saved[key], prior[key]) {
					t.Errorf("legacy operator configuration %s lost", key)
				}
			}
			if !reflect.DeepEqual(saved["headers"], wantHeaders) || saved["access_token"] != "new-access" || saved["refresh_token"] != "new-refresh" {
				t.Fatal("new explicit metadata or credentials overwritten")
			}
			for _, key := range []string{"id_token", "expired", "last_refresh", "session_id"} {
				if _, copied := saved[key]; copied {
					t.Errorf("old token lifecycle field %s copied", key)
				}
			}
			backups, errGlob := filepath.Glob(filepath.Join(dir, "auth-backups", oldName+"-*.bak"))
			if errGlob != nil || len(backups) != 1 {
				t.Fatalf("predecessor not archived: %v %v", backups, errGlob)
			}
			if !reflect.DeepEqual(readLoginPolicyFixture(t, backups[0]), prior) {
				t.Fatal("archived metadata changed")
			}
		})
	}
}

func TestFileTokenStoreLoginPolicyClaudeAccountTargetRequiresLegacyAccount(t *testing.T) {
	for _, account := range []string{"", "different-account", "account-a"} {
		t.Run("prior-account="+account, func(t *testing.T) {
			dir := t.TempDir()
			const email = "user@example.test"
			oldPath := filepath.Join(dir, claude.CredentialFileName(email, "", ""))
			writeLoginPolicyMetadataFixture(t, oldPath, map[string]any{
				"type": "claude", "email": email, "account_uuid": account, "weight": float64(5),
			})
			name := claude.CredentialFileName(email, "", "account-a")
			record := &coreauth.Auth{ID: name, FileName: name, Provider: "claude", Metadata: map[string]any{
				"type": "claude", "email": email, "account_uuid": "account-a", "access_token": "new-access",
			}}
			store := NewFileTokenStore()
			store.SetBaseDir(dir)
			path, errSave := store.Save(coreauth.WithAuthCreationIntent(context.Background()), record)
			if errSave != nil {
				t.Fatal(errSave)
			}
			_, copied := readLoginPolicyFixture(t, path)["weight"]
			wantMatch := account == "account-a"
			if copied != wantMatch {
				t.Fatalf("policy copied=%v, want %v", copied, wantMatch)
			}
			_, errStat := os.Stat(oldPath)
			if wantMatch != os.IsNotExist(errStat) {
				t.Fatalf("unexpected predecessor retirement: %v", errStat)
			}
		})
	}
}

func TestFileTokenStoreLoginPolicyPluginMultiAuthSiblings(t *testing.T) {
	dir := t.TempDir()
	store := NewFileTokenStore()
	store.SetBaseDir(dir)
	ctx := coreauth.WithAuthCreationIntent(context.Background())
	for _, name := range []string{"parent", "project-a", "project-b"} {
		metadata := map[string]any{"type": "plugin-projects", "email": "user@example.test", "access_token": "synthetic"}
		if name == "parent" {
			metadata["weight"] = float64(5)
		} else {
			metadata["project_id"] = name
		}
		if _, errSave := store.Save(ctx, &coreauth.Auth{ID: name + ".json", Provider: "plugin-projects", Metadata: metadata}); errSave != nil {
			t.Fatal(errSave)
		}
	}
	loaded, errList := store.List(context.Background())
	if errList != nil || len(loaded) != 3 {
		t.Fatalf("plugin siblings retired: count=%d err=%v", len(loaded), errList)
	}
	for _, name := range []string{"project-a", "project-b"} {
		if _, inherited := readLoginPolicyFixture(t, filepath.Join(dir, name+".json"))["weight"]; inherited {
			t.Fatal("plugin project inherited parent policy")
		}
		// A later batch failure must be able to roll back its children without
		// losing the independently persisted parent credential.
		if errDelete := store.Delete(context.Background(), name+".json"); errDelete != nil {
			t.Fatal(errDelete)
		}
	}
	loaded, errList = store.List(context.Background())
	if errList != nil || len(loaded) != 1 || loaded[0].ID != "parent.json" {
		t.Fatalf("plugin parent lost after child rollback: count=%d err=%v", len(loaded), errList)
	}
	if _, errStat := os.Stat(filepath.Join(dir, "auth-backups")); !os.IsNotExist(errStat) {
		t.Fatal("plugin siblings created migration backups", errStat)
	}
}

func TestFileTokenStoreLoginPolicyFailureLeavesCallerUnchanged(t *testing.T) {
	for _, failure := range []string{"inherited-validation", "persistence", "claude-persistence"} {
		t.Run(failure, func(t *testing.T) {
			dir := t.TempDir()
			prior := priorLoginPolicy
			if failure == "inherited-validation" {
				prior = `{"type":"codex","email":"user@example.test","account_id":"account-a","weight":"invalid","prefix":"guarded","disabled":true}`
			}
			oldPath := filepath.Join(dir, "codex-1234abcd-user@example.test-pro.json")
			record := codexLoginRecord("codex-1234abcd-user@example.test-promax.json")
			if failure == "claude-persistence" {
				oldPath = filepath.Join(dir, claude.CredentialFileName("user@example.test", "", ""))
				prior = `{"type":"claude","email":"user@example.test","account_uuid":"account-a","weight":5,"prefix":"guarded","disabled":true,"proxy_url":"http://127.0.0.1:8080"}`
				name := claude.CredentialFileName("user@example.test", "", "account-a")
				storage := &claude.ClaudeTokenStorage{Email: "user@example.test", AccessToken: "new-access", AccountUUID: "account-a", Metadata: map[string]any{"unchanged": "storage"}}
				record = &coreauth.Auth{ID: name, FileName: name, Provider: "claude", Storage: storage, Metadata: map[string]any{
					"type": "claude", "email": "user@example.test", "account_uuid": "account-a", "access_token": "new-access",
					"invalid_json_value": make(chan int),
				}}
			}
			writeLoginPolicyFixture(t, oldPath, prior)
			record.Status = coreauth.StatusActive
			record.Attributes = map[string]string{"operator": "unchanged"}
			if failure == "persistence" {
				record.Storage = &loginPolicyFailingStorage{}
			}
			before := record.Clone()
			if storage, ok := before.Storage.(*claude.ClaudeTokenStorage); ok {
				storageBefore := *storage
				before.Storage = &storageBefore
			}
			store := NewFileTokenStore()
			store.SetBaseDir(dir)
			path, errSave := store.Save(coreauth.WithAuthCreationIntent(context.Background()), record)
			if errSave == nil || path != "" {
				t.Fatalf("expected failure before persistence, got %q %v", path, errSave)
			}
			if !reflect.DeepEqual(record, before) {
				t.Fatal("failed save mutated caller metadata, attributes or runtime policy")
			}
			if raw, errRead := os.ReadFile(oldPath); errRead != nil || string(raw) != prior {
				t.Fatal("failed save changed predecessor")
			}
		})
	}
}
