package auth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/claude"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

const priorLoginPolicy = `{"type":"codex","email":"user@example.test","account_id":"account-a","access_token":"old-access","refresh_token":"old-refresh","siwc":{"access_token":"old-siwc"},"proxy_url":"old-proxy","note":"do not copy","quota_guard":{"reserve_percent":25,"final_reserve_percent":5,"reset_window":"24h"},"weight":1,"priority":3,"prefix":"guarded","disabled":true}`

func writeLoginPolicyFixture(t *testing.T, path, raw string) {
	t.Helper()
	if errWrite := os.WriteFile(path, []byte(raw), 0o600); errWrite != nil {
		t.Fatal(errWrite)
	}
}

func readLoginPolicyFixture(t *testing.T, path string) map[string]any {
	t.Helper()
	metadata, errRead := readLoginPolicy(path)
	if errRead != nil {
		t.Fatal(errRead)
	}
	return metadata
}

func codexLoginRecord(name string) *coreauth.Auth {
	return &coreauth.Auth{
		ID: name, FileName: name, Provider: "codex",
		Metadata: map[string]any{"email": "user@example.test", "plan_type": "promax"},
		Storage: &codex.CodexTokenStorage{
			Email: "user@example.test", AccountID: "account-a", PlanType: "promax",
			AccessToken: "new-access", RefreshToken: "new-refresh",
		},
	}
}

func TestFileTokenStoreLoginPolicyPlanChange(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		name := "inherit"
		if explicit {
			name = "explicit-new-values-win"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			oldName := "codex-1234abcd-user@example.test-pro.json"
			newName := "codex-1234abcd-user@example.test-promax.json"
			oldPath := filepath.Join(dir, oldName)
			writeLoginPolicyFixture(t, oldPath, priorLoginPolicy)
			record := codexLoginRecord(newName)
			if explicit {
				record.Metadata["quota_guard"] = nil // Presence, including null, is explicit.
				record.Metadata["weight"] = float64(9)
				record.Metadata["priority"] = float64(0)
				record.Metadata["prefix"] = ""
				record.Metadata["disabled"] = false
			}
			store := NewFileTokenStore()
			manager := NewManager(store, &dummyAuthenticator{provider: "codex", record: record})
			_, savedPath, errLogin := manager.Login(context.Background(), "codex", &config.Config{AuthDir: dir}, nil)
			if errLogin != nil {
				t.Fatal(errLogin)
			}
			saved := readLoginPolicyFixture(t, savedPath)
			prior := ojson.Parse(priorLoginPolicy).Value().(map[string]any)
			for _, key := range loginPolicyFields {
				want := prior[key]
				if explicit {
					want = record.Metadata[key]
				}
				if !reflect.DeepEqual(saved[key], want) {
					t.Errorf("%s = %#v, want %#v", key, saved[key], want)
				}
			}
			if record.Disabled != !explicit || record.Prefix != saved["prefix"] {
				t.Errorf("returned runtime policy differs: disabled=%v prefix=%q", record.Disabled, record.Prefix)
			}
			if saved["access_token"] != "new-access" || saved["refresh_token"] != "new-refresh" {
				t.Fatal("new credentials were overwritten")
			}
			for _, key := range []string{"siwc", "proxy_url", "note"} {
				if _, copied := saved[key]; copied {
					t.Errorf("non-policy field %s was copied", key)
				}
			}
			if _, errStat := os.Stat(oldPath); !os.IsNotExist(errStat) {
				t.Fatalf("old credential remains active: %v", errStat)
			}
			backups, errGlob := filepath.Glob(filepath.Join(dir, "auth-backups", oldName+"-*.bak"))
			if errGlob != nil || len(backups) != 1 {
				t.Fatalf("backups = %v, err = %v", backups, errGlob)
			}
			backupBytes, errRead := os.ReadFile(backups[0])
			if errRead != nil || string(backupBytes) != priorLoginPolicy {
				t.Fatal("prior credential was not archived unchanged")
			}
			loaded, errList := store.List(context.Background())
			if errList != nil || len(loaded) != 1 || loaded[0].FileName != newName {
				t.Fatalf("backup was counted as an auth: loaded=%v err=%v", loaded, errList)
			}
		})
	}
}

func TestFileTokenStoreLoginPolicyClaude(t *testing.T) {
	for _, sameName := range []bool{false, true} {
		t.Run(map[bool]string{false: "changed-filename", true: "same-filename"}[sameName], func(t *testing.T) {
			dir := t.TempDir()
			oldName, newName := "claude-old-name.json", "claude-new-name.json"
			if sameName {
				oldName = newName
			}
			oldDoc := ojson.NewDocString(priorLoginPolicy)
			if errSet := oldDoc.Set("type", "claude"); errSet != nil {
				t.Fatal(errSet)
			}
			writeLoginPolicyFixture(t, filepath.Join(dir, oldName), oldDoc.String())
			record := &coreauth.Auth{
				ID: newName, FileName: newName, Provider: "claude",
				Metadata: map[string]any{"email": "user@example.test"},
				Storage:  &claude.ClaudeTokenStorage{Email: "user@example.test", AccessToken: "new-access"},
			}
			store := NewFileTokenStore()
			store.SetBaseDir(dir)
			// Management OAuth and the CLI manager both mark this shared save seam.
			savedPath, errSave := store.Save(coreauth.WithAuthCreationIntent(context.Background()), record)
			if errSave != nil {
				t.Fatal(errSave)
			}
			saved := readLoginPolicyFixture(t, savedPath)
			prior := ojson.Parse(oldDoc.String()).Value().(map[string]any)
			for _, key := range loginPolicyFields {
				if !reflect.DeepEqual(saved[key], prior[key]) {
					t.Errorf("policy %s lost", key)
				}
			}
			if saved["access_token"] != "new-access" {
				t.Fatal("old token copied")
			}
			backups, errGlob := filepath.Glob(filepath.Join(dir, "auth-backups", "*.bak"))
			if errGlob != nil || (sameName && len(backups) != 0) || (!sameName && len(backups) != 1) {
				t.Fatalf("unexpected retirement: %v (%v)", backups, errGlob)
			}
		})
	}
}

func TestFileTokenStoreLoginPolicyIsolation(t *testing.T) {
	for _, tc := range []struct {
		name, provider, email, accountID, hash string
		creation                               bool
	}{
		{"different-provider", "claude", "user@example.test", "account-a", "1234abcd", true},
		{"different-account-same-email", "codex", "user@example.test", "account-b", "1234abcd", true},
		{"different-email", "codex", "other@example.test", "", "", true},
		{"different-hash-same-email", "codex", "user@example.test", "", "8765abcd", true},
		{"refresh-does-not-migrate", "codex", "user@example.test", "account-a", "1234abcd", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			oldPath := filepath.Join(dir, "codex-1234abcd-user@example.test-pro.json")
			writeLoginPolicyFixture(t, oldPath, priorLoginPolicy)
			newName := "codex-" + tc.hash + "-" + tc.email + "-promax.json"
			record := &coreauth.Auth{ID: newName, FileName: newName, Provider: tc.provider,
				Metadata: map[string]any{"type": tc.provider, "email": tc.email, "account_id": tc.accountID, "access_token": "new"}}
			store := NewFileTokenStore()
			store.SetBaseDir(dir)
			ctx := context.Background()
			if tc.creation {
				ctx = coreauth.WithAuthCreationIntent(ctx)
			}
			savedPath, errSave := store.Save(ctx, record)
			if errSave != nil {
				t.Fatal(errSave)
			}
			saved := readLoginPolicyFixture(t, savedPath)
			if _, copied := saved["quota_guard"]; copied {
				t.Fatal("unrelated credential policy copied")
			}
			oldBytes, errRead := os.ReadFile(oldPath)
			if errRead != nil || string(oldBytes) != priorLoginPolicy {
				t.Fatal("unrelated credential changed")
			}
		})
	}
}

func TestFileTokenStoreLoginPolicySharedCodexWorkspace(t *testing.T) {
	for _, withAccountID := range []bool{false, true} {
		t.Run(map[bool]string{false: "filename-hash-only", true: "shared-account-id"}[withAccountID], func(t *testing.T) {
			dir := t.TempDir()
			store := NewFileTokenStore()
			store.SetBaseDir(dir)
			for _, email := range []string{"alice@example.test", "bob@example.test", "carol@example.test"} {
				name := "codex-1234abcd-" + email + "-pro.json"
				metadata := map[string]any{"type": "codex", "email": email, "access_token": "synthetic"}
				if withAccountID {
					metadata["account_id"] = "shared-workspace"
				}
				if email == "alice@example.test" {
					metadata["weight"] = float64(5)
				}
				path, errSave := store.Save(coreauth.WithAuthCreationIntent(context.Background()), &coreauth.Auth{
					ID: name, FileName: name, Provider: "codex", Metadata: metadata,
				})
				if errSave != nil {
					t.Fatal(errSave)
				}
				if email != "alice@example.test" {
					if _, copied := readLoginPolicyFixture(t, path)["weight"]; copied {
						t.Fatal("shared workspace inherited another member's policy")
					}
				}
			}
			loaded, errList := store.List(context.Background())
			if errList != nil || len(loaded) != 3 {
				t.Fatalf("workspace credentials retired: count=%d err=%v", len(loaded), errList)
			}
			backups, errGlob := filepath.Glob(filepath.Join(dir, "auth-backups", "*.bak"))
			if errGlob != nil || len(backups) != 0 {
				t.Fatalf("unrelated credentials archived: %v %v", backups, errGlob)
			}
		})
	}
}

func TestFileTokenStoreLoginPolicyClaudeOrganizationAmbiguity(t *testing.T) {
	const email = "user@example.test"
	for _, tc := range []struct {
		name, organization, account, filename string
		wantMatch                             bool
	}{
		{name: "missing-legacy-organization-remains-ambiguous", account: "shared-account"},
		{name: "missing-legacy-organization-email-only-remains-ambiguous"},
		{name: "account-hashed-name-without-account-metadata-remains-ambiguous", filename: claude.CredentialFileName(email, "", "shared-account")},
		{name: "noncanonical-account-predecessor-remains-ambiguous", account: "shared-account", filename: "claude-other.json"},
		{name: "different-organization-with-shared-account", organization: "organization-b", account: "shared-account"},
		{name: "account-predecessor-associated-with-another-organization", organization: "organization-b", account: "shared-account", filename: claude.CredentialFileName(email, "", "shared-account")},
		{name: "matching-account-hashed-predecessor", account: "shared-account", filename: claude.CredentialFileName(email, "", "shared-account"), wantMatch: true},
		{name: "matching-organization", organization: "organization-a", account: "shared-account", wantMatch: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			oldName := tc.filename
			if oldName == "" {
				oldName = claude.CredentialFileName(email, "", "")
			}
			oldPath := filepath.Join(dir, oldName)
			doc := ojson.NewDocString("{}")
			for key, value := range map[string]any{"type": "claude", "email": email, "organization_uuid": tc.organization, "account_uuid": tc.account, "weight": 5} {
				if errSet := doc.Set(key, value); errSet != nil {
					t.Fatal(errSet)
				}
			}
			prior := doc.String()
			writeLoginPolicyFixture(t, oldPath, prior)
			name := claude.CredentialFileName(email, "organization-a", "shared-account")
			record := &coreauth.Auth{ID: name, FileName: name, Provider: "claude", Metadata: map[string]any{
				"type": "claude", "email": email, "organization_uuid": "organization-a", "account_uuid": "shared-account", "access_token": "synthetic",
			}}
			store := NewFileTokenStore()
			store.SetBaseDir(dir)
			path, errSave := store.Save(coreauth.WithAuthCreationIntent(context.Background()), record)
			if errSave != nil {
				t.Fatal(errSave)
			}
			_, copied := readLoginPolicyFixture(t, path)["weight"]
			if copied != tc.wantMatch {
				t.Fatalf("policy copied=%v, want %v", copied, tc.wantMatch)
			}
			if tc.wantMatch {
				if _, errStat := os.Stat(oldPath); !os.IsNotExist(errStat) {
					t.Fatal("accepted predecessor was not retired", errStat)
				}
			} else {
				raw, errRead := os.ReadFile(oldPath)
				if errRead != nil || string(raw) != prior {
					t.Fatal("ambiguous or conflicting credential changed")
				}
				if _, errStat := os.Stat(loginRetirementFence(oldPath)); !os.IsNotExist(errStat) {
					t.Fatal("ambiguous or conflicting credential fenced", errStat)
				}
			}
		})
	}
}

func TestFileTokenStoreLoginPolicyRediscoveredProject(t *testing.T) {
	dir := t.TempDir()
	name := "antigravity-user@example.test.json"
	writeLoginPolicyFixture(t, filepath.Join(dir, name), `{"type":"antigravity","email":"user@example.test","project_id":"old-project","weight":5}`)
	store := NewFileTokenStore()
	store.SetBaseDir(dir)
	path, errSave := store.Save(coreauth.WithAuthCreationIntent(context.Background()), &coreauth.Auth{
		ID: name, Provider: "antigravity", Metadata: map[string]any{"type": "antigravity", "email": "USER@example.test", "project_id": "rediscovered-project", "access_token": "synthetic"},
	})
	if errSave != nil {
		t.Fatal(errSave)
	}
	saved := readLoginPolicyFixture(t, path)
	if saved["weight"] != float64(5) || saved["project_id"] != "rediscovered-project" {
		t.Fatalf("same-account project rediscovery lost policy or new project: %#v", saved)
	}
}

func TestCarryLoginPolicyReportsOnlyArchivedFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "codex-1234abcd-user@example.test-promax.json")
	writeLoginPolicyFixture(t, path, `{"type":"codex","email":"user@example.test","account_id":"account-a","weight":9}`)
	writeLoginPolicyFixture(t, filepath.Join(dir, "codex-1234abcd-user@example.test-pro.json"), priorLoginPolicy)
	record := codexLoginRecord(filepath.Base(path))
	source, errCarry := carryLoginPolicy(path, record)
	if errCarry != nil {
		t.Fatal(errCarry)
	}
	want := []string{"quota_guard", "priority", "prefix", "disabled"}
	if source == nil || !reflect.DeepEqual(source.carried, want) {
		t.Fatalf("archived field provenance = %#v, want %v", source, want)
	}
	if record.Metadata["weight"] != float64(9) {
		t.Fatal("same-file policy did not win")
	}
}

func TestFileTokenStoreLoginPolicyRetirementFenceAllowsRestoredRefresh(t *testing.T) {
	dir := t.TempDir()
	name := "claude-restored@example.test.json"
	path := filepath.Join(dir, name)
	writeLoginPolicyFixture(t, loginRetirementFence(path), "")
	writeLoginPolicyFixture(t, path, `{"type":"claude","email":"restored@example.test","access_token":"old-access"}`)
	store := NewFileTokenStore()
	store.SetBaseDir(dir)
	record := &coreauth.Auth{ID: name, Provider: "claude", Metadata: map[string]any{
		"type": "claude", "email": "restored@example.test", "access_token": "new-access",
	}}
	savedPath, errSave := store.Save(context.Background(), record)
	if errSave != nil || savedPath != path {
		t.Fatalf("restored refresh = %q, %v", savedPath, errSave)
	}
	if readLoginPolicyFixture(t, path)["access_token"] != "new-access" {
		t.Fatal("retirement fence blocked a restored credential's refresh")
	}
}

func TestFileTokenStoreLoginPolicySaveFailureRetainsPrior(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "codex-1234abcd-user@example.test-pro.json")
	writeLoginPolicyFixture(t, oldPath, priorLoginPolicy)
	record := codexLoginRecord("codex-1234abcd-user@example.test-promax.json")
	record.Metadata["weight"] = "invalid" // Invalid explicit values must not retire the source.
	store := NewFileTokenStore()
	store.SetBaseDir(dir)
	if _, errSave := store.Save(coreauth.WithAuthCreationIntent(context.Background()), record); errSave == nil {
		t.Fatal("expected failed save")
	}
	oldBytes, errRead := os.ReadFile(oldPath)
	if errRead != nil || string(oldBytes) != priorLoginPolicy {
		t.Fatal("source changed after failed save")
	}
}

type loginPolicyFailingStorage struct{}

func (*loginPolicyFailingStorage) SaveTokenToFile(string) error {
	return errors.New("synthetic persistence failure")
}

func TestFileTokenStoreLoginPolicyFailedPersistence(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "codex-1234abcd-user@example.test-pro.json")
	writeLoginPolicyFixture(t, oldPath, priorLoginPolicy)
	record := codexLoginRecord("codex-1234abcd-user@example.test-promax.json")
	record.Storage = &loginPolicyFailingStorage{}
	store := NewFileTokenStore()
	store.SetBaseDir(dir)
	if _, errSave := store.Save(coreauth.WithAuthCreationIntent(context.Background()), record); errSave == nil {
		t.Fatal("expected token-storage failure")
	}
	oldBytes, errRead := os.ReadFile(oldPath)
	if errRead != nil || string(oldBytes) != priorLoginPolicy {
		t.Fatal("failed token persistence retired source")
	}
	if _, errStat := os.Stat(loginRetirementFence(oldPath)); !os.IsNotExist(errStat) {
		t.Fatal("failed persistence fenced source")
	}
}

func TestFileTokenStoreLoginPolicyAmbiguousPriorFailsClosed(t *testing.T) {
	dir := t.TempDir()
	for _, plan := range []string{"pro", "plus"} {
		writeLoginPolicyFixture(t, filepath.Join(dir, "codex-1234abcd-user@example.test-"+plan+".json"), priorLoginPolicy)
	}
	store := NewFileTokenStore()
	store.SetBaseDir(dir)
	name := "codex-1234abcd-user@example.test-promax.json"
	if _, errSave := store.Save(coreauth.WithAuthCreationIntent(context.Background()), codexLoginRecord(name)); errSave == nil {
		t.Fatal("ambiguous prior policy did not fail closed")
	}
	if _, errStat := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(errStat) {
		t.Fatal("ambiguous login wrote a replacement")
	}
}

func TestFileTokenStoreLoginPolicyOrganizationIsNotAccount(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "claude-alice.json")
	writeLoginPolicyFixture(t, oldPath, `{"type":"claude","email":"alice@example.test","organization_uuid":"shared-org","weight":5}`)
	record := &coreauth.Auth{ID: "claude-bob.json", Provider: "claude", Metadata: map[string]any{
		"type": "claude", "email": "bob@example.test", "organization_uuid": "shared-org", "access_token": "new",
	}}
	store := NewFileTokenStore()
	store.SetBaseDir(dir)
	path, errSave := store.Save(coreauth.WithAuthCreationIntent(context.Background()), record)
	if errSave != nil {
		t.Fatal(errSave)
	}
	if _, copied := readLoginPolicyFixture(t, path)["weight"]; copied {
		t.Fatal("shared organization copied a different account's policy")
	}
	if _, errStat := os.Stat(oldPath); errStat != nil {
		t.Fatal("different account retired", errStat)
	}
}

func TestFileTokenStoreLoginPolicyDestinationConflict(t *testing.T) {
	for _, key := range []string{"type", "account_id", "email"} {
		t.Run(key, func(t *testing.T) {
			dir := t.TempDir()
			name := "codex-1234abcd-user@example.test-promax.json"
			path := filepath.Join(dir, name)
			writeLoginPolicyFixture(t, path, priorLoginPolicy)
			record := codexLoginRecord(name)
			switch key {
			case "type":
				record.Provider = "claude"
				record.Storage = nil
				record.Metadata["type"] = "claude"
			case "account_id":
				record.Metadata[key] = "different-account"
			case "email":
				record.Metadata[key] = "different@example.test"
			}
			store := NewFileTokenStore()
			store.SetBaseDir(dir)
			if _, errSave := store.Save(coreauth.WithAuthCreationIntent(context.Background()), record); errSave == nil {
				t.Fatal("conflicting destination accepted")
			}
			raw, errRead := os.ReadFile(path)
			if errRead != nil || string(raw) != priorLoginPolicy {
				t.Fatal("conflicting destination changed")
			}
		})
	}
}

func TestFileTokenStoreLoginPolicyClaudeManagerAccountConflict(t *testing.T) {
	dir := t.TempDir()
	oldName := "claude-user@example.test.json"
	oldPath := filepath.Join(dir, oldName)
	prior := `{"type":"claude","email":"user@example.test","organization_uuid":"shared-org","account_uuid":"account-a","weight":5,"proxy_url":"old-proxy","access_token":"old"}`
	writeLoginPolicyFixture(t, oldPath, prior)
	name := claude.CredentialFileName("user@example.test", "shared-org", "account-b")
	record := &coreauth.Auth{ID: name, FileName: name, Provider: "claude", Metadata: map[string]any{
		"type": "claude", "email": "user@example.test", "organization_uuid": "shared-org", "account_uuid": "account-b", "access_token": "new",
	}}
	store := NewFileTokenStore()
	manager := NewManager(store, &dummyAuthenticator{provider: "claude", record: record})
	_, path, errLogin := manager.Login(context.Background(), "claude", &config.Config{AuthDir: dir}, nil)
	if errLogin != nil {
		t.Fatal(errLogin)
	}
	if _, copied := readLoginPolicyFixture(t, path)["weight"]; copied {
		t.Fatal("legacy manager migrated a conflicting account")
	}
	raw, errRead := os.ReadFile(oldPath)
	if errRead != nil || string(raw) != prior {
		t.Fatal("legacy manager deleted a conflicting account")
	}
}

func TestFileTokenStoreLoginPolicySameFileAliases(t *testing.T) {
	for _, alias := range []string{"relative", "case"} {
		t.Run(alias, func(t *testing.T) {
			dir := t.TempDir()
			name := "credential.json"
			path := filepath.Join(dir, name)
			writeLoginPolicyFixture(t, path, priorLoginPolicy)
			aliasPath := dir + "/./" + name
			wantBackups := 0
			if alias == "case" {
				aliasPath = filepath.Join(dir, "CREDENTIAL.JSON")
				if _, errStat := os.Stat(aliasPath); os.IsNotExist(errStat) {
					// A hard link provides the same file-identity alias on a
					// case-sensitive CI volume without relying on host defaults.
					if errLink := os.Link(path, aliasPath); errLink != nil {
						t.Fatal(errLink)
					}
					wantBackups = 1 // Distinct hard-link entries must be reconciled.
				}
			}
			record := &coreauth.Auth{ID: name, Provider: "codex", Metadata: map[string]any{
				"type": "codex", "email": "user@example.test", "account_id": "account-a", "access_token": "new",
			}, Attributes: map[string]string{coreauth.AttributePath: aliasPath}}
			store := NewFileTokenStore()
			store.SetBaseDir(dir)
			if _, errSave := store.Save(coreauth.WithAuthCreationIntent(context.Background()), record); errSave != nil {
				t.Fatal(errSave)
			}
			if got := readLoginPolicyFixture(t, aliasPath)["access_token"]; got != "new" {
				t.Fatal("replacement disappeared or was not updated", got)
			}
			backups, errGlob := filepath.Glob(filepath.Join(dir, "auth-backups", "*.bak"))
			if errGlob != nil || len(backups) != wantBackups {
				t.Fatalf("destination alias retirement = %v %v, want %d backups", backups, errGlob, wantBackups)
			}
			loaded, errList := store.List(context.Background())
			if errList != nil || len(loaded) != 1 {
				t.Fatalf("alias left duplicate active credentials: count=%d err=%v", len(loaded), errList)
			}
		})
	}
}

func TestFileTokenStoreLoginPolicyMissingPayloadStillFails(t *testing.T) {
	store := NewFileTokenStore()
	store.SetBaseDir(t.TempDir())
	if _, errSave := store.Save(coreauth.WithAuthCreationIntent(context.Background()), &coreauth.Auth{ID: "invalid.json", Provider: "demo"}); errSave == nil {
		t.Fatal("policy carryover turned an empty login payload into a valid credential")
	}
}

func TestFileTokenStoreLoginPolicyInvalidDisabledRejected(t *testing.T) {
	dir := t.TempDir()
	record := codexLoginRecord("new.json")
	record.Metadata["disabled"] = nil
	store := NewFileTokenStore()
	store.SetBaseDir(dir)
	if _, errSave := store.Save(coreauth.WithAuthCreationIntent(context.Background()), record); errSave == nil {
		t.Fatal("invalid disabled value was silently overwritten")
	}
}

func TestFileTokenStoreLoginPolicyRetirementFencesStaleSave(t *testing.T) {
	dir := t.TempDir()
	oldName := "codex-1234abcd-user@example.test-pro.json"
	oldPath := filepath.Join(dir, oldName)
	writeLoginPolicyFixture(t, oldPath, priorLoginPolicy)
	store := NewFileTokenStore()
	store.SetBaseDir(dir)
	if _, errSave := store.Save(coreauth.WithAuthCreationIntent(context.Background()), codexLoginRecord("codex-1234abcd-user@example.test-promax.json")); errSave != nil {
		t.Fatal(errSave)
	}
	// A new store represents the serving process/restart; fencing is not merely
	// an in-memory flag on the CLI's store. The stale snapshot is enabled.
	runtimeStore := NewFileTokenStore()
	runtimeStore.SetBaseDir(dir)
	stale := &coreauth.Auth{ID: oldName, FileName: oldName, Provider: "codex", Metadata: map[string]any{"type": "codex", "access_token": "stale"}}
	if path, errSave := runtimeStore.Save(context.Background(), stale); errSave != nil || path != "" {
		t.Fatalf("stale save = %q, %v", path, errSave)
	}
	if _, errStat := os.Stat(oldPath); !os.IsNotExist(errStat) {
		t.Fatal("retired credential was resurrected")
	}
	// A deliberate later plan downgrade may reuse the retired filename.
	if _, errSave := store.Save(coreauth.WithAuthCreationIntent(context.Background()), codexLoginRecord(oldName)); errSave != nil {
		t.Fatal(errSave)
	}
	if _, errStat := os.Stat(loginRetirementFence(oldPath)); !os.IsNotExist(errStat) {
		t.Fatal("explicit reuse did not clear retirement fence")
	}
}

func TestFileTokenStoreLoginPolicyRetryFinishesRetirement(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "codex-1234abcd-user@example.test-pro.json")
	writeLoginPolicyFixture(t, oldPath, priorLoginPolicy)
	backupDir := filepath.Join(dir, "auth-backups")
	writeLoginPolicyFixture(t, backupDir, "obstruction")
	store := NewFileTokenStore()
	store.SetBaseDir(dir)
	name := "codex-1234abcd-user@example.test-promax.json"
	record := codexLoginRecord(name)
	path, errSave := store.Save(coreauth.WithAuthCreationIntent(context.Background()), record)
	if errSave == nil || path == "" {
		t.Fatalf("want partial-success retirement error, got %q %v", path, errSave)
	}
	if !record.Disabled || record.Status != coreauth.StatusDisabled || record.Prefix != "guarded" || record.Metadata["weight"] != float64(1) || record.Attributes[coreauth.AttributePath] != path {
		t.Fatal("partial-success save did not publish persisted policy to caller")
	}
	if readLoginPolicyFixture(t, path)["access_token"] != "new-access" {
		t.Fatal("partial-success replacement was not persisted")
	}
	if _, errStat := os.Stat(oldPath); errStat != nil {
		t.Fatal("failed archive lost predecessor", errStat)
	}
	if errRemove := os.Remove(backupDir); errRemove != nil {
		t.Fatal(errRemove)
	}
	retry := codexLoginRecord(name)
	retry.Metadata["quota_guard"] = nil
	retry.Metadata["prefix"] = ""
	if _, errSave := store.Save(coreauth.WithAuthCreationIntent(context.Background()), retry); errSave != nil {
		t.Fatal(errSave)
	}
	saved := readLoginPolicyFixture(t, filepath.Join(dir, name))
	if saved["quota_guard"] != nil || saved["prefix"] != "" {
		t.Fatalf("retry silently restored explicitly cleared policy: guard=%v prefix=%v", saved["quota_guard"], saved["prefix"])
	}
	if _, errStat := os.Stat(oldPath); !os.IsNotExist(errStat) {
		t.Fatal("retry left prior credential active")
	}
}
