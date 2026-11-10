package auth

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/claude"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

// CarriesLoginPolicy reports that this store owns cross-filename policy transfer
// and retirement; legacy provider migrators must not pre-merge or delete files.
func (s *FileTokenStore) CarriesLoginPolicy() bool { return true }

var loginPolicyFields = [...]string{"quota_guard", "weight", "priority", "prefix", "disabled"}

type loginPolicySource struct {
	path     string
	metadata map[string]any
	carried  []string
}

// carryLoginPolicy runs only for explicit credential creation, under the store
// mutex. Refreshes and operator updates must never inherit another file's policy.
func carryLoginPolicy(path string, auth *coreauth.Auth) (*loginPolicySource, error) {
	provider := loginPolicyProvider(auth.Provider)
	// A nonempty malformed record must remain an error rather than being repaired
	// by inherited policy, preserving plugin batch rollback behavior.
	if provider == "" || (auth.Storage == nil && auth.Metadata == nil) {
		return nil, nil
	}
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	// Struct/attribute values supplied by callers are explicit too. An explicit
	// false disabled value must use Metadata, since a bool has no presence bit.
	if _, exists := auth.Metadata["disabled"]; !exists && auth.Disabled {
		auth.Metadata["disabled"] = true
	}
	if _, exists := auth.Metadata["prefix"]; !exists && auth.Prefix != "" {
		auth.Metadata["prefix"] = auth.Prefix
	}
	for _, key := range []string{"weight", "priority"} {
		if value, exists := auth.Attributes[key]; exists {
			if _, explicit := auth.Metadata[key]; !explicit {
				auth.Metadata[key] = value
			}
		}
	}

	var source *loginPolicySource
	var destinationPolicy map[string]any
	if metadata, errRead := readLoginPolicy(path); errRead == nil {
		if loginAccountConflicts(provider, auth, metadata) {
			return nil, fmt.Errorf("auth filestore: destination credential belongs to a different provider or account")
		}
		destinationPolicy = metadata
	} else if !os.IsNotExist(errRead) {
		return nil, errRead
	}
	entries, errEntries := os.ReadDir(filepath.Dir(path))
	if errEntries != nil {
		return nil, fmt.Errorf("auth filestore: list prior credentials: %w", errEntries)
	}
	for _, entry := range entries {
		// Do not follow symlinks or descend into backup directories.
		if !entry.Type().IsRegular() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
			continue
		}
		candidatePath := filepath.Join(filepath.Dir(path), entry.Name())
		if sameLoginFile(candidatePath, path) {
			continue
		}
		metadata, errRead := readLoginPolicy(candidatePath)
		if errRead != nil {
			// Unknown/unreadable credentials cannot be established as the same
			// account. Leave them untouched, as the ordinary loader does.
			continue
		}
		if !sameLoginAccount(provider, path, auth, candidatePath, metadata) {
			continue
		}
		if source != nil {
			return nil, fmt.Errorf("auth filestore: multiple prior credentials match login; reconcile duplicates before re-login")
		}
		source = &loginPolicySource{path: candidatePath, metadata: metadata}
	}
	// Existing destination policy wins over predecessor policy. Still reconcile
	// the predecessor on retries after a partial-success retirement failure.
	policies := []map[string]any{destinationPolicy}
	if source != nil {
		policies = append(policies, source.metadata)
	}
	for policyIndex, policy := range policies {
		for _, key := range loginPolicyFields {
			if _, explicit := auth.Metadata[key]; explicit {
				continue
			}
			if value, exists := policy[key]; exists {
				auth.Metadata[key] = value
				if source != nil && policyIndex > 0 {
					source.carried = append(source.carried, key)
				}
			}
		}
	}
	if value, exists := auth.Metadata["disabled"]; exists {
		disabled, ok := value.(bool)
		if !ok {
			return nil, fmt.Errorf("auth filestore: disabled policy must be a boolean")
		}
		auth.Disabled = disabled
		if disabled {
			auth.Status = coreauth.StatusDisabled
		} else if auth.Status == coreauth.StatusDisabled {
			auth.Status = coreauth.StatusActive
		}
	}
	if prefix, ok := auth.Metadata["prefix"].(string); ok {
		auth.Prefix = strings.Trim(strings.TrimSpace(prefix), "/")
	}
	if errWeight := coreauth.ApplyAuthWeightMetadata(auth, auth.Metadata); errWeight != nil {
		return nil, fmt.Errorf("auth filestore: inherited policy: %w", errWeight)
	}
	coreauth.ApplyAuthPriorityMetadata(auth, auth.Metadata)
	return source, nil
}

func readLoginPolicy(path string) (map[string]any, error) {
	raw, errRead := os.ReadFile(path)
	if errRead != nil {
		return nil, errRead
	}
	if !ojson.ValidBytes(raw) {
		return nil, fmt.Errorf("auth filestore: invalid prior credential JSON in %s", filepath.Base(path))
	}
	metadata, ok := ojson.ParseBytes(raw).Value().(map[string]any)
	if !ok {
		return nil, fmt.Errorf("auth filestore: prior credential is not an object in %s", filepath.Base(path))
	}
	return metadata, nil
}

func loginPolicyProvider(provider string) string {
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "gemini" {
		return "gemini-cli"
	}
	return provider
}

func loginAccountConflicts(provider string, auth *coreauth.Auth, candidate map[string]any) bool {
	if candidateProvider := loginPolicyProvider(metadataStringValue(candidate, "type")); candidateProvider != "" && candidateProvider != provider {
		return true
	}
	for _, key := range []string{"account_id", "account_uuid", "organization_uuid", "sub", "email"} {
		left, right := metadataStringValue(auth.Metadata, key), metadataStringValue(candidate, key)
		if storage, ok := auth.Storage.(*codex.CodexTokenStorage); ok && key == "account_id" && left == "" {
			left = strings.TrimSpace(storage.AccountID)
		}
		if key == "email" {
			left, right = strings.ToLower(left), strings.ToLower(right)
		}
		if left != "" && right != "" && left != right {
			return true
		}
	}
	return false
}

func sameLoginAccount(provider, path string, auth *coreauth.Auth, candidatePath string, candidate map[string]any) bool {
	if provider != loginPolicyProvider(metadataStringValue(candidate, "type")) {
		return false
	}
	incoming := auth.Metadata
	leftEmail, rightEmail := metadataStringValue(incoming, "email"), metadataStringValue(candidate, "email")
	// Workspace/account identifiers may be shared by distinct users.
	if leftEmail != "" && rightEmail != "" && !strings.EqualFold(leftEmail, rightEmail) {
		return false
	}
	if provider == "claude" && metadataStringValue(incoming, "organization_uuid") != "" && metadataStringValue(candidate, "organization_uuid") == "" {
		// Mirror the legacy migrator: an org-less credential is ambiguous,
		// except for the exact account-hashed predecessor of an org-hashed login.
		account := metadataStringValue(incoming, "account_uuid")
		organization := metadataStringValue(incoming, "organization_uuid")
		if leftEmail == "" || account == "" || !strings.EqualFold(metadataStringValue(candidate, "account_uuid"), account) ||
			!strings.EqualFold(filepath.Base(candidatePath), claude.CredentialFileName(leftEmail, "", account)) ||
			!strings.EqualFold(filepath.Base(path), claude.CredentialFileName(leftEmail, organization, account)) {
			return false
		}
	}
	accountID := metadataStringValue(incoming, "account_id")
	if storage, ok := auth.Storage.(*codex.CodexTokenStorage); ok && accountID == "" {
		accountID = strings.TrimSpace(storage.AccountID)
	}
	matchedID := false
	for _, key := range []string{"account_id", "account_uuid", "organization_uuid", "sub", "project_id"} {
		left := metadataStringValue(incoming, key)
		if key == "account_id" {
			left = accountID
		}
		right := metadataStringValue(candidate, key)
		if left != "" && right != "" {
			// Organization/project conflicts veto an email or account match.
			if left != right {
				return false
			}
			if key != "project_id" && key != "organization_uuid" {
				matchedID = true
			}
		}
	}
	if provider == "codex" {
		left, right := codexLoginHash(path), codexLoginHash(candidatePath)
		if left != "" && right != "" {
			if left != right {
				return false
			}
			matchedID = true
		}
	}
	if matchedID {
		return true
	}
	left, right := metadataStringValue(incoming, "email"), metadataStringValue(candidate, "email")
	return left != "" && right != "" && strings.EqualFold(left, right)
}

func codexLoginHash(path string) string {
	parts := strings.SplitN(filepath.Base(path), "-", 3)
	if len(parts) != 3 || parts[0] != "codex" || len(parts[1]) != 8 {
		return ""
	}
	for _, r := range parts[1] {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return ""
		}
	}
	return parts[1]
}

// Archive only after the replacement was saved successfully. A non-JSON suffix
// keeps backups out of both the watcher and FileTokenStore.List, even recursively.
// Unique names retain every prior grant and avoid poisoning the next login with
// a disabled flag added solely for retirement.
func sameLoginFile(left, right string) bool {
	if filepath.Clean(left) == filepath.Clean(right) {
		return true
	}
	leftInfo, leftErr := os.Stat(left)
	rightInfo, rightErr := os.Stat(right)
	if leftErr != nil || rightErr != nil || !os.SameFile(leftInfo, rightInfo) {
		return false
	}
	// A case-insensitive filesystem has one directory entry for both spellings.
	// Distinct hard-link entries are predecessors, not aliases: atomic token
	// replacement breaks their link and would otherwise leave stale JSON active.
	leftName, rightName := filepath.Base(left), filepath.Base(right)
	if leftName != rightName {
		entries, errEntries := os.ReadDir(filepath.Dir(right))
		if errEntries != nil {
			return false
		}
		leftExists, rightExists := false, false
		for _, entry := range entries {
			leftExists = leftExists || entry.Name() == leftName
			rightExists = rightExists || entry.Name() == rightName
		}
		if leftExists && rightExists {
			return false
		}
	}
	return true
}

func loginRetirementFence(path string) string {
	return path + ".retired"
}

func retireLoginPolicySource(path string, source *loginPolicySource) error {
	if source == nil || sameLoginFile(source.path, path) {
		return nil
	}
	// Codex executors may persist refreshes directly under the credential lock
	// before calling the store. Wait for those writes before retiring the path.
	return codex.WithFileLock(source.path, func() error {
		return archiveLoginPolicySource(path, source)
	})
}

func archiveLoginPolicySource(path string, source *loginPolicySource) error {
	backupDir := filepath.Join(filepath.Dir(path), "auth-backups")
	if errDir := os.MkdirAll(backupDir, 0o700); errDir != nil {
		return fmt.Errorf("auth filestore: replacement saved but prior credential backup directory failed: %w", errDir)
	}
	backup, errCreate := os.CreateTemp(backupDir, filepath.Base(source.path)+"-*.bak")
	if errCreate != nil {
		return fmt.Errorf("auth filestore: replacement saved but prior credential backup failed: %w", errCreate)
	}
	backupPath := backup.Name()
	if errClose := backup.Close(); errClose != nil {
		_ = os.Remove(backupPath)
		return errClose
	}
	// Persist the fence before moving the source. Later saves, including from a
	// different store/process, are ordered by the directory lock and cannot
	// recreate this path from an in-flight runtime snapshot. No secret is stored.
	if errFence := os.WriteFile(loginRetirementFence(source.path), nil, 0o600); errFence != nil {
		_ = os.Remove(backupPath)
		return fmt.Errorf("auth filestore: replacement saved but retirement fence failed: %w", errFence)
	}
	if errRename := os.Rename(source.path, backupPath); errRename != nil {
		_ = os.Remove(backupPath)
		return fmt.Errorf("auth filestore: replacement saved but prior credential retirement failed: %w", errRename)
	}
	log.WithFields(log.Fields{
		"carried_fields":   source.carried,
		"retired_file":     filepath.Base(source.path),
		"replacement_file": filepath.Base(path),
	}).Info("OAuth login operator policy carried forward; prior credential archived")
	return nil
}
