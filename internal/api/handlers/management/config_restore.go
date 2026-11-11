package management

import (
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

// Management reads never return a stored secret. They return a mask instead,
// and writes accept that mask back: a masked or omitted secret keeps its stored
// value, so a read/edit/write client (the control panel, a YAML editor, the TUI)
// can round-trip a config without deleting keys. Only an explicit new value, an
// explicit empty value, or removal of the whole entry changes or removes a secret.

// managementSecretMask prefixes every masked secret. It is ASCII so it is valid
// inside URL userinfo, and recognizable so writes can tell it from a real value.
const managementSecretMask = "***"

// maskManagementSecret hides a secret but keeps a short suffix so an operator
// can tell credentials apart: the last 4 characters of long secrets, the last 2
// of medium ones, nothing for short ones. Masking is idempotent.
func maskManagementSecret(value string) string {
	if value == "" || isManagementSecretMask(value) {
		return value
	}
	runes := []rune(value)
	switch {
	case len(runes) >= 16:
		return managementSecretMask + string(runes[len(runes)-4:])
	case len(runes) >= 8:
		return managementSecretMask + string(runes[len(runes)-2:])
	}
	return managementSecretMask
}

func maskManagementSecretList(items []any) []any {
	out := make([]any, len(items))
	for i, item := range items {
		if s, ok := item.(string); ok {
			out[i] = maskManagementSecret(s)
		} else {
			out[i] = item
		}
	}
	return out
}

func isManagementSecretMask(value string) bool {
	return strings.HasPrefix(strings.TrimSpace(value), managementSecretMask)
}

// isMaskableKey names keys whose string values (or string lists) are masked.
func isMaskableKey(key string) bool {
	return isReadOnlySecretKey(key) || isReadOnlySecretScalarKey(key)
}

// urlUserinfo returns the userinfo of a URL-shaped value and whether it has one.
func urlUserinfo(value string) (string, bool) {
	at := strings.LastIndex(value, "@")
	if at < 0 {
		return "", false
	}
	if i := strings.Index(value, "://"); i >= 0 && i < at {
		return value[i+3 : at], true
	}
	if scheme, rest, ok := strings.Cut(value, ":"); ok && isReadOnlyOpaqueURLScheme(scheme) && strings.Contains(rest, "@") {
		return rest[:strings.LastIndex(rest, "@")], true
	}
	return "", false
}

func isMaskedURLValue(value string) bool {
	info, ok := urlUserinfo(value)
	return ok && isManagementSecretMask(info)
}

// restoreMaskedURL swaps a masked userinfo for the stored one when the rest of
// the URL is free to change.
func restoreMaskedURL(incoming, previous string) (string, bool) {
	if incoming == redactReadOnlyProxyURL(previous) {
		return previous, true
	}
	prevInfo, ok := urlUserinfo(previous)
	if !ok {
		return incoming, false
	}
	inInfo, _ := urlUserinfo(incoming)
	if maskManagementSecret(prevInfo) != inInfo {
		return incoming, false
	}
	return strings.Replace(incoming, inInfo+"@", prevInfo+"@", 1), true
}

// maskedValueMatches reports whether a masked incoming value is the mask of a stored one.
func maskedValueMatches(key, incoming, previous string) bool {
	if isReadOnlyURLKey(key) && isMaskedURLValue(incoming) {
		_, ok := restoreMaskedURL(incoming, previous)
		return ok
	}
	return maskManagementSecret(previous) == strings.TrimSpace(incoming)
}

func isMaskedValue(key, value string) bool {
	if isReadOnlyURLKey(key) && !isMaskableKey(key) {
		return isMaskedURLValue(value)
	}
	return isManagementSecretMask(value)
}

// redactedIdentity identifies a config entry independently of its secrets: the
// stored entry and the client's masked copy of it redact to the same JSON.
func redactedIdentity(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	var copyValue any
	if json.Unmarshal(encoded, &copyValue) != nil {
		return ""
	}
	out, _ := json.Marshal(redactReadOnlyConfig(copyValue))
	return string(out)
}

// compatibleEntry decides whether an incoming map is an edited copy of a stored
// one: no masked secret may disagree, and at least one masked secret or one
// non-secret scalar must agree. A changed endpoint therefore never inherits the
// credentials of a different server.
func compatibleEntry(next, previous map[string]any) bool {
	agreed := false
	for key, nv := range next {
		ns, nOK := nv.(string)
		ps, pOK := previous[key].(string)
		if !nOK || !pOK {
			continue
		}
		switch {
		case isMaskedValue(key, ns):
			if !maskedValueMatches(key, ns, ps) {
				return false
			}
			agreed = true
		case !isMaskableKey(key) && ns == ps:
			agreed = true
		}
	}
	return agreed
}

// matchPrevious pairs incoming list items with stored ones: first by identical
// redacted identity, then by compatible entry preferring the same index. An
// unmatched item is new and gets no stored secrets.
func matchPrevious(next, old []any) []int {
	match := make([]int, len(next))
	used := make([]bool, len(old))
	ids := make([]string, len(old))
	for j := range old {
		ids[j] = redactedIdentity(old[j])
	}
	for i := range next {
		match[i] = -1
		id := redactedIdentity(next[i])
		for j := range old {
			if !used[j] && ids[j] == id {
				match[i], used[j] = j, true
				break
			}
		}
	}
	for i := range next {
		nm, isMap := next[i].(map[string]any)
		if match[i] >= 0 || !isMap {
			continue
		}
		candidates := make([]int, 0, len(old))
		if i < len(old) {
			candidates = append(candidates, i)
		}
		for j := range old {
			candidates = append(candidates, j)
		}
		for _, j := range candidates {
			if pm, ok := old[j].(map[string]any); ok && !used[j] && compatibleEntry(nm, pm) {
				match[i], used[j] = j, true
				break
			}
		}
	}
	return match
}

func restoreSecretStrings(next, old []any, key string) {
	used := make([]bool, len(old))
	for i, item := range next {
		s, ok := item.(string)
		if !ok || !isManagementSecretMask(s) {
			continue
		}
		for j, prev := range old {
			if ps, okPrev := prev.(string); okPrev && !used[j] && maskManagementSecret(ps) == strings.TrimSpace(s) {
				next[i], used[j] = ps, true
				break
			}
		}
	}
}

// restoreManagementSecrets is the write-side inverse of redactReadOnlyConfig.
// A secret leaf that is omitted, or that still holds its mask, keeps the stored
// value. Any other value, including an empty string or an empty list, is
// authoritative, and an entry the client dropped stays removed.
func restoreManagementSecrets(value, before any) any {
	switch next := value.(type) {
	case map[string]any:
		old, _ := before.(map[string]any)
		oldHasCredential := false
		for oldKey := range old {
			if normalizeReadOnlyKey(oldKey) == "credential" {
				oldHasCredential = true
			}
		}
		for key, previous := range old {
			incoming, present := next[key]
			if !present {
				if isReadOnlySecretKey(key) || (oldHasCredential && isReadOnlyUsernameKey(key)) {
					next[key] = previous
				}
				continue
			}
			switch in := incoming.(type) {
			case string:
				if ps, ok := previous.(string); ok && (isMaskedValue(key, in) || (oldHasCredential && isReadOnlyUsernameKey(key) && isManagementSecretMask(in))) {
					if isReadOnlyURLKey(key) && isMaskedURLValue(in) {
						if restored, okURL := restoreMaskedURL(in, ps); okURL {
							next[key] = restored
						}
					} else if maskedValueMatches(key, in, ps) {
						next[key] = ps
					}
				}
			case []any:
				if oldList, ok := previous.([]any); ok && isReadOnlySecretKey(key) && stringItems(in) && stringItems(oldList) {
					restoreSecretStrings(in, oldList, key)
				} else {
					next[key] = restoreManagementSecrets(in, previous)
				}
			default:
				next[key] = restoreManagementSecrets(incoming, previous)
			}
		}
	case []any:
		old, _ := before.([]any)
		match := matchPrevious(next, old)
		for i := range next {
			if match[i] >= 0 {
				next[i] = restoreManagementSecrets(next[i], old[match[i]])
			}
		}
	}
	return value
}

// unresolvedMask returns the key of a masked value that restore could not map to
// a stored secret. Persisting it would silently replace a real secret.
func unresolvedMask(value any) (string, bool) {
	switch item := value.(type) {
	case map[string]any:
		for key, child := range item {
			switch in := child.(type) {
			case string:
				if (isMaskableKey(key) && isManagementSecretMask(in)) || (isReadOnlyURLKey(key) && isMaskedURLValue(in)) {
					return key, true
				}
			case []any:
				if isReadOnlySecretKey(key) && stringItems(in) {
					for _, entry := range in {
						if s, ok := entry.(string); ok && isManagementSecretMask(s) {
							return key, true
						}
					}
					continue
				}
				if found, ok := unresolvedMask(in); ok {
					return found, true
				}
			default:
				if found, ok := unresolvedMask(in); ok {
					return found, true
				}
			}
		}
	case []any:
		for _, child := range item {
			if found, ok := unresolvedMask(child); ok {
				return found, true
			}
		}
	}
	return "", false
}

func errUnresolvedMask(key string) error {
	return fmt.Errorf("masked value for %q does not match a stored secret; send the full value or leave the field out", key)
}

// restoreManagementValue restores masked and omitted secrets in a decoded write
// payload and rejects any mask it cannot resolve.
func restoreManagementValue(incoming, previous any) (any, error) {
	restored := restoreManagementSecrets(incoming, previous)
	if key, bad := unresolvedMask(restored); bad {
		return nil, errUnresolvedMask(key)
	}
	return restored, nil
}

// restoreManagementJSONList restores secrets in a v0 list body, which is either
// a JSON array or {"items": [...]}, against the current list.
func restoreManagementJSONList(data []byte, current any) ([]byte, error) {
	var incoming any
	if json.Unmarshal(data, &incoming) != nil {
		return data, nil
	}
	encoded, err := json.Marshal(current)
	if err != nil {
		return data, nil
	}
	var previous any
	_ = json.Unmarshal(encoded, &previous)
	target := &incoming
	if obj, ok := incoming.(map[string]any); ok {
		items, hasItems := obj["items"]
		if !hasItems {
			return data, nil
		}
		restored, errRestore := restoreManagementValue(items, previous)
		if errRestore != nil {
			return nil, errRestore
		}
		obj["items"] = restored
	} else {
		restored, errRestore := restoreManagementValue(*target, previous)
		if errRestore != nil {
			return nil, errRestore
		}
		incoming = restored
	}
	return json.Marshal(incoming)
}

// restoreManagementYAMLBody restores secrets in a whole-config YAML write. The
// body is left byte-for-byte untouched when nothing needed restoring, so the
// writer keeps the author's comments and formatting.
func restoreManagementYAMLBody(body, current []byte) ([]byte, error) {
	var incoming, original, previous any
	if yaml.Unmarshal(body, &incoming) != nil || yaml.Unmarshal(body, &original) != nil {
		return body, nil
	}
	if yaml.Unmarshal(current, &previous) != nil {
		previous = nil
	}
	restored, err := restoreManagementValue(incoming, previous)
	if err != nil {
		return nil, err
	}
	if reflect.DeepEqual(original, restored) {
		return body, nil
	}
	out, errMarshal := yaml.Marshal(restored)
	if errMarshal != nil {
		return body, nil
	}
	return out, nil
}

// restoreReadOnlyYAMLNode applies the same restoration to a YAML tree, keeping
// comments and styles of everything the client sent.
func restoreReadOnlyYAMLNode(node, before *yaml.Node) error {
	preserveV8TURNSecrets(node, before)
	restoreYAMLNode(node, before)
	var decoded any
	if node != nil && node.Decode(&decoded) == nil {
		if key, bad := unresolvedMask(decoded); bad {
			return errUnresolvedMask(key)
		}
	}
	return nil
}

func yamlScalarString(node *yaml.Node) (string, bool) {
	if node == nil || node.Kind != yaml.ScalarNode || node.Tag == "!!null" {
		return "", false
	}
	return node.Value, true
}

func restoreYAMLNode(node, before *yaml.Node) {
	if node == nil || before == nil {
		return
	}
	switch {
	case node.Kind == yaml.MappingNode && before.Kind == yaml.MappingNode:
		oldHasCredential := false
		for i := 0; i+1 < len(before.Content); i += 2 {
			if normalizeReadOnlyKey(before.Content[i].Value) == "credential" {
				oldHasCredential = true
			}
		}
		for i := 0; i+1 < len(before.Content); i += 2 {
			key, previous := before.Content[i], before.Content[i+1]
			idx := -1
			for j := 0; j+1 < len(node.Content); j += 2 {
				if node.Content[j].Value == key.Value {
					idx = j
					break
				}
			}
			if idx < 0 {
				if isReadOnlySecretKey(key.Value) || (oldHasCredential && isReadOnlyUsernameKey(key.Value)) {
					node.Content = append(node.Content, cloneConfigV8Node(key), cloneConfigV8Node(previous))
				}
				continue
			}
			incoming := node.Content[idx+1]
			if in, ok := yamlScalarString(incoming); ok {
				if ps, okPrev := yamlScalarString(previous); okPrev && (isMaskedValue(key.Value, in) || (oldHasCredential && isReadOnlyUsernameKey(key.Value) && isManagementSecretMask(in))) {
					if isReadOnlyURLKey(key.Value) && isMaskedURLValue(in) {
						if restored, okURL := restoreMaskedURL(in, ps); okURL {
							incoming.Value = restored
						}
					} else if maskedValueMatches(key.Value, in, ps) {
						node.Content[idx+1] = cloneConfigV8Node(previous)
					}
				}
				continue
			}
			if incoming.Kind == yaml.SequenceNode && previous.Kind == yaml.SequenceNode && isReadOnlySecretKey(key.Value) && yamlAllScalars(incoming) && yamlAllScalars(previous) {
				next, old := yamlStringItems(incoming), yamlStringItems(previous)
				restoreSecretStrings(next, old, key.Value)
				for k, item := range next {
					if s, ok := item.(string); ok && k < len(incoming.Content) {
						incoming.Content[k].Value = s
					}
				}
				continue
			}
			restoreYAMLNode(incoming, previous)
		}
	case node.Kind == yaml.SequenceNode && before.Kind == yaml.SequenceNode:
		next, old := make([]any, len(node.Content)), make([]any, len(before.Content))
		for i, item := range node.Content {
			_ = item.Decode(&next[i])
		}
		for i, item := range before.Content {
			_ = item.Decode(&old[i])
		}
		for i, j := range matchPrevious(next, old) {
			if j >= 0 {
				restoreYAMLNode(node.Content[i], before.Content[j])
			}
		}
	}
}

func yamlStringItems(node *yaml.Node) []any {
	items := make([]any, len(node.Content))
	for i, item := range node.Content {
		if item.Kind == yaml.ScalarNode {
			items[i] = item.Value
		}
	}
	return items
}

// restoreListBody restores masked or omitted secrets in a v0 list PUT body (a
// JSON array or {"items": [...]}) against the current list. On an unresolvable
// mask it writes a 400 and returns false.
func (h *Handler) restoreListBody(c *gin.Context, data []byte, current func() any) ([]byte, bool) {
	var incoming any
	if json.Unmarshal(data, &incoming) != nil {
		return data, true
	}
	h.mu.Lock()
	encoded, _ := json.Marshal(current())
	h.mu.Unlock()
	var previous any
	_ = json.Unmarshal(encoded, &previous)
	var restored any
	var err error
	if obj, ok := incoming.(map[string]any); ok {
		items, has := obj["items"]
		if !has {
			return data, true
		}
		if obj["items"], err = restoreManagementValue(items, previous); err == nil {
			restored = obj
		}
	} else {
		restored, err = restoreManagementValue(incoming, previous)
	}
	if err != nil {
		c.JSON(400, gin.H{"error": "unresolved_masked_secret", "message": err.Error()})
		return nil, false
	}
	out, errMarshal := json.Marshal(restored)
	if errMarshal != nil {
		return data, true
	}
	return out, true
}

// dropMaskedPatchFields keeps a PATCH from overwriting a stored secret with its
// mask: a masked secret under "value" means "unchanged", so it is removed from
// the patch before the handler applies it.
func dropMaskedPatchFields(c *gin.Context) {
	if c.Request.Method != "PATCH" || c.Request.Body == nil {
		return
	}
	data, err := io.ReadAll(c.Request.Body)
	c.Request.Body = io.NopCloser(strings.NewReader(string(data)))
	if err != nil {
		return
	}
	var body map[string]any
	if json.Unmarshal(data, &body) != nil {
		return
	}
	if value, ok := body["value"].(map[string]any); ok && dropMaskedFields(value) {
		if out, errMarshal := json.Marshal(body); errMarshal == nil {
			c.Request.Body = io.NopCloser(strings.NewReader(string(out)))
		}
	}
}

func dropMaskedFields(item map[string]any) bool {
	changed := false
	for key, child := range item {
		switch in := child.(type) {
		case string:
			if isMaskedValue(key, in) {
				delete(item, key)
				changed = true
			}
		case map[string]any:
			changed = dropMaskedFields(in) || changed
		}
	}
	return changed
}

// RestoreMaskedPatchMiddleware applies dropMaskedPatchFields to v0 routes.
func (h *Handler) RestoreMaskedPatchMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		dropMaskedPatchFields(c)
		c.Next()
	}
}

// restoreMaskedStringList resolves masked entries of a string list (api-keys)
// to the stored values; unmatched masked entries are dropped so a mask is never
// persisted as a key.
func restoreMaskedStringList(next, old []string) []string {
	used := make([]bool, len(old))
	out := make([]string, 0, len(next))
	for _, item := range next {
		if !isManagementSecretMask(item) {
			out = append(out, item)
			continue
		}
		for j, prev := range old {
			if !used[j] && maskManagementSecret(prev) == strings.TrimSpace(item) {
				used[j] = true
				out = append(out, prev)
				break
			}
		}
	}
	return out
}

func containsMaskOf(stored []string, masked string) bool {
	for _, prev := range stored {
		if maskManagementSecret(prev) == strings.TrimSpace(masked) {
			return true
		}
	}
	return false
}

func stringItems(items []any) bool {
	for _, item := range items {
		if _, ok := item.(string); !ok {
			return false
		}
	}
	return true
}

func yamlAllScalars(node *yaml.Node) bool {
	for _, item := range node.Content {
		if item.Kind != yaml.ScalarNode {
			return false
		}
	}
	return true
}
