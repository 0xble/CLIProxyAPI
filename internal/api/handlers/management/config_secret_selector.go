package management

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// Management reads return masked secrets, so a client that only ever saw a mask
// must still be able to name a stored entry. A selector is either the raw value
// (matched exactly, as before) or a mask that names exactly one stored entry.

// secretSelectorMatches reports whether selector names the stored secret: an
// exact match on the raw value, or a mask equal to the stored secret's mask.
func secretSelectorMatches(selector, stored string) bool {
	selector = strings.TrimSpace(selector)
	stored = strings.TrimSpace(stored)
	if selector == "" || stored == "" {
		return false
	}
	if selector == stored {
		return true
	}
	return isManagementSecretMask(selector) && maskManagementSecret(stored) == selector
}

// ambiguousSelectorStatus keeps the legacy 400 for a raw duplicate and uses 409
// for a mask that names several entries.
func ambiguousSelectorStatus(selector string) int {
	if isManagementSecretMask(selector) {
		return http.StatusConflict
	}
	return http.StatusBadRequest
}

// resolveMaskedAPIKey resolves a masked api-key selector (and the optional
// base-url query) to exactly one of count entries. A raw selector returns
// masked=false so the caller keeps its existing matching. For a mask it returns
// the unique index, or -1 when nothing matches; several matches write 409 and
// return ok=false.
func resolveMaskedAPIKey(c *gin.Context, selector string, count int, keyOf, baseOf func(int) string) (index int, masked, ok bool) {
	selector = strings.TrimSpace(selector)
	if !isManagementSecretMask(selector) {
		return -1, false, true
	}
	baseRaw, hasBase := c.GetQuery("base-url")
	base := strings.TrimSpace(baseRaw)
	index = -1
	matches := 0
	for i := 0; i < count; i++ {
		if hasBase && strings.TrimSpace(baseOf(i)) != base {
			continue
		}
		if secretSelectorMatches(selector, keyOf(i)) {
			matches++
			if index < 0 {
				index = i
			}
		}
	}
	if matches > 1 {
		c.JSON(http.StatusConflict, gin.H{"error": "ambiguous_masked_secret", "message": "masked api-key matches multiple entries; use index or the full value"})
		return -1, true, false
	}
	return index, true, true
}
