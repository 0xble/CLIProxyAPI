package management

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestResolveMaskedAPIKeyRequiresUniqueMatch(t *testing.T) {
	gin.SetMode(gin.TestMode)
	entries := []struct{ key, base string }{
		{key: "prefix-1234", base: "https://one.example"},
		{key: "other-1234", base: "https://two.example"},
	}
	request := httptest.NewRequest(http.MethodDelete, "/?api-key=***34", nil)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = request
	if _, masked, ok := resolveMaskedAPIKey(c, "***34", len(entries), func(i int) string { return entries[i].key }, func(i int) string { return entries[i].base }); ok || !masked || rec.Code != http.StatusConflict {
		t.Fatalf("ambiguous mask: index/masked/ok=%v/%v/%v status=%d", -1, masked, ok, rec.Code)
	}
}

func TestResolveMaskedAPIKeyHonorsBaseURL(t *testing.T) {
	gin.SetMode(gin.TestMode)
	entries := []struct{ key, base string }{
		{key: "prefix-1234", base: "https://one.example"},
		{key: "other-1234", base: "https://two.example"},
	}
	request := httptest.NewRequest(http.MethodDelete, "/?api-key=***34&base-url=https://two.example", nil)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = request
	index, masked, ok := resolveMaskedAPIKey(c, "***34", len(entries), func(i int) string { return entries[i].key }, func(i int) string { return entries[i].base })
	if !ok || !masked || index != 1 {
		t.Fatalf("base-filtered mask: index/masked/ok=%d/%v/%v", index, masked, ok)
	}
}

func TestSecretSelectorPreservesRawDuplicateSemantics(t *testing.T) {
	if !secretSelectorMatches("same", "same") || secretSelectorMatches("***", "same") == false {
		t.Fatal("selector did not match raw or masked value")
	}
	if got := ambiguousSelectorStatus("same"); got != http.StatusBadRequest {
		t.Fatalf("raw duplicate status = %d", got)
	}
	if got := ambiguousSelectorStatus("***"); got != http.StatusConflict {
		t.Fatalf("masked duplicate status = %d", got)
	}
}
