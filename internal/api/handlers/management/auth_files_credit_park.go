package management

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/clienterror"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// ClearCodexCreditParkV8 manually releases an independently parked Codex API key.
func (h *Handler) ClearCodexCreditParkV8(c *gin.Context) {
	if h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "core auth manager unavailable"})
		return
	}
	var req struct {
		AuthIndex string `json:"auth_index"`
	}
	if errBind := c.ShouldBindJSON(&req); errBind != nil {
		c.JSON(clienterror.HTTPStatusFromErrorOr(errBind, http.StatusBadRequest), gin.H{"error": "invalid request body"})
		return
	}
	index := strings.TrimSpace(req.AuthIndex)
	if index == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "auth_index is required"})
		return
	}
	// Config entries that share a key and base URL can have the same public
	// index (for example when they use different proxies). Do not guess which
	// credential the operator meant to release.
	var target *coreauth.Auth
	for _, auth := range h.authManager.List() {
		if auth.EnsureIndex() != index {
			continue
		}
		if target != nil {
			c.JSON(http.StatusConflict, gin.H{"error": "auth_index matches multiple credentials"})
			return
		}
		target = auth
	}
	if target == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "auth not found"})
		return
	}
	cleared, errClear := h.authManager.ClearCodexCreditPark(c.Request.Context(), target)
	if errClear != nil {
		if targetErr, ok := errClear.(*coreauth.Error); ok {
			c.JSON(targetErr.HTTPStatus, gin.H{"error": targetErr.Message})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to clear Codex credit park"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "auth_index": index, "cleared": cleared})
}
