package sharing

import "github.com/gin-gonic/gin"

// RegisterRoutes mounts the share-request routes. All of them require login.
func (h *Handler) RegisterRoutes(_, protected *gin.RouterGroup) {
	protected.GET("/shares", h.show)
	protected.POST("/shares/requests", h.send)
	protected.POST("/shares/requests/:id/approve", h.approve)
	protected.POST("/shares/requests/:id/reject", h.action(reject, "rejected"))
	protected.POST("/shares/requests/:id/revoke", h.action(revoke, "revoked"))
	protected.POST("/shares/requests/:id/cancel", h.action(cancel, "cancelled"))
}
