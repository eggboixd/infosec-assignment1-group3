package sharekey

import "github.com/gin-gonic/gin"

// RegisterRoutes mounts the share-key routes. All of them require login.
func (h *Handler) RegisterRoutes(_, protected *gin.RouterGroup) {
	protected.GET("/shares/requests/:id/key", h.showKey)
	protected.GET("/shares/requests/:id/data", h.showData)
	protected.POST("/shares/requests/:id/import", h.importKey)
	protected.GET("/shares/requests/:id/files/:file", h.download)
}
