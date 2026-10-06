package files

import "github.com/gin-gonic/gin"

// RegisterRoutes mounts the file routes. All of them require login.
func (h *Handler) RegisterRoutes(_, protected *gin.RouterGroup) {
	protected.GET("/files", h.list)
	protected.POST("/files", h.upload)
	protected.GET("/files/:id/download", h.download)
	protected.DELETE("/files/:id", h.remove)
}
