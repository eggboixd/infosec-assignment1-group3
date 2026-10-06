package profile

import "github.com/gin-gonic/gin"

// RegisterRoutes mounts the profile routes. All of them require login.
func (h *Handler) RegisterRoutes(_, protected *gin.RouterGroup) {
	protected.GET("/profile", h.show)
	protected.POST("/profile", h.save)
}
