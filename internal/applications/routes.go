package applications

import "github.com/gin-gonic/gin"

// RegisterRoutes mounts the home page, the detail pages and submit. Only
// submitting requires login.
func (h *Handler) RegisterRoutes(public, protected *gin.RouterGroup) {
	public.GET("/", h.home)
	public.GET("/scholarships/:id", h.show)
	protected.POST("/scholarships/:id/apply", h.apply)
}
