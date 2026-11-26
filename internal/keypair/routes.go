package keypair

import "github.com/gin-gonic/gin"

// RegisterRoutes mounts the key routes. All of them require login.
func (h *Handler) RegisterRoutes(_, protected *gin.RouterGroup) {
	protected.GET("/keys/:purpose/public.pem", h.downloadPublic)
}
