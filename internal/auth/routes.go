package auth

import "github.com/gin-gonic/gin"

// RegisterRoutes mounts the auth routes.
func (h *Handler) RegisterRoutes(public, protected *gin.RouterGroup) {
	public.GET("/register", h.showRegister)
	public.POST("/register", h.register)
	public.GET("/login", h.showLogin)
	public.POST("/login", h.login)

	protected.POST("/logout", h.logout)
}
