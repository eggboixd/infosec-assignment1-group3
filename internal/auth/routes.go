package auth

import "github.com/gin-gonic/gin"

// RegisterRoutes mounts the auth routes. The POST routes are rate limited
// per client IP.
func (h *Handler) RegisterRoutes(public, protected *gin.RouterGroup) {
	public.GET("/register", h.showRegister)
	public.POST("/register", rateLimit(h.registerLimit, h.tooManyRegisters), h.register)
	public.GET("/login", h.showLogin)
	public.POST("/login", rateLimit(h.loginLimit, h.tooManyLogins), h.login)

	protected.POST("/logout", h.logout)
}
