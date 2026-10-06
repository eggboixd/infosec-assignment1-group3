package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// registerForm is the validated input for POST /register.
type registerForm struct {
	Username string `form:"username" binding:"required,min=3,max=32,alphanum"`
	Password string `form:"password" binding:"required,min=12,max=128"`
	Confirm  string `form:"confirm" binding:"required,eqfield=Password"`
}

// loginForm is the validated input for POST /login.
type loginForm struct {
	Username string `form:"username" binding:"required,max=32"`
	Password string `form:"password" binding:"required,max=128"`
}

// Handler serves the auth pages. It only parses input, calls the Service,
// and writes responses.
type Handler struct {
	svc *Service
}

// NewHandler returns a Handler for svc.
func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// TODO(feature/frontend): render register.html.
func (h *Handler) showRegister(c *gin.Context) {
	c.String(http.StatusNotImplemented, "not implemented")
}

// TODO(feature/auth): bind registerForm with c.ShouldBind, call
// h.svc.Register, then redirect to /login.
func (h *Handler) register(c *gin.Context) {
	c.String(http.StatusNotImplemented, "not implemented")
}

// TODO(feature/frontend): render login.html.
func (h *Handler) showLogin(c *gin.Context) {
	c.String(http.StatusNotImplemented, "not implemented")
}

// TODO(feature/auth): bind loginForm, call h.svc.Login, rotate the session
// ID, store the user ID in the session, then redirect to /files.
func (h *Handler) login(c *gin.Context) {
	c.String(http.StatusNotImplemented, "not implemented")
}

// TODO(feature/auth): clear and expire the session, then redirect to /login.
func (h *Handler) logout(c *gin.Context) {
	c.String(http.StatusNotImplemented, "not implemented")
}
