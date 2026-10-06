package profile

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Handler serves the profile page.
type Handler struct {
	svc *Service
}

// NewHandler returns a Handler for svc.
func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// TODO(feature/private-data): read ?alg= with crypto.ParseAlgorithm, get
// the user with auth.CurrentUser, call h.svc.Get, and render profile.html
// (TODO(feature/frontend)).
func (h *Handler) show(c *gin.Context) {
	c.String(http.StatusNotImplemented, "not implemented")
}

// TODO(feature/private-data): bind PrivateData with c.ShouldBind, call
// h.svc.Save, and re-render. Never echo the NIK or other fields in logs.
func (h *Handler) save(c *gin.Context) {
	c.String(http.StatusNotImplemented, "not implemented")
}
