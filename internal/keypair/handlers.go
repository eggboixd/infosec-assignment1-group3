package keypair

import (
	"errors"
	"log/slog"
	"mime"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/eggboixd/infosec-assignment1-group3/internal/auth"
)

// User-facing messages. They never include key material or internal errors.
const (
	msgNotFound  = "You don't have that key yet. Key pairs are created when you log in."
	msgIntegrity = "Your stored public key failed its integrity check, so it was not sent."
	msgServer    = "Something went wrong on our side. Please try again."
)

// Handler serves the logged-in user's public keys.
type Handler struct {
	svc *Service
}

// NewHandler returns a Handler for svc.
func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// downloadPublic handles GET /keys/:purpose/public.pem. It only ever serves
// the logged-in user's own key: there is no user ID in the URL to change.
// Private keys have no download route at all.
func (h *Handler) downloadPublic(c *gin.Context) {
	user, ok := auth.CurrentUser(c)
	if !ok {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	p, err := ParsePurpose(c.Param("purpose"))
	if err != nil {
		renderError(c, user, http.StatusNotFound, "We couldn't find that page.")
		return
	}

	pub, err := h.svc.PublicKey(c.Request.Context(), user.ID, p)
	switch {
	case err == nil:
	case errors.Is(err, ErrNoKeys):
		renderError(c, user, http.StatusNotFound, msgNotFound)
		return
	case errors.Is(err, ErrCorrupt):
		slog.Warn("keypair: integrity check failed", "user_id", user.ID.Hex(), "purpose", p, "error", err)
		renderError(c, user, http.StatusUnprocessableEntity, msgIntegrity)
		return
	default:
		slog.Error("keypair: load public key", "user_id", user.ID.Hex(), "purpose", p, "error", err)
		renderError(c, user, http.StatusInternalServerError, msgServer)
		return
	}

	out, err := PublicKeyPEM(pub)
	if err != nil {
		slog.Error("keypair: encode public key", "user_id", user.ID.Hex(), "purpose", p, "error", err)
		renderError(c, user, http.StatusInternalServerError, msgServer)
		return
	}
	// Usernames are ASCII letters and digits, but FormatMediaType quotes the
	// name properly anyway. The file is a download, never rendered.
	name := "securestore-" + user.Username + "-" + string(p) + "-public.pem"
	hdr := c.Writer.Header()
	hdr.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	hdr.Set("Cache-Control", "no-store")
	c.Data(http.StatusOK, "application/x-pem-file", out)
}

// renderError shows error.html with a fixed, user-facing message.
func renderError(c *gin.Context, user *auth.User, status int, msg string) {
	c.HTML(status, "error.html", gin.H{
		"Title":   "Error",
		"User":    user,
		"Status":  status,
		"Message": msg,
	})
}
