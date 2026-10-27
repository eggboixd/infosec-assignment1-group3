package profile

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/eggboixd/infosec-assignment1-group3/internal/auth"
	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
)

// User-facing messages. They never include submitted values or internal
// error text.
const (
	msgUnknownAlg   = "Unknown algorithm. Choose AES-256, DES or RC4."
	msgNIKTaken     = "This NIK is already registered to another account."
	msgCheckForm    = "Please check the form and try again."
	msgSaveFailed   = "Your data could not be saved. Please try again."
	msgIntegrity    = "Your stored data failed its integrity check, so it was not shown."
	msgLoadFailed   = "Your data could not be loaded. Please try again."
	profileTemplate = "profile.html"
	profileTitle    = "Applicant data"
)

// Handler serves the profile page.
type Handler struct {
	svc *Service
}

// NewHandler returns a Handler for svc.
func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// show handles GET /profile?alg=aes|des|rc4 (default aes): it decrypts the
// logged-in user's profile with the chosen algorithm's copy.
func (h *Handler) show(c *gin.Context) {
	user, ok := auth.CurrentUser(c)
	if !ok {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	alg, err := parseAlg(c.Query("alg"))
	if err != nil {
		h.render(c, http.StatusBadRequest, user, nil, crypto.AES, []string{msgUnknownAlg})
		return
	}

	data, err := h.svc.Get(c.Request.Context(), user.ID, alg)
	switch {
	case err == nil:
		h.render(c, http.StatusOK, user, data, alg, nil)
	case errors.Is(err, ErrNotFound):
		// Nothing stored yet: empty form, sleepy Gembi.
		h.render(c, http.StatusOK, user, nil, alg, nil)
	case errors.Is(err, crypto.ErrAuthentication), errors.Is(err, ErrCorrupt):
		// Log who and which copy, never what. err holds no field values.
		slog.Warn("profile: integrity check failed", "user_id", user.ID.Hex(), "alg", alg, "error", err)
		renderError(c, http.StatusUnprocessableEntity, user, msgIntegrity)
	default:
		slog.Error("profile: load", "user_id", user.ID.Hex(), "alg", alg, "error", err)
		renderError(c, http.StatusInternalServerError, user, msgLoadFailed)
	}
}

// save handles POST /profile. On success it redirects (Post/Redirect/Get)
// so the page shows the data decrypted back from MongoDB, which is the
// confirmation, and a browser refresh does not resubmit the form.
//
// Never log the bound struct or any field: they are personal data.
func (h *Handler) save(c *gin.Context) {
	user, ok := auth.CurrentUser(c)
	if !ok {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	var data PrivateData
	if err := c.ShouldBind(&data); err != nil {
		// The binding tags are the first gate. Gin's messages are developer
		// text ("Key: 'PrivateData.NIK' Error:..."), so build friendly ones
		// from the same rules instead. The struct is still filled, so the
		// form is re-rendered with what the user typed.
		data.normalize()
		msgs := []string{msgCheckForm}
		var verr *ValidationError
		if errors.As(validate(data, h.svc.now()), &verr) {
			msgs = verr.Messages
		}
		h.render(c, http.StatusUnprocessableEntity, user, &data, crypto.AES, msgs)
		return
	}

	err := h.svc.Save(c.Request.Context(), user.ID, data)
	var verr *ValidationError
	switch {
	case err == nil:
		c.Redirect(http.StatusSeeOther, "/profile?alg="+string(crypto.AES))
	case errors.As(err, &verr):
		data.normalize()
		h.render(c, http.StatusUnprocessableEntity, user, &data, crypto.AES, verr.Messages)
	case errors.Is(err, ErrNIKTaken):
		// Doesn't say whose account has it.
		data.normalize()
		h.render(c, http.StatusConflict, user, &data, crypto.AES, []string{msgNIKTaken})
	default:
		slog.Error("profile: save", "user_id", user.ID.Hex(), "error", err)
		data.normalize()
		h.render(c, http.StatusInternalServerError, user, &data, crypto.AES, []string{msgSaveFailed})
	}
}

// parseAlg reads the ?alg= value; empty means AES, the page's default.
func parseAlg(s string) (crypto.Algorithm, error) {
	if s == "" {
		return crypto.AES, nil
	}
	return crypto.ParseAlgorithm(s)
}

// render passes exactly the data profile.html and layout.html document:
// .Title, .User, .Profile, .Alg and .Errors.
func (h *Handler) render(c *gin.Context, status int, user *auth.User, data *PrivateData, alg crypto.Algorithm, errs []string) {
	c.HTML(status, profileTemplate, gin.H{
		"Title":   profileTitle,
		"User":    user,
		"Profile": data,
		"Alg":     string(alg),
		"Errors":  errs,
	})
}

// renderError shows error.html with a fixed, user-facing message.
func renderError(c *gin.Context, status int, user *auth.User, msg string) {
	c.HTML(status, "error.html", gin.H{
		"Title":   "Error",
		"User":    user,
		"Status":  status,
		"Message": msg,
	})
}
