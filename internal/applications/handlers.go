package applications

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/eggboixd/infosec-assignment1-group3/internal/auth"
)

// User-facing messages. They never name another user or internal errors.
const (
	msgNotFound     = "We couldn't find that scholarship."
	msgClosed       = "This scholarship is closed. Applications are no longer accepted."
	msgNotReady     = "Your application is not complete yet. Fill in your applicant data and upload every document first."
	msgAlready      = "You have already applied to this scholarship."
	msgIntegrity    = "Your stored application failed its integrity check, so it was not shown."
	msgLoadFailed   = "Your application could not be loaded. Please try again."
	msgSubmitFailed = "Your application could not be submitted. Please try again."
)

// Handler serves the scholarship home page, the detail pages and submit.
type Handler struct {
	svc *Service
}

// NewHandler returns a Handler for svc.
func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// status loads what the cards show for the logged-in user, if any.
type status struct {
	user      *auth.User
	readiness Readiness
	submitted map[string]time.Time
}

func (h *Handler) loadStatus(c *gin.Context) (status, error) {
	user, ok := auth.CurrentUser(c)
	if !ok {
		return status{}, nil
	}
	ctx := c.Request.Context()
	r, err := h.svc.Readiness(ctx, user.ID)
	if err != nil {
		return status{user: user}, err
	}
	sub, err := h.svc.Submitted(ctx, user.ID)
	if err != nil {
		return status{user: user}, err
	}
	return status{user: user, readiness: r, submitted: sub}, nil
}

// home handles GET /: the landing page and scholarship grid for everyone.
// "/" is public, so RequireAuth does not run, but LoadSession has already
// stored the logged-in user, if any.
func (h *Handler) home(c *gin.Context) {
	st, err := h.loadStatus(c)
	if err != nil {
		h.loadError(c, st.user, err)
		return
	}
	c.HTML(http.StatusOK, "home.html", gin.H{
		"Title":        "",
		"User":         st.user,
		"Cards":        BuildCards(st.user != nil, st.readiness, st.submitted, h.svc.Now()),
		"JustLoggedIn": auth.JustLoggedIn(c),
		"Flash":        auth.TakeFlash(c),
	})
}

// show handles GET /scholarships/:id.
func (h *Handler) show(c *gin.Context) {
	s, ok := Find(c.Param("id"))
	if !ok {
		user, _ := auth.CurrentUser(c)
		renderError(c, http.StatusNotFound, user, msgNotFound)
		return
	}
	st, err := h.loadStatus(c)
	if err != nil {
		h.loadError(c, st.user, err)
		return
	}
	h.renderDetail(c, http.StatusOK, s, st, "")
}

// apply handles POST /scholarships/:id/apply. On success it redirects
// (Post/Redirect/Get) to the detail page, whose "Submitted" seal is the
// confirmation read back from MongoDB.
func (h *Handler) apply(c *gin.Context) {
	user, ok := auth.CurrentUser(c)
	if !ok {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	s, ok := Find(c.Param("id"))
	if !ok {
		renderError(c, http.StatusNotFound, user, msgNotFound)
		return
	}

	err := h.svc.Submit(c.Request.Context(), user.ID, s.ID)
	var status int
	var msg string
	switch {
	case err == nil:
		slog.Info("applications: submitted", "user_id", user.ID.Hex())
		c.Redirect(http.StatusSeeOther, "/scholarships/"+s.ID)
		return
	case errors.Is(err, ErrAlreadyApplied):
		status, msg = http.StatusConflict, msgAlready
	case errors.Is(err, ErrNotReady):
		status, msg = http.StatusUnprocessableEntity, msgNotReady
	case errors.Is(err, ErrClosed):
		status, msg = http.StatusUnprocessableEntity, msgClosed
	default:
		// Which scholarship is private, so it is not logged.
		slog.Error("applications: submit", "user_id", user.ID.Hex(), "error", err)
		status, msg = http.StatusInternalServerError, msgSubmitFailed
	}

	st, err := h.loadStatus(c)
	if err != nil {
		h.loadError(c, user, err)
		return
	}
	h.renderDetail(c, status, s, st, msg)
}

// renderDetail passes exactly the data scholarship.html documents.
func (h *Handler) renderDetail(c *gin.Context, code int, s Scholarship, st status, errMsg string) {
	card := buildCard(s, st.user != nil, st.readiness, st.submitted, h.svc.Now())
	c.HTML(code, "scholarship.html", gin.H{
		"Title":     s.Name,
		"User":      st.user,
		"Card":      card,
		"Readiness": st.readiness,
		"Error":     errMsg,
	})
}

func (h *Handler) loadError(c *gin.Context, user *auth.User, err error) {
	if IsIntegrityError(err) {
		slog.Warn("applications: integrity check failed", "user_id", user.ID.Hex(), "error", err)
		renderError(c, http.StatusUnprocessableEntity, user, msgIntegrity)
		return
	}
	slog.Error("applications: load", "user_id", user.ID.Hex(), "error", err)
	renderError(c, http.StatusInternalServerError, user, msgLoadFailed)
}

// renderError shows error.html with a fixed, user-facing message.
func renderError(c *gin.Context, code int, user *auth.User, msg string) {
	c.HTML(code, "error.html", gin.H{
		"Title":   "Error",
		"User":    user,
		"Status":  code,
		"Message": msg,
	})
}
