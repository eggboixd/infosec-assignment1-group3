package sharing

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/eggboixd/infosec-assignment1-group3/internal/auth"
)

const (
	sharesTemplate = "shares.html"
	sharesTitle    = "Data sharing"
	msgCheckForm   = "Please check the form and try again."
	msgServer      = "Something went wrong on our side. Please try again."
	msgNotFound    = "We couldn't find that request."
)

// errorResponses maps service errors to a status and a fixed message. The
// messages never include user input or internal error text.
var errorResponses = []struct {
	err    error
	status int
	msg    string
}{
	{ErrUserNotFound, http.StatusNotFound, "No user with that username."},
	{ErrSelfRequest, http.StatusBadRequest, "You can't request your own data."},
	{ErrReasonTooLong, http.StatusBadRequest, "Keep the reason under 200 characters."},
	{ErrBadDuration, http.StatusBadRequest, "Choose 1, 7 or 30 days."},
	{ErrAlreadyOpen, http.StatusConflict, "You already have an open request to this user."},
	{ErrTooManyPending, http.StatusConflict, "You have 20 pending requests. Wait for answers or cancel some."},
	{ErrNotPending, http.StatusConflict, "That request has already been answered."},
	{ErrNotApproved, http.StatusConflict, "That request has already been answered."},
	{ErrExpired, http.StatusConflict, "That request has expired."},
	{ErrRequesterKeys, http.StatusConflict, "The requester's public key couldn't be verified, so no share key was made."},
	{ErrGrant, http.StatusInternalServerError, "Couldn't create the share key. Please try again."},
	{ErrRateLimited, http.StatusTooManyRequests, "Too many requests. Try again in an hour."},
	{ErrNotFound, http.StatusNotFound, msgNotFound},
}

// doneMessages are the success messages after a redirect. The query value is
// only a code, so a forged link can at most show one of these texts.
var doneMessages = map[string]string{
	"sent":      "Request sent. You'll see the answer under \"Your requests\".",
	"approved":  "Access approved.",
	"rejected":  "Request rejected.",
	"revoked":   "Access revoked.",
	"cancelled": "Request cancelled.",
}

// durationOption is one choice in the approve form.
type durationOption struct {
	Value, Label string
}

var durationOptions = []durationOption{{"1d", "1 day"}, {"7d", "7 days"}, {"30d", "30 days"}}

// Handler serves /shares.
type Handler struct {
	svc *Service
}

// NewHandler returns a Handler for svc.
func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

type sendForm struct {
	Username string `form:"username" binding:"max=64"`
	Reason   string `form:"reason" binding:"max=1000"`
}

type approveForm struct {
	Duration string `form:"duration" binding:"max=8"`
}

// show handles GET /shares.
func (h *Handler) show(c *gin.Context) {
	var flash *auth.Flash
	if msg, ok := doneMessages[c.Query("done")]; ok {
		flash = &auth.Flash{Kind: "success", Message: msg}
	}
	h.render(c, http.StatusOK, flash)
}

// send handles POST /shares/requests. Never log the form: the reason is user text.
func (h *Handler) send(c *gin.Context) {
	user := mustUser(c)
	var f sendForm
	if err := c.ShouldBind(&f); err != nil {
		h.render(c, http.StatusBadRequest, errFlash(msgCheckForm))
		return
	}
	_, err := h.svc.Send(c.Request.Context(), user, f.Username, f.Reason)
	h.finish(c, user, err, "sent")
}

// approve handles POST /shares/requests/:id/approve.
func (h *Handler) approve(c *gin.Context) {
	user := mustUser(c)
	id, ok := h.requestID(c)
	if !ok {
		return
	}
	var f approveForm
	if err := c.ShouldBind(&f); err != nil {
		h.render(c, http.StatusBadRequest, errFlash(msgCheckForm))
		return
	}
	_, err := h.svc.Approve(c.Request.Context(), user.ID, id, f.Duration)
	h.finish(c, user, err, "approved")
}

// action returns a handler for an action that takes only the request ID.
func (h *Handler) action(do func(s *Service) func(c *gin.Context, userID, id bson.ObjectID) error, done string) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := mustUser(c)
		id, ok := h.requestID(c)
		if !ok {
			return
		}
		h.finish(c, user, do(h.svc)(c, user.ID, id), done)
	}
}

func reject(s *Service) func(c *gin.Context, userID, id bson.ObjectID) error {
	return func(c *gin.Context, userID, id bson.ObjectID) error { return s.Reject(c.Request.Context(), userID, id) }
}

func revoke(s *Service) func(c *gin.Context, userID, id bson.ObjectID) error {
	return func(c *gin.Context, userID, id bson.ObjectID) error { return s.Revoke(c.Request.Context(), userID, id) }
}

func cancel(s *Service) func(c *gin.Context, userID, id bson.ObjectID) error {
	return func(c *gin.Context, userID, id bson.ObjectID) error { return s.Cancel(c.Request.Context(), userID, id) }
}

// requestID parses :id. An invalid ID is the same 404 as an unknown one.
func (h *Handler) requestID(c *gin.Context) (bson.ObjectID, bool) {
	id, err := bson.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		h.render(c, http.StatusNotFound, errFlash(msgNotFound))
		return bson.ObjectID{}, false
	}
	return id, true
}

// finish redirects on success (Post/Redirect/Get) or re-renders the page
// with the error's message.
func (h *Handler) finish(c *gin.Context, user *auth.User, err error, done string) {
	if err == nil {
		c.Redirect(http.StatusSeeOther, "/shares?done="+done)
		return
	}
	for _, r := range errorResponses {
		if errors.Is(err, r.err) {
			h.render(c, r.status, errFlash(r.msg))
			return
		}
	}
	slog.Error("sharing: action failed", "user_id", user.ID.Hex(), "done", done, "error", err)
	h.render(c, http.StatusInternalServerError, errFlash(msgServer))
}

// render shows shares.html with the user's inbox and sent requests.
func (h *Handler) render(c *gin.Context, status int, flash *auth.Flash) {
	user := mustUser(c)
	ctx := c.Request.Context()
	inbox, err := h.svc.Inbox(ctx, user.ID)
	if err == nil {
		var sent []View
		sent, err = h.svc.Sent(ctx, user.ID)
		if err == nil {
			c.HTML(status, sharesTemplate, gin.H{
				"Title":        sharesTitle,
				"User":         user,
				"Flash":        flash,
				"JustLoggedIn": auth.JustLoggedIn(c),
				"Inbox":        inbox,
				"Sent":         sent,
				"Durations":    durationOptions,
				"Default":      DefaultDuration,
			})
			return
		}
	}
	slog.Error("sharing: load requests", "user_id", user.ID.Hex(), "error", err)
	c.HTML(http.StatusInternalServerError, "error.html", gin.H{
		"Title": "Error", "User": user, "Status": http.StatusInternalServerError, "Message": msgServer,
	})
}

func errFlash(msg string) *auth.Flash { return &auth.Flash{Kind: "error", Message: msg} }

// mustUser returns the logged-in user. RequireAuth guards every route here,
// so a missing user is a wiring bug: it gets an empty user and the request
// fails on its first lookup rather than panicking.
func mustUser(c *gin.Context) *auth.User {
	if u, ok := auth.CurrentUser(c); ok {
		return u
	}
	return &auth.User{}
}
