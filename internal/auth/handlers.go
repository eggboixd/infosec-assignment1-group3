package auth

import (
	"errors"
	"log/slog"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
)

// User-facing messages. They never include the submitted password.
const (
	msgUsernameRule  = "Username must be 3–32 letters or digits."
	msgPasswordMin   = "Password must be at least 12 characters."
	msgPasswordMax   = "Password must be at most 128 characters."
	msgConfirm       = "The two passwords don't match."
	msgUsernameTaken = "That username is already taken."
	msgCheckForm     = "Please check the form and try again."
	msgBadLogin      = "Wrong username or password."
	msgTooMany       = "Too many attempts. Please wait a minute and try again."
	msgServer        = "Something went wrong on our side. Please try again."
)

// homePath is where login sends the user: the scholarship grid, which shows
// the status of each application (docs/decisions-frontend.md 19).
const homePath = "/"

// Attempts allowed per client IP per minute (docs/decisions.md D29).
const (
	loginAttemptsPerMinute    = 10
	registerAttemptsPerMinute = 5
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

// Handler serves the auth pages. It only parses input, calls the Service
// and the SessionManager, and writes responses.
type Handler struct {
	svc           *Service
	sessions      *SessionManager
	loginLimit    *rateLimiter
	registerLimit *rateLimiter
}

// NewHandler returns a Handler for svc and sessions.
func NewHandler(svc *Service, sessions *SessionManager) *Handler {
	return &Handler{
		svc:           svc,
		sessions:      sessions,
		loginLimit:    newRateLimiter(loginAttemptsPerMinute, time.Minute),
		registerLimit: newRateLimiter(registerAttemptsPerMinute, time.Minute),
	}
}

// showRegister renders the empty registration form, or sends a logged-in
// user to the scholarship home page.
func (h *Handler) showRegister(c *gin.Context) {
	if _, ok := CurrentUser(c); ok {
		c.Redirect(http.StatusSeeOther, homePath)
		return
	}
	h.renderRegister(c, http.StatusOK, "", nil)
}

// register handles POST /register. On success it redirects to /login with
// a one-time "Account created" message; it does not log the user in.
func (h *Handler) register(c *gin.Context) {
	var f registerForm
	if err := c.ShouldBind(&f); err != nil {
		h.renderRegister(c, http.StatusUnprocessableEntity, f.Username, registerErrors(f))
		return
	}
	u, err := h.svc.Register(c.Request.Context(), f.Username, f.Password)
	switch {
	case err == nil:
		slog.Info("auth: registered", "user_id", u.ID.Hex())
		setFlash(c.Writer, flashRegistered, h.sessions.Secure())
		c.Redirect(http.StatusSeeOther, "/login")
	case errors.Is(err, ErrUsernameTaken):
		h.renderRegister(c, http.StatusConflict, f.Username, []string{msgUsernameTaken})
	default:
		slog.Error("auth: register", "error", err)
		h.renderRegister(c, http.StatusInternalServerError, f.Username, []string{msgServer})
	}
}

// registerErrors turns the binding rules into friendly messages. Gin's own
// messages are developer text ("Key: 'registerForm.Username' Error:...").
func registerErrors(f registerForm) []string {
	var msgs []string
	if n := len(f.Username); n < 3 || n > 32 || !isAlnum(f.Username) {
		msgs = append(msgs, msgUsernameRule)
	}
	switch n := utf8.RuneCountInString(f.Password); {
	case n < 12:
		msgs = append(msgs, msgPasswordMin)
	case n > 128:
		msgs = append(msgs, msgPasswordMax)
	}
	if f.Confirm != f.Password {
		msgs = append(msgs, msgConfirm)
	}
	if len(msgs) == 0 {
		msgs = append(msgs, msgCheckForm)
	}
	return msgs
}

// isAlnum matches the binding tag "alphanum": ASCII letters and digits.
func isAlnum(s string) bool {
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

// showLogin renders the login form with any one-time message, or sends a
// logged-in user to the scholarship home page.
func (h *Handler) showLogin(c *gin.Context) {
	if _, ok := CurrentUser(c); ok {
		c.Redirect(http.StatusSeeOther, homePath)
		return
	}
	h.renderLogin(c, http.StatusOK, "", nil)
}

// login handles POST /login. Every failure shows the same message, so
// usernames can't be probed. On success any previous session is ended and
// a new one started (a fresh token on every login), then the user is sent
// to /files.
func (h *Handler) login(c *gin.Context) {
	var f loginForm
	if err := c.ShouldBind(&f); err != nil {
		h.renderLogin(c, http.StatusUnauthorized, f.Username, []string{msgBadLogin})
		return
	}
	ctx := c.Request.Context()
	u, err := h.svc.Login(ctx, f.Username, f.Password)
	switch {
	case errors.Is(err, ErrInvalidCredentials):
		slog.Info("auth: login failed", "client_ip", c.ClientIP())
		h.renderLogin(c, http.StatusUnauthorized, f.Username, []string{msgBadLogin})
		return
	case err != nil:
		slog.Error("auth: login", "error", err)
		h.renderLogin(c, http.StatusInternalServerError, f.Username, []string{msgServer})
		return
	}

	if err := h.sessions.Revoke(ctx, c.Request); err != nil {
		slog.Error("auth: revoke previous session", "error", err)
	}
	if err := h.sessions.Start(ctx, c.Writer, u); err != nil {
		slog.Error("auth: start session", "user_id", u.ID.Hex(), "error", err)
		h.renderLogin(c, http.StatusInternalServerError, f.Username, []string{msgServer})
		return
	}
	slog.Info("auth: logged in", "user_id", u.ID.Hex())
	c.Redirect(http.StatusSeeOther, homePath)
}

// logout handles POST /logout: it deletes the session server-side, expires
// the cookie, and redirects to /login.
func (h *Handler) logout(c *gin.Context) {
	if err := h.sessions.End(c.Request.Context(), c.Writer, c.Request); err != nil {
		slog.Error("auth: logout", "error", err)
	}
	setFlash(c.Writer, flashLoggedOut, h.sessions.Secure())
	c.Redirect(http.StatusSeeOther, "/login")
}

// tooManyLogins and tooManyRegisters render the form with a 429.
func (h *Handler) tooManyLogins(c *gin.Context) {
	h.renderLogin(c, http.StatusTooManyRequests, "", []string{msgTooMany})
}

func (h *Handler) tooManyRegisters(c *gin.Context) {
	h.renderRegister(c, http.StatusTooManyRequests, "", []string{msgTooMany})
}

// renderLogin and renderRegister pass exactly the data the templates
// document: .Title, .Errors, .Username and .Flash. The password is never
// echoed back.
func (h *Handler) renderLogin(c *gin.Context, status int, username string, errs []string) {
	c.HTML(status, "login.html", gin.H{
		"Title":    "Log in",
		"Errors":   errs,
		"Username": username,
		"Flash":    TakeFlash(c),
	})
}

func (h *Handler) renderRegister(c *gin.Context, status int, username string, errs []string) {
	c.HTML(status, "register.html", gin.H{
		"Title":    "Register",
		"Errors":   errs,
		"Username": username,
		"Flash":    TakeFlash(c),
	})
}
