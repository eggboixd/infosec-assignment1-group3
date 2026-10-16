package auth

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

// gin.Context keys set by LoadSession.
const (
	userKey         = "auth.user"
	justLoggedInKey = "auth.just_logged_in"
	expiredKey      = "auth.session_expired"
	secureKey       = "auth.cookie_secure"
)

// LoadSession resolves the session cookie on every request and stores the
// logged-in user for CurrentUser. It never rejects a request; RequireAuth
// does that for protected routes. Static files and the health check skip
// the database lookup.
func LoadSession(m *SessionManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(secureKey, m.Secure())
		p := c.Request.URL.Path
		if strings.HasPrefix(p, "/static/") || p == "/healthz" {
			c.Next()
			return
		}
		s, err := m.Load(c.Request.Context(), c.Request)
		switch {
		case err == nil && s != nil:
			c.Set(userKey, &User{ID: s.UserID, Username: s.Username})
			if s.JustLoggedIn {
				c.Set(justLoggedInKey, true)
			}
		case errors.Is(err, errSessionInvalid):
			m.ClearCookie(c.Writer)
			c.Set(expiredKey, true)
		case err != nil:
			// The database is unreachable: treat the request as logged out.
			// /healthz reports the outage.
			slog.Error("auth: load session", "error", err)
		}
		c.Next()
	}
}

// RequireAuth rejects requests without a logged-in user. Browsers are
// redirected to /login; htmx requests get 401 with HX-Redirect, because
// htmx would otherwise swap the login page into the current one.
func RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		if _, ok := CurrentUser(c); ok {
			c.Next()
			return
		}
		if c.GetBool(expiredKey) {
			setFlash(c.Writer, flashExpired, c.GetBool(secureKey))
		}
		if c.GetHeader("HX-Request") == "true" {
			c.Header("HX-Redirect", "/login")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Redirect(http.StatusSeeOther, "/login")
		c.Abort()
	}
}

// CurrentUser returns the logged-in user stored by LoadSession. Only ID and
// Username are set; the password hash is never loaded per request.
func CurrentUser(c *gin.Context) (*User, bool) {
	v, ok := c.Get(userKey)
	if !ok {
		return nil, false
	}
	u, ok := v.(*User)
	return u, ok && u != nil
}

// SetCurrentUser stores u as the logged-in user. LoadSession is the only
// production caller; tests of other packages use it to simulate a login.
func SetCurrentUser(c *gin.Context, u *User) {
	c.Set(userKey, u)
}

// JustLoggedIn reports whether this is the first page load after login, so
// the files page can play Gembi's unlock animation once.
func JustLoggedIn(c *gin.Context) bool {
	return c.GetBool(justLoggedInKey)
}

// TakeFlash returns the pending one-time message, if any, and clears it.
func TakeFlash(c *gin.Context) *Flash {
	return takeFlash(c.Writer, c.Request, c.GetBool(secureKey))
}

// rateLimit allows limit attempts per client IP per window. Over the limit
// it calls reject, which renders the page with a 429.
func rateLimit(l *rateLimiter, reject func(c *gin.Context)) gin.HandlerFunc {
	return func(c *gin.Context) {
		// ClientIP is the TCP peer: the engine trusts no proxy headers.
		ok, retry := l.allow(c.ClientIP())
		if ok {
			c.Next()
			return
		}
		secs := max(int(retry.Seconds()+0.999), 1)
		c.Header("Retry-After", strconv.Itoa(secs))
		slog.Warn("auth: rate limited", "path", c.FullPath(), "client_ip", c.ClientIP())
		reject(c)
		c.Abort()
	}
}
