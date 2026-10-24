package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// SessionCookieName is the cookie that carries the session token.
const SessionCookieName = "session"

// SessionTTL is the absolute lifetime of a session. It is not extended by
// activity; after it the user logs in again (docs/decisions.md D27).
const SessionTTL = 8 * time.Hour

// tokenLen is the number of random bytes in a session token (256 bits).
const tokenLen = 32

// ErrSessionNotFound is returned by a session store for an unknown or
// expired session ID.
var ErrSessionNotFound = errors.New("auth: session not found")

// errSessionInvalid means the request carried a session cookie that does not
// match a live session: expired, logged out elsewhere, or forged.
var errSessionInvalid = errors.New("auth: invalid session")

// Session is a logged-in session as stored in the sessions collection.
//
// The cookie holds a random token; only HMAC-SHA256(SESSION_SECRET, token)
// is stored as ID, so someone who can read the database cannot reuse the
// IDs they see as cookies.
type Session struct {
	ID       []byte        `bson:"_id"`
	UserID   bson.ObjectID `bson:"user_id"`
	Username string        `bson:"username"`
	// JustLoggedIn is true until the first page load after login.
	JustLoggedIn bool      `bson:"just_logged_in,omitempty"`
	CreatedAt    time.Time `bson:"created_at"`
	// ExpiresAt drives the TTL index that deletes expired sessions.
	ExpiresAt time.Time `bson:"expires_at"`
}

// sessionStore is the persistence the session manager needs.
// *SessionStore satisfies it.
type sessionStore interface {
	Create(ctx context.Context, s *Session) error
	// Find returns the session with id if it expires after now.
	Find(ctx context.Context, id []byte, now time.Time) (*Session, error)
	ClearJustLoggedIn(ctx context.Context, id []byte) error
	Delete(ctx context.Context, id []byte) error
}

// SessionManager creates, loads and ends sessions. It uses net/http types
// only; the Gin glue is in middleware.go.
type SessionManager struct {
	store  sessionStore
	secret []byte
	secure bool
	now    func() time.Time
}

// NewSessionManager returns a manager that keys session IDs with secret and
// marks cookies Secure when secure is true (set it when served over HTTPS).
func NewSessionManager(store sessionStore, secret []byte, secure bool) *SessionManager {
	return &SessionManager{store: store, secret: secret, secure: secure, now: time.Now}
}

// Start creates a session for u and sets its cookie on w. Call Revoke for
// any existing session first, so every login gets a fresh token.
func (m *SessionManager) Start(ctx context.Context, w http.ResponseWriter, u *User) error {
	raw := make([]byte, tokenLen)
	if _, err := rand.Read(raw); err != nil {
		return fmt.Errorf("auth: generate session token: %w", err)
	}
	now := m.now().UTC()
	s := &Session{
		ID:           m.sessionID(raw),
		UserID:       u.ID,
		Username:     u.Username,
		JustLoggedIn: true,
		CreatedAt:    now,
		ExpiresAt:    now.Add(SessionTTL),
	}
	if err := m.store.Create(ctx, s); err != nil {
		return fmt.Errorf("auth: create session: %w", err)
	}
	http.SetCookie(w, m.cookie(base64.RawURLEncoding.EncodeToString(raw), int(SessionTTL/time.Second)))
	return nil
}

// Load returns the session named by r's cookie. It returns (nil, nil) when
// there is no cookie and errSessionInvalid when the cookie matches no live
// session. The first Load after login reports JustLoggedIn and clears it.
func (m *SessionManager) Load(ctx context.Context, r *http.Request) (*Session, error) {
	id, ok := m.idFromRequest(r)
	if !ok {
		if _, err := r.Cookie(SessionCookieName); err == nil {
			return nil, errSessionInvalid // present but malformed
		}
		return nil, nil
	}
	s, err := m.store.Find(ctx, id, m.now())
	if errors.Is(err, ErrSessionNotFound) {
		return nil, errSessionInvalid
	}
	if err != nil {
		return nil, fmt.Errorf("auth: load session: %w", err)
	}
	if s.JustLoggedIn {
		if err := m.store.ClearJustLoggedIn(ctx, id); err != nil {
			return nil, fmt.Errorf("auth: update session: %w", err)
		}
	}
	return s, nil
}

// End deletes the session named by r's cookie, if any, and expires the
// cookie on w.
func (m *SessionManager) End(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	m.ClearCookie(w)
	return m.Revoke(ctx, r)
}

// Revoke deletes the session named by r's cookie, if any, without touching
// the cookie. Login uses it before Start, which overwrites the cookie.
func (m *SessionManager) Revoke(ctx context.Context, r *http.Request) error {
	id, ok := m.idFromRequest(r)
	if !ok {
		return nil
	}
	if err := m.store.Delete(ctx, id); err != nil {
		return fmt.Errorf("auth: delete session: %w", err)
	}
	return nil
}

// ClearCookie tells the browser to drop the session cookie.
func (m *SessionManager) ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, m.cookie("", -1))
}

// Secure reports whether cookies are marked Secure.
func (m *SessionManager) Secure() bool {
	return m.secure
}

// cookie builds the session cookie. HttpOnly keeps it from JavaScript;
// SameSite=Strict keeps browsers from sending it on cross-site requests.
func (m *SessionManager) cookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{ // #nosec G124 -- Secure follows COOKIE_SECURE (docs/decisions.md D28); HttpOnly and SameSite=Strict are always set.
		Name:     SessionCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: http.SameSiteStrictMode,
	}
}

// idFromRequest decodes the cookie token and derives the stored ID.
func (m *SessionManager) idFromRequest(r *http.Request) ([]byte, bool) {
	c, err := r.Cookie(SessionCookieName)
	if err != nil {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil || len(raw) != tokenLen {
		return nil, false
	}
	return m.sessionID(raw), true
}

// sessionID is HMAC-SHA256(secret, token).
func (m *SessionManager) sessionID(token []byte) []byte {
	mac := hmac.New(sha256.New, m.secret)
	mac.Write(token)
	return mac.Sum(nil)
}
