package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// memSessions is an in-memory sessionStore.
type memSessions struct {
	mu       sync.Mutex
	sessions map[string]Session
}

func newMemSessions() *memSessions { return &memSessions{sessions: map[string]Session{}} }

func (m *memSessions) Create(_ context.Context, s *Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[string(s.ID)] = *s
	return nil
}

func (m *memSessions) Find(_ context.Context, id []byte, now time.Time) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[string(id)]
	if !ok || !s.ExpiresAt.After(now) {
		return nil, ErrSessionNotFound
	}
	return &s, nil
}

func (m *memSessions) ClearJustLoggedIn(_ context.Context, id []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.sessions[string(id)]
	s.JustLoggedIn = false
	m.sessions[string(id)] = s
	return nil
}

func (m *memSessions) Delete(_ context.Context, id []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, string(id))
	return nil
}

var testSecret = []byte("0123456789abcdef0123456789abcdef")

// startSession runs Start and returns the cookie it set.
func startSession(t *testing.T, m *SessionManager) *http.Cookie {
	t.Helper()
	w := httptest.NewRecorder()
	u := &User{ID: bson.NewObjectID(), Username: "budi"}
	if err := m.Start(context.Background(), w, u); err != nil {
		t.Fatal(err)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == SessionCookieName {
			return c
		}
	}
	t.Fatal("Start set no session cookie")
	return nil
}

func requestWith(c *http.Cookie) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if c != nil {
		r.AddCookie(c)
	}
	return r
}

func TestSessionCookieAttributes(t *testing.T) {
	for _, secure := range []bool{false, true} {
		c := startSession(t, NewSessionManager(newMemSessions(), testSecret, secure))
		if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.Secure != secure {
			t.Errorf("secure=%v: cookie = %+v; want HttpOnly, SameSite=Strict, Path=/, Secure=%v", secure, c, secure)
		}
		if c.MaxAge != int(SessionTTL/time.Second) {
			t.Errorf("MaxAge = %d, want %d", c.MaxAge, int(SessionTTL/time.Second))
		}
		raw, err := base64.RawURLEncoding.DecodeString(c.Value)
		if err != nil || len(raw) != tokenLen {
			t.Errorf("token decodes to %d bytes (err %v), want %d", len(raw), err, tokenLen)
		}
	}
}

// The database stores HMAC(secret, token), never the token itself.
func TestSessionStoresOnlyKeyedID(t *testing.T) {
	store := newMemSessions()
	m := NewSessionManager(store, testSecret, false)
	c := startSession(t, m)
	raw, _ := base64.RawURLEncoding.DecodeString(c.Value)

	if len(store.sessions) != 1 {
		t.Fatalf("%d sessions stored, want 1", len(store.sessions))
	}
	for id, s := range store.sessions {
		if bytes.Equal([]byte(id), raw) || bytes.Contains([]byte(id), raw) {
			t.Error("stored session ID contains the cookie token")
		}
		if !s.ExpiresAt.Equal(s.CreatedAt.Add(SessionTTL)) {
			t.Errorf("ExpiresAt = %v, want CreatedAt + %v", s.ExpiresAt, SessionTTL)
		}
	}

	// The same token under another secret finds nothing.
	other := NewSessionManager(store, []byte("another-secret-another-secret-xx"), false)
	if _, err := other.Load(context.Background(), requestWith(c)); !errors.Is(err, errSessionInvalid) {
		t.Errorf("Load with another secret: err = %v, want errSessionInvalid", err)
	}
}

func TestSessionLoad(t *testing.T) {
	m := NewSessionManager(newMemSessions(), testSecret, false)
	c := startSession(t, m)

	s, err := m.Load(context.Background(), requestWith(c))
	if err != nil || s == nil || s.Username != "budi" || !s.JustLoggedIn {
		t.Fatalf("first Load = %+v, %v; want budi with JustLoggedIn", s, err)
	}
	s, err = m.Load(context.Background(), requestWith(c))
	if err != nil || s == nil || s.JustLoggedIn {
		t.Errorf("second Load = %+v, %v; want JustLoggedIn cleared", s, err)
	}

	if s, err := m.Load(context.Background(), requestWith(nil)); s != nil || err != nil {
		t.Errorf("Load without cookie = %+v, %v; want nil, nil", s, err)
	}
	forged := &http.Cookie{Name: SessionCookieName, Value: base64.RawURLEncoding.EncodeToString(make([]byte, tokenLen))}
	if _, err := m.Load(context.Background(), requestWith(forged)); !errors.Is(err, errSessionInvalid) {
		t.Errorf("forged token: err = %v, want errSessionInvalid", err)
	}
	garbage := &http.Cookie{Name: SessionCookieName, Value: "not-a-token"}
	if _, err := m.Load(context.Background(), requestWith(garbage)); !errors.Is(err, errSessionInvalid) {
		t.Errorf("malformed cookie: err = %v, want errSessionInvalid", err)
	}
}

func TestSessionExpires(t *testing.T) {
	m := NewSessionManager(newMemSessions(), testSecret, false)
	start := time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)
	SetSessionClock(m, func() time.Time { return start })
	c := startSession(t, m)

	SetSessionClock(m, func() time.Time { return start.Add(SessionTTL - time.Second) })
	if s, err := m.Load(context.Background(), requestWith(c)); err != nil || s == nil {
		t.Errorf("just before expiry: %+v, %v; want a session", s, err)
	}
	SetSessionClock(m, func() time.Time { return start.Add(SessionTTL) })
	if _, err := m.Load(context.Background(), requestWith(c)); !errors.Is(err, errSessionInvalid) {
		t.Errorf("at expiry: err = %v, want errSessionInvalid", err)
	}
}

func TestSessionEnd(t *testing.T) {
	store := newMemSessions()
	m := NewSessionManager(store, testSecret, false)
	c := startSession(t, m)

	w := httptest.NewRecorder()
	if err := m.End(context.Background(), w, requestWith(c)); err != nil {
		t.Fatal(err)
	}
	if len(store.sessions) != 0 {
		t.Errorf("%d sessions left after End, want 0", len(store.sessions))
	}
	cleared := w.Result().Cookies()
	if len(cleared) != 1 || cleared[0].Name != SessionCookieName || cleared[0].MaxAge >= 0 {
		t.Errorf("End cookies = %+v, want the session cookie expired", cleared)
	}
	if _, err := m.Load(context.Background(), requestWith(c)); !errors.Is(err, errSessionInvalid) {
		t.Errorf("Load after End: err = %v, want errSessionInvalid", err)
	}
}
