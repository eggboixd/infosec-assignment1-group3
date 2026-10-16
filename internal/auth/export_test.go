package auth

import (
	"testing"
	"time"
)

// UseFastHashes lowers the Argon2id cost for the rest of the test, so tests
// that register and log in many times stay fast (the race detector slows
// Argon2id's memory passes a lot). Hashes made this way still verify,
// because VerifyPassword reads the cost from the hash.
func UseFastHashes(t *testing.T) {
	t.Helper()
	old := params
	params = hashParams{time: 1, memory: 64, threads: 1, saltLen: 16, keyLen: 32}
	t.Cleanup(func() { params = old })
}

// SetSessionClock replaces the session manager's clock.
func SetSessionClock(m *SessionManager, now func() time.Time) {
	m.now = now
}

// In-memory stores for the handler tests in package auth_test.
func NewMemUsers() *memUsers       { return newMemUsers() }
func NewMemSessions() *memSessions { return newMemSessions() }

// Get returns the stored user named username.
func (m *memUsers) Get(username string) (User, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[username]
	return u, ok
}

// Len returns the number of stored sessions.
func (m *memSessions) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions)
}
