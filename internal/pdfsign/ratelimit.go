package pdfsign

import (
	"sync"
	"time"
)

const (
	// maxUnlockFailures wrong passwords per user are allowed in each
	// unlockWindow (D51). Each one is an online guess at the password that
	// protects the signing key (D44).
	maxUnlockFailures = 5
	unlockWindow      = 5 * time.Minute
	// maxTrackedUsers bounds the limiter's memory.
	maxTrackedUsers = 10_000
)

// failureLimiter counts failed attempts per key (a user ID) in fixed
// windows. Only failures count, so a user who signs many documents with the
// right password is never blocked. It is in memory, like auth's per-IP
// limiter (D29): it resets on restart and isn't shared between replicas.
type failureLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	hits   map[string]*failureWindow
	now    func() time.Time
}

type failureWindow struct {
	start time.Time
	count int
}

func newFailureLimiter(limit int, window time.Duration) *failureLimiter {
	return &failureLimiter{limit: limit, window: window, hits: map[string]*failureWindow{}, now: time.Now}
}

// blocked reports whether key has used up its failures in the current
// window, and if so how long until the window ends.
func (l *failureLimiter) blocked(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	w, ok := l.hits[key]
	if !ok {
		return false, 0
	}
	now := l.now()
	if now.Sub(w.start) >= l.window {
		delete(l.hits, key)
		return false, 0
	}
	if w.count >= l.limit {
		return true, w.start.Add(l.window).Sub(now)
	}
	return false, 0
}

// fail records one failed attempt for key.
func (l *failureLimiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	w, ok := l.hits[key]
	if !ok || now.Sub(w.start) >= l.window {
		if !ok && len(l.hits) >= maxTrackedUsers {
			l.sweep(now)
		}
		l.hits[key] = &failureWindow{start: now, count: 1}
		return
	}
	w.count++
}

// sweep drops ended windows; if none have ended, it starts over rather
// than growing without bound.
func (l *failureLimiter) sweep(now time.Time) {
	for k, w := range l.hits {
		if now.Sub(w.start) >= l.window {
			delete(l.hits, k)
		}
	}
	if len(l.hits) >= maxTrackedUsers {
		l.hits = map[string]*failureWindow{}
	}
}
