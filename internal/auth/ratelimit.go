package auth

import (
	"sync"
	"time"
)

// maxTrackedKeys bounds the limiter's memory. When it is reached, expired
// windows are swept before a new key is added.
const maxTrackedKeys = 10_000

// rateLimiter allows up to limit attempts per key in each fixed window.
// It is in-memory, so limits reset when the app restarts and are not
// shared between replicas (docs/decisions.md D29).
type rateLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	hits   map[string]*rateWindow
	now    func() time.Time
}

type rateWindow struct {
	start time.Time
	count int
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{limit: limit, window: window, hits: map[string]*rateWindow{}, now: time.Now}
}

// allow records an attempt for key. When the limit is exceeded it returns
// false and how long until the window resets.
func (l *rateLimiter) allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()

	w, ok := l.hits[key]
	if !ok || now.Sub(w.start) >= l.window {
		if !ok && len(l.hits) >= maxTrackedKeys {
			l.sweep(now)
		}
		l.hits[key] = &rateWindow{start: now, count: 1}
		return true, 0
	}
	if w.count >= l.limit {
		return false, w.start.Add(l.window).Sub(now)
	}
	w.count++
	return true, 0
}

// sweep drops windows that have ended. If every key is still active, the
// map is reset rather than allowed to grow without bound.
func (l *rateLimiter) sweep(now time.Time) {
	for k, w := range l.hits {
		if now.Sub(w.start) >= l.window {
			delete(l.hits, k)
		}
	}
	if len(l.hits) >= maxTrackedKeys {
		clear(l.hits)
	}
}
