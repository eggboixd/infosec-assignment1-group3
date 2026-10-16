package auth

import (
	"strconv"
	"testing"
	"time"
)

func TestRateLimiter(t *testing.T) {
	now := time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)
	l := newRateLimiter(3, time.Minute)
	l.now = func() time.Time { return now }

	for i := range 3 {
		if ok, _ := l.allow("10.0.0.1"); !ok {
			t.Fatalf("attempt %d refused, want allowed", i+1)
		}
	}
	now = now.Add(20 * time.Second)
	ok, retry := l.allow("10.0.0.1")
	if ok || retry != 40*time.Second {
		t.Errorf("4th attempt = %v, retry %v; want refused, 40s", ok, retry)
	}
	if ok, _ := l.allow("10.0.0.2"); !ok {
		t.Error("another client was refused; limits must be per key")
	}
	now = now.Add(40 * time.Second)
	if ok, _ := l.allow("10.0.0.1"); !ok {
		t.Error("attempt after the window was refused")
	}
}

func TestRateLimiterBoundsMemory(t *testing.T) {
	now := time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)
	l := newRateLimiter(1, time.Minute)
	l.now = func() time.Time { return now }
	for i := range maxTrackedKeys + 100 {
		l.allow("k" + strconv.Itoa(i))
	}
	if len(l.hits) > maxTrackedKeys {
		t.Errorf("tracking %d keys, want at most %d", len(l.hits), maxTrackedKeys)
	}
}
