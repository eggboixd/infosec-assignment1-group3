package crypto

import (
	"context"
	"sync/atomic"
	"time"
)

// Clock accumulates time spent inside cipher and MAC operations, separate
// from I/O, so benchmarks can report crypto-only duration for a streaming
// operation. It is safe for concurrent use. A nil *Clock ignores Add.
type Clock struct {
	ns atomic.Int64
	// parent is the Clock the context already carried, if any. Time added
	// here is added there too, so a measurement nested inside another (a
	// decrypt inside a download) counts towards both.
	parent *Clock
}

type clockKey struct{}

// WithClock returns a child context carrying a new Clock. If ctx already
// carries one, time added to the new Clock is also added to it.
func WithClock(ctx context.Context) (context.Context, *Clock) {
	c := &Clock{parent: ClockFrom(ctx)}
	return context.WithValue(ctx, clockKey{}, c), c
}

// ClockFrom returns the Clock carried by ctx, or nil if there is none.
func ClockFrom(ctx context.Context) *Clock {
	c, _ := ctx.Value(clockKey{}).(*Clock)
	return c
}

// Add records d. Encryptor implementations call it around each
// XORKeyStream and HMAC write.
func (c *Clock) Add(d time.Duration) {
	for ; c != nil; c = c.parent {
		c.ns.Add(int64(d))
	}
}

// Elapsed returns the total recorded duration.
func (c *Clock) Elapsed() time.Duration {
	if c == nil {
		return 0
	}
	return time.Duration(c.ns.Load())
}
