package benchmark

import (
	"context"
	"time"

	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
)

// Measure runs fn and returns a Record of its timings.
//
// fn receives a context carrying a crypto.Clock; Encryptor implementations
// add their cipher and MAC time to it, which becomes CryptoDuration. The
// wall-clock time of fn becomes TotalDuration. fn returns the number of
// plaintext bytes processed, because a streamed size is known only at the
// end. The Record is returned even when fn fails, so callers can decide
// whether to keep partial measurements; usually they should discard it.
func Measure(ctx context.Context, alg crypto.Algorithm, op Operation, fn func(ctx context.Context) (int64, error)) (Record, error) {
	ctx, clock := crypto.WithClock(ctx)
	start := time.Now()
	n, err := fn(ctx)
	total := time.Since(start)
	return Record{
		Algorithm:      alg,
		Operation:      op,
		Bytes:          n,
		CryptoDuration: clock.Elapsed(),
		TotalDuration:  total,
		CreatedAt:      start.UTC(),
	}, err
}
