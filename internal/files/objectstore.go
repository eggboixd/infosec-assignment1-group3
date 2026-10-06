package files

import (
	"context"
	"io"
)

// ObjectStore is the object storage the files feature needs. It only ever
// receives ciphertext. internal/platform/minio provides the implementation.
type ObjectStore interface {
	// Put streams r into key. size is the exact length in bytes, or -1 if
	// unknown, in which case the implementation must bound its buffering.
	Put(ctx context.Context, key string, r io.Reader, size int64, contentType string) error

	// Get opens key for reading. The reader supports Seek so the caller can
	// verify the MAC in a first pass, seek to the start, and decrypt in a
	// second pass. The caller must Close it.
	Get(ctx context.Context, key string) (io.ReadSeekCloser, error)

	// Delete removes key. Deleting a missing key is not an error.
	Delete(ctx context.Context, key string) error
}
