// Package benchmark measures and stores the running time of every
// encryption, decryption, and download, so the ciphers can be compared in
// the report.
package benchmark

import (
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
)

// Operation names what was measured.
type Operation string

// Measured operations.
const (
	OpEncrypt  Operation = "encrypt"  // upload: plaintext stream to stored ciphertext
	OpDecrypt  Operation = "decrypt"  // verify-then-decrypt of a stored object
	OpDownload Operation = "download" // full download request, including network I/O
)

// Record is one measured operation, stored in the benchmarks collection.
// Durations are stored as int64 nanoseconds.
type Record struct {
	ID        bson.ObjectID    `bson:"_id,omitempty"`
	Algorithm crypto.Algorithm `bson:"algorithm"`
	Operation Operation        `bson:"operation"`
	// FileKind is the files.Kind as a string, or empty for field operations.
	FileKind string `bson:"file_kind,omitempty"`
	// Bytes is the plaintext size processed.
	Bytes int64 `bson:"bytes"`
	// CryptoDuration is time spent in cipher and MAC operations only.
	CryptoDuration time.Duration `bson:"crypto_ns"`
	// TotalDuration is wall-clock time for the whole operation, including I/O.
	TotalDuration time.Duration `bson:"total_ns"`
	CreatedAt     time.Time     `bson:"created_at"`
}
