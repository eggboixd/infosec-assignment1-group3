package applications

import (
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
)

// Errors returned by the service.
var (
	ErrUnknownScholarship = errors.New("applications: unknown scholarship")
	ErrClosed             = errors.New("applications: scholarship is closed")
	ErrNotReady           = errors.New("applications: application is incomplete")
	ErrAlreadyApplied     = errors.New("applications: already applied")
	// ErrCorrupt is returned when a stored application decrypts but does not
	// belong where it is stored: an unknown scholarship, or a blind index
	// that does not match its owner and scholarship. Tampered ciphertext is
	// reported as crypto.ErrAuthentication instead.
	ErrCorrupt = errors.New("applications: stored application is inconsistent")
)

// Application is the stored document: one per student and scholarship.
type Application struct {
	ID     bson.ObjectID `bson:"_id,omitempty"`
	UserID bson.ObjectID `bson:"user_id"`
	// Scholarship is the scholarship ID, encrypted with each algorithm.
	Scholarship crypto.SealedSet `bson:"scholarship"`
	// Index is HMAC-SHA256(key, user ID || scholarship ID), a blind index
	// whose unique index allows one application per student and scholarship
	// without storing the scholarship ID in plaintext (D38, as D19).
	Index       []byte    `bson:"index"`
	SubmittedAt time.Time `bson:"submitted_at"`
}

// Readiness says whether a student has everything an application needs.
// Both scholarships require the same applicant data and documents.
type Readiness struct {
	HasProfile bool
	// Uploaded and Total count the filled document slots.
	Uploaded int
	Total    int
	// Missing names the missing documents, in checklist order.
	Missing []string
}

// Ready reports whether the student can submit.
func (r Readiness) Ready() bool {
	return r.HasProfile && r.Total > 0 && r.Uploaded == r.Total
}

// MissingCount is the number of missing items, applicant data included.
func (r Readiness) MissingCount() int {
	n := len(r.Missing)
	if !r.HasProfile {
		n++
	}
	return n
}
