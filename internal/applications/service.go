package applications

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
	"github.com/eggboixd/infosec-assignment1-group3/internal/files"
)

// indexKeySize is the length of the blind-index key: a 32-byte subkey from
// crypto.DeriveKey, equal to the HMAC-SHA256 output size.
const indexKeySize = 32

// statusAlg is the copy decrypted to show a student's applications. Any of
// the three would do; all are written on submit.
const statusAlg = crypto.AES

// applicationStore is the persistence the service needs. *Store satisfies it.
type applicationStore interface {
	Insert(ctx context.Context, a *Application) error
	Exists(ctx context.Context, index []byte) (bool, error)
	ListByUser(ctx context.Context, userID bson.ObjectID) ([]Application, error)
}

// profileChecker reports whether a student has saved applicant data.
// *profile.Service satisfies it.
type profileChecker interface {
	HasProfile(ctx context.Context, userID bson.ObjectID) (bool, error)
}

// documentLister lists a student's uploaded files. *files.Service satisfies it.
type documentLister interface {
	List(ctx context.Context, ownerID bson.ObjectID) ([]files.FileView, error)
}

// Service checks readiness, submits applications and reads them back.
//
// It records no benchmark timings: the scholarship ID is a few bytes, and
// page views must not mix into the private-data measurements (D38).
type Service struct {
	store    applicationStore
	profiles profileChecker
	docs     documentLister
	enc      crypto.Encryptor
	// indexKey keys the blind index. It is derived from the master key with
	// crypto.DeriveKey(master, "application-blind-index").
	indexKey []byte
	// now is time.Now outside tests.
	now func() time.Time
}

// NewService returns a Service.
func NewService(store applicationStore, profiles profileChecker, docs documentLister, enc crypto.Encryptor, indexKey []byte) *Service {
	return &Service{store: store, profiles: profiles, docs: docs, enc: enc, indexKey: indexKey, now: time.Now}
}

// Now returns the service's current time, for deadline checks in pages.
func (s *Service) Now() time.Time { return s.now() }

// Readiness reports what userID still needs before applying. The applicant
// data is only checked for existence, never decrypted.
func (s *Service) Readiness(ctx context.Context, userID bson.ObjectID) (Readiness, error) {
	hasProfile, err := s.profiles.HasProfile(ctx, userID)
	if err != nil {
		return Readiness{}, err
	}
	list, err := s.docs.List(ctx, userID)
	if err != nil {
		return Readiness{}, err
	}
	cl := files.BuildChecklist(list)
	r := Readiness{HasProfile: hasProfile, Uploaded: cl.Uploaded, Total: cl.Total}
	for _, sv := range cl.Slots {
		if sv.File == nil {
			r.Missing = append(r.Missing, sv.Label)
		}
	}
	return r, nil
}

// Submitted returns userID's applications as scholarship ID -> submission
// time. Every application is verified and decrypted; one that fails is
// reported, never skipped, so a tampered record cannot silently turn back
// into "not applied".
func (s *Service) Submitted(ctx context.Context, userID bson.ObjectID) (map[string]time.Time, error) {
	apps, err := s.store.ListByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make(map[string]time.Time, len(apps))
	for _, a := range apps {
		id, err := s.open(userID, a)
		if err != nil {
			return nil, err
		}
		out[id] = a.SubmittedAt
	}
	return out, nil
}

// Submit applies userID to the scholarship with the given ID.
//
// The checks run on the server whatever the page showed: the scholarship
// must exist and be open, the student must not have applied already, and
// the applicant data and every document must be present.
func (s *Service) Submit(ctx context.Context, userID bson.ObjectID, scholarshipID string) error {
	sch, ok := Find(scholarshipID)
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownScholarship, scholarshipID)
	}
	now := s.now()
	if !sch.Open(now) {
		return ErrClosed
	}
	index, err := s.blindIndex(userID, sch.ID)
	if err != nil {
		return err
	}
	switch exists, err := s.store.Exists(ctx, index); {
	case err != nil:
		return err
	case exists:
		return ErrAlreadyApplied
	}
	r, err := s.Readiness(ctx, userID)
	if err != nil {
		return err
	}
	if !r.Ready() {
		return ErrNotReady
	}

	a := &Application{
		ID:          bson.NewObjectID(),
		UserID:      userID,
		Scholarship: make(crypto.SealedSet, len(crypto.All())),
		Index:       index,
		SubmittedAt: now.UTC(),
	}
	for _, alg := range crypto.All() {
		ct, meta, err := s.enc.EncryptField(alg, []byte(sch.ID))
		if err != nil {
			return fmt.Errorf("applications: encrypt: %w", err)
		}
		a.Scholarship[alg] = crypto.Sealed{Ciphertext: ct, Meta: meta}
	}
	// The unique index still catches two submits racing past Exists.
	return s.store.Insert(ctx, a)
}

// open verifies and decrypts the scholarship ID of a, and checks that the
// record belongs to userID: its blind index must be the one computed from
// the decrypted ID. That catches a ciphertext copied in from another record,
// which the per-field HMAC alone would accept.
func (s *Service) open(userID bson.ObjectID, a Application) (string, error) {
	sealed, ok := a.Scholarship[statusAlg]
	if !ok {
		return "", fmt.Errorf("%w: no %s ciphertext", ErrCorrupt, statusAlg)
	}
	pt, err := s.enc.DecryptField(statusAlg, sealed.Meta, sealed.Ciphertext)
	if err != nil {
		return "", err
	}
	id := string(pt)
	if _, ok := Find(id); !ok {
		return "", fmt.Errorf("%w: unknown scholarship", ErrCorrupt)
	}
	want, err := s.blindIndex(userID, id)
	if err != nil {
		return "", err
	}
	if a.UserID != userID || !hmac.Equal(want, a.Index) {
		return "", fmt.Errorf("%w: index does not match", ErrCorrupt)
	}
	return id, nil
}

// blindIndex returns HMAC-SHA256(indexKey, user ID || scholarship ID). The
// user ID is a fixed 12 bytes, so the concatenation is unambiguous.
func (s *Service) blindIndex(userID bson.ObjectID, scholarshipID string) ([]byte, error) {
	// An empty key would make this an unkeyed hash that anyone could
	// recompute for the two scholarships.
	if len(s.indexKey) != indexKeySize {
		return nil, fmt.Errorf("applications: blind-index key must be %d bytes, got %d", indexKeySize, len(s.indexKey))
	}
	mac := hmac.New(sha256.New, s.indexKey)
	mac.Write(userID[:])
	mac.Write([]byte(scholarshipID))
	return mac.Sum(nil), nil
}

// IsIntegrityError reports whether err means stored data failed verification.
func IsIntegrityError(err error) bool {
	return errors.Is(err, crypto.ErrAuthentication) || errors.Is(err, ErrCorrupt)
}
