package profile

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/eggboixd/infosec-assignment1-group3/internal/benchmark"
	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
)

// blindKeySize is the length of the NIK blind-index key: a 32-byte subkey
// from crypto.DeriveKey, equal to the HMAC-SHA256 output size (RFC 2104).
const blindKeySize = 32

// ErrCorrupt is returned when a stored profile is structurally broken, for
// example a field has no ciphertext for the requested algorithm. Tampered
// ciphertext is reported as crypto.ErrAuthentication instead.
var ErrCorrupt = errors.New("profile: stored data is incomplete")

// profileStore is the persistence the service needs. *Store satisfies it.
type profileStore interface {
	Upsert(ctx context.Context, p *Profile) error
	FindByUserID(ctx context.Context, userID bson.ObjectID) (*Profile, error)
}

// benchmarkSink receives one record per measured operation.
// *benchmark.Store satisfies it.
type benchmarkSink interface {
	Save(ctx context.Context, r benchmark.Record) error
}

// Service encrypts and decrypts private data on plain Go types.
type Service struct {
	store profileStore
	enc   crypto.Encryptor
	// blindKey keys the NIK blind index. It is derived from the master key
	// with crypto.DeriveKey(master, "nik-blind-index").
	blindKey []byte
	// bench may be nil, which disables benchmark records.
	bench benchmarkSink
	// now is time.Now outside tests.
	now func() time.Time
}

// NewService returns a Service.
func NewService(store profileStore, enc crypto.Encryptor, blindKey []byte, bench benchmarkSink) *Service {
	return &Service{store: store, enc: enc, blindKey: blindKey, bench: bench, now: time.Now}
}

// fieldRef ties a plaintext field to its encrypted counterpart, so Save and
// Get walk the six fields in one place instead of six copies of the same code.
type fieldRef struct {
	plain  *string
	sealed *crypto.SealedSet
}

func fields(d *PrivateData, p *Profile) []fieldRef {
	return []fieldRef{
		{&d.FullName, &p.FullName},
		{&d.NIK, &p.NIK},
		{&d.DateOfBirth, &p.DateOfBirth},
		{&d.Address, &p.Address},
		{&d.Phone, &p.Phone},
		{&d.Email, &p.Email},
	}
}

// Save validates data, encrypts every field once with every algorithm, and
// stores the result for userID, replacing any earlier profile.
//
// It returns a *ValidationError for bad input and ErrNIKTaken when another
// profile already has the same NIK.
func (s *Service) Save(ctx context.Context, userID bson.ObjectID, data PrivateData) error {
	// The service never trusts its caller: normalise and validate again.
	data.normalize()
	if err := validate(data, s.now()); err != nil {
		return err
	}

	nikIndex, err := s.nikBlindIndex(data.NIK)
	if err != nil {
		return err
	}

	p := &Profile{UserID: userID}
	refs := fields(&data, p)
	for _, f := range refs {
		*f.sealed = make(crypto.SealedSet, len(crypto.All()))
	}

	// Algorithm outer, field inner, so each algorithm's work on the whole
	// profile is one benchmark record (decision D22).
	var records []benchmark.Record
	for _, alg := range crypto.All() {
		rec, err := benchmark.Measure(ctx, alg, benchmark.OpEncrypt, func(ctx context.Context) (int64, error) {
			var n int64
			for _, f := range refs {
				sealed, err := s.sealField(ctx, alg, *f.plain)
				if err != nil {
					return n, err
				}
				(*f.sealed)[alg] = sealed
				n += int64(len(*f.plain))
			}
			return n, nil
		})
		if err != nil {
			return fmt.Errorf("profile: encrypt: %w", err)
		}
		records = append(records, rec)
	}

	// ReplaceOne overwrites the whole document, so keep the original _id and
	// created_at when the user already has a profile.
	now := s.now().UTC()
	p.CreatedAt = now
	existing, err := s.store.FindByUserID(ctx, userID)
	switch {
	case err == nil:
		p.ID = existing.ID
		p.CreatedAt = existing.CreatedAt
	case !errors.Is(err, ErrNotFound):
		return err
	}
	p.UpdatedAt = now
	p.NIKIndex = nikIndex

	// The unique index on nik_index turns a duplicate NIK into ErrNIKTaken.
	if err := s.store.Upsert(ctx, p); err != nil {
		return err
	}
	s.saveRecords(ctx, records...)
	return nil
}

// Get loads the profile owned by userID and decrypts the copy made with alg.
//
// The lookup is always by the logged-in user's ID, never by an ID from the
// request, so one user cannot read another's profile (no IDOR). It returns
// ErrNotFound if the user has no profile yet and crypto.ErrAuthentication if
// any field fails its integrity check; in both cases no data is returned.
func (s *Service) Get(ctx context.Context, userID bson.ObjectID, alg crypto.Algorithm) (*PrivateData, error) {
	if !alg.Valid() {
		return nil, fmt.Errorf("%w: %q", crypto.ErrUnknownAlgorithm, alg)
	}
	p, err := s.store.FindByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}

	var data PrivateData
	refs := fields(&data, p)
	rec, err := benchmark.Measure(ctx, alg, benchmark.OpDecrypt, func(ctx context.Context) (int64, error) {
		var n int64
		for _, f := range refs {
			pt, err := s.openField(ctx, alg, *f.sealed)
			if err != nil {
				return n, err
			}
			*f.plain = pt
			n += int64(len(pt))
		}
		return n, nil
	})
	if err != nil {
		// Fail closed: never return the fields that did verify.
		return nil, err
	}
	s.saveRecords(ctx, rec)
	return &data, nil
}

// HasProfile reports whether userID has saved a profile. It decrypts
// nothing and records no benchmark, so it can run on every page view (the
// scholarship portal checks it before an application, D38).
func (s *Service) HasProfile(ctx context.Context, userID bson.ObjectID) (bool, error) {
	switch _, err := s.store.FindByUserID(ctx, userID); {
	case err == nil:
		return true, nil
	case errors.Is(err, ErrNotFound):
		return false, nil
	default:
		return false, err
	}
}

// sealField encrypts one value with one algorithm.
//
// EncryptField takes no context, so the Envelope cannot add to the
// benchmark clock itself. The whole call is timed here instead; for fields
// that includes key generation and key wrapping, which is exactly the fixed
// per-item overhead the report compares against large files (D22).
func (s *Service) sealField(ctx context.Context, alg crypto.Algorithm, plaintext string) (crypto.Sealed, error) {
	start := time.Now()
	ct, meta, err := s.enc.EncryptField(alg, []byte(plaintext))
	crypto.ClockFrom(ctx).Add(time.Since(start))
	if err != nil {
		return crypto.Sealed{}, err
	}
	return crypto.Sealed{Ciphertext: ct, Meta: meta}, nil
}

// openField verifies and decrypts the alg copy in set.
func (s *Service) openField(ctx context.Context, alg crypto.Algorithm, set crypto.SealedSet) (string, error) {
	sealed, ok := set[alg]
	if !ok {
		return "", fmt.Errorf("%w: no %s ciphertext", ErrCorrupt, alg)
	}
	start := time.Now()
	pt, err := s.enc.DecryptField(alg, sealed.Meta, sealed.Ciphertext)
	crypto.ClockFrom(ctx).Add(time.Since(start))
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// saveRecords stores benchmark records. A failure is logged and otherwise
// ignored: losing a timing sample must not fail the user's request.
func (s *Service) saveRecords(ctx context.Context, records ...benchmark.Record) {
	if s.bench == nil {
		return
	}
	for _, r := range records {
		if err := s.bench.Save(ctx, r); err != nil {
			slog.Warn("profile: save benchmark record", "alg", r.Algorithm, "op", r.Operation, "error", err)
		}
	}
}

// nikBlindIndex returns HMAC-SHA256(blindKey, nik) for a normalised NIK.
//
// The encrypted NIK changes every time (fresh key and IV), so MongoDB cannot
// compare it. This keyed hash is deterministic, so a unique index on it
// rejects a NIK that is already registered without storing the NIK itself.
// A plain SHA-256 would not do: there are few enough valid NIKs (region code
// + date of birth + 4-digit serial) to hash them all and reverse it. Without
// blindKey that is impossible (D19).
func (s *Service) nikBlindIndex(nik string) ([]byte, error) {
	// Refuse to run without the real key: an empty HMAC key would silently
	// turn this into an unkeyed, reversible hash.
	if len(s.blindKey) != blindKeySize {
		return nil, fmt.Errorf("profile: NIK blind-index key must be %d bytes, got %d", blindKeySize, len(s.blindKey))
	}
	if len(nik) != nikDigits || !allDigits(nik) {
		return nil, errors.New("profile: NIK blind index needs a normalised 16-digit NIK")
	}
	mac := hmac.New(sha256.New, s.blindKey)
	mac.Write([]byte(nik))
	return mac.Sum(nil), nil
}
