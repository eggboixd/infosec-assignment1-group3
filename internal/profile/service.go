package profile

import (
	"context"
	"errors"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
)

// ErrNotImplemented marks service functions that are still stubs.
var ErrNotImplemented = errors.New("profile: not implemented")

// profileStore is the persistence the service needs. *Store satisfies it.
type profileStore interface {
	Upsert(ctx context.Context, p *Profile) error
	FindByUserID(ctx context.Context, userID bson.ObjectID) (*Profile, error)
}

// Service encrypts and decrypts private data on plain Go types.
type Service struct {
	store profileStore
	enc   crypto.Encryptor
	// blindKey keys the NIK blind index. It is derived from the master key
	// with crypto.DeriveKey(master, "nik-blind-index").
	blindKey []byte
}

// NewService returns a Service.
func NewService(store profileStore, enc crypto.Encryptor, blindKey []byte) *Service {
	return &Service{store: store, enc: enc, blindKey: blindKey}
}

// Save encrypts every field of data with every algorithm and stores it.
//
// TODO(feature/private-data): call sealAll for each field, set NIKIndex
// with nikBlindIndex, set timestamps, and call store.Upsert.
func (s *Service) Save(ctx context.Context, userID bson.ObjectID, data PrivateData) error {
	return ErrNotImplemented
}

// Get loads the profile and decrypts it using alg.
//
// TODO(feature/private-data): load with store.FindByUserID and call
// enc.DecryptField on each field's alg entry. Record a benchmark.Record per
// field operation if field-level timings are needed for the report.
func (s *Service) Get(ctx context.Context, userID bson.ObjectID, alg crypto.Algorithm) (*PrivateData, error) {
	return nil, ErrNotImplemented
}

// sealAll encrypts plaintext once with each algorithm.
//
// TODO(feature/private-data): loop over crypto.All() and call enc.EncryptField.
func (s *Service) sealAll(plaintext string) (crypto.SealedSet, error) {
	return nil, ErrNotImplemented
}

// nikBlindIndex returns HMAC-SHA256(blindKey, normalised NIK).
//
// TODO(feature/private-data): implement with crypto/hmac and crypto/sha256.
func (s *Service) nikBlindIndex(nik string) ([]byte, error) {
	return nil, ErrNotImplemented
}
