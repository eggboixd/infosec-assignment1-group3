package auth

import (
	"context"
	"errors"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// ErrNotImplemented marks service functions that are still stubs.
var ErrNotImplemented = errors.New("auth: not implemented")

// ErrInvalidCredentials is returned by Login for an unknown user or a wrong
// password. The two cases must stay indistinguishable to the caller.
var ErrInvalidCredentials = errors.New("auth: invalid username or password")

// userStore is the persistence the service needs. *Store satisfies it.
type userStore interface {
	Create(ctx context.Context, u *User) error
	FindByUsername(ctx context.Context, username string) (*User, error)
	FindByID(ctx context.Context, id bson.ObjectID) (*User, error)
}

// Service implements account logic on plain Go types, with no HTTP types.
type Service struct {
	users userStore
}

// NewService returns a Service using users for persistence.
func NewService(users userStore) *Service {
	return &Service{users: users}
}

// Register creates an account with a hashed password.
//
// TODO(feature/auth): normalise the username, hash the password with
// HashPassword, and call users.Create; map ErrUsernameTaken to a form error.
func (s *Service) Register(ctx context.Context, username, password string) (*User, error) {
	return nil, ErrNotImplemented
}

// Login returns the user if the password matches.
//
// TODO(feature/auth): look up the user and call VerifyPassword. When the
// user does not exist, still verify against a dummy hash so response time
// does not reveal which usernames exist. Return ErrInvalidCredentials.
func (s *Service) Login(ctx context.Context, username, password string) (*User, error) {
	return nil, ErrNotImplemented
}

// HashPassword returns an Argon2id hash in PHC string format.
//
// TODO(feature/auth): use golang.org/x/crypto/argon2.IDKey with a 16-byte
// salt from crypto/rand and documented parameters (for example
// time=3, memory=64 MiB, threads=2, keyLen=32).
func HashPassword(password string) (string, error) {
	return "", ErrNotImplemented
}

// VerifyPassword reports whether password matches encoded.
//
// TODO(feature/auth): parse the PHC string and compare with
// crypto/subtle.ConstantTimeCompare.
func VerifyPassword(encoded, password string) (bool, error) {
	return false, ErrNotImplemented
}
