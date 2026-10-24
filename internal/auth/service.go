package auth

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// ErrInvalidCredentials is returned by Login for an unknown user or a wrong
// password. The two cases must stay indistinguishable to the caller.
var ErrInvalidCredentials = errors.New("auth: invalid username or password")

// maxConcurrentHashes bounds how many Argon2id computations run at once.
// Each one allocates params.memory (64 MiB), so without a bound a burst of
// login requests could exhaust the container's memory.
const maxConcurrentHashes = 4

// userStore is the persistence the service needs. *Store satisfies it.
type userStore interface {
	Create(ctx context.Context, u *User) error
	FindByUsername(ctx context.Context, username string) (*User, error)
	FindByID(ctx context.Context, id bson.ObjectID) (*User, error)
}

// Service implements account logic on plain Go types, with no HTTP types.
type Service struct {
	users     userStore
	hashSlots chan struct{}
	now       func() time.Time
}

// NewService returns a Service using users for persistence.
func NewService(users userStore) *Service {
	return &Service{
		users:     users,
		hashSlots: make(chan struct{}, maxConcurrentHashes),
		now:       time.Now,
	}
}

// NormalizeUsername trims surrounding spaces and lower-cases the username,
// so "Budi" and "budi" are the same account.
func NormalizeUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

// Register creates an account with a hashed password. It returns
// ErrUsernameTaken if the (normalized) username exists. Input rules are
// checked by the handler's binding tags before this is called.
func (s *Service) Register(ctx context.Context, username, password string) (*User, error) {
	var hash string
	err := s.withHashSlot(ctx, func() error {
		var err error
		hash, err = HashPassword(password)
		return err
	})
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	u := &User{
		Username:     NormalizeUsername(username),
		PasswordHash: hash,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := s.users.Create(ctx, u); err != nil {
		return nil, err
	}
	return u, nil
}

// Login returns the user if the password matches, or ErrInvalidCredentials.
//
// When the user does not exist, the password is still verified against a
// dummy hash, so the response time does not reveal which usernames exist.
func (s *Service) Login(ctx context.Context, username, password string) (*User, error) {
	u, err := s.users.FindByUsername(ctx, NormalizeUsername(username))
	if err != nil && !errors.Is(err, ErrUserNotFound) {
		return nil, err
	}
	encoded := dummyHash()
	if u != nil {
		encoded = u.PasswordHash
	}

	var ok bool
	err = s.withHashSlot(ctx, func() error {
		var err error
		ok, err = VerifyPassword(encoded, password)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("auth: verify password: %w", err)
	}
	if u == nil || !ok {
		return nil, ErrInvalidCredentials
	}
	return u, nil
}

// withHashSlot runs fn once a hashing slot is free, or gives up when ctx
// is done (for example, the client disconnected while queued).
func (s *Service) withHashSlot(ctx context.Context, fn func() error) error {
	select {
	case s.hashSlots <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-s.hashSlots }()
	return fn()
}

// dummyHash is a valid hash of a random password, made with the current
// parameters so verifying against it costs the same as a real login.
var dummyHash = sync.OnceValue(func() string {
	h, err := HashPassword(rand.Text())
	if err != nil {
		// crypto/rand does not fail on supported platforms.
		panic("auth: build dummy hash: " + err.Error())
	}
	return h
})
