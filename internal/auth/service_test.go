package auth

import (
	"context"
	"errors"
	"sync"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// memUsers is an in-memory userStore enforcing the unique username index.
type memUsers struct {
	mu    sync.Mutex
	users map[string]User
}

func newMemUsers() *memUsers { return &memUsers{users: map[string]User{}} }

func (m *memUsers) Create(_ context.Context, u *User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.users[u.Username]; ok {
		return ErrUsernameTaken
	}
	u.ID = bson.NewObjectID()
	m.users[u.Username] = *u
	return nil
}

func (m *memUsers) FindByUsername(_ context.Context, username string) (*User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[username]
	if !ok {
		return nil, ErrUserNotFound
	}
	return &u, nil
}

func (m *memUsers) FindByID(_ context.Context, id bson.ObjectID) (*User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.users {
		if u.ID == id {
			return &u, nil
		}
	}
	return nil, ErrUserNotFound
}

func TestRegisterNormalizesAndHashes(t *testing.T) {
	UseFastHashes(t)
	users := newMemUsers()
	svc := NewService(users)

	u, err := svc.Register(context.Background(), "  BudiS  ", "a long enough password")
	if err != nil {
		t.Fatal(err)
	}
	if u.Username != "budis" {
		t.Errorf("username = %q, want %q", u.Username, "budis")
	}
	stored := users.users["budis"]
	if stored.PasswordHash == "" || stored.PasswordHash == "a long enough password" {
		t.Errorf("password not hashed: %q", stored.PasswordHash)
	}
	if stored.CreatedAt.IsZero() || stored.UpdatedAt.IsZero() {
		t.Error("timestamps not set")
	}
}

func TestRegisterDuplicateIsCaseInsensitive(t *testing.T) {
	UseFastHashes(t)
	svc := NewService(newMemUsers())
	if _, err := svc.Register(context.Background(), "budi", "a long enough password"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Register(context.Background(), "BUDI", "another long password"); !errors.Is(err, ErrUsernameTaken) {
		t.Errorf("err = %v, want ErrUsernameTaken", err)
	}
}

func TestLogin(t *testing.T) {
	UseFastHashes(t)
	svc := NewService(newMemUsers())
	reg, err := svc.Register(context.Background(), "budi", "a long enough password")
	if err != nil {
		t.Fatal(err)
	}

	u, err := svc.Login(context.Background(), "Budi", "a long enough password")
	if err != nil || u.ID != reg.ID {
		t.Errorf("Login(right) = %v, %v; want the registered user", u, err)
	}
	for name, tc := range map[string][2]string{
		"wrong password": {"budi", "a long enough passworD"},
		"unknown user":   {"nobody", "a long enough password"},
		"empty password": {"budi", ""},
	} {
		if _, err := svc.Login(context.Background(), tc[0], tc[1]); !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("%s: err = %v, want ErrInvalidCredentials", name, err)
		}
	}
}

type failingUsers struct{ *memUsers }

func (failingUsers) FindByUsername(context.Context, string) (*User, error) {
	return nil, errors.New("connection refused")
}

// A database failure must not look like wrong credentials.
func TestLoginStoreErrorIsNotInvalidCredentials(t *testing.T) {
	svc := NewService(failingUsers{newMemUsers()})
	_, err := svc.Login(context.Background(), "budi", "a long enough password")
	if err == nil || errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("err = %v, want a non-credentials error", err)
	}
}

// With every hashing slot taken, a request whose context ends gives up
// instead of waiting forever.
func TestHashSlotsRespectContext(t *testing.T) {
	svc := NewService(newMemUsers())
	for range maxConcurrentHashes {
		svc.hashSlots <- struct{}{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := svc.Register(ctx, "budi", "a long enough password"); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}
