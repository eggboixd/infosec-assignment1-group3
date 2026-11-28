package sharing

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/eggboixd/infosec-assignment1-group3/internal/auth"
	"github.com/eggboixd/infosec-assignment1-group3/internal/keypair"
)

// memStore is an in-memory requestStore. Like the partial unique index
// open_pair_unique, it refuses a second stored pending/approved request for
// the same pair, whatever the expiry. beforeTransition, if set, runs before
// each Transition so tests can simulate a concurrent change.
type memStore struct {
	mu               sync.Mutex
	reqs             map[bson.ObjectID]*Request
	seq              int
	order            map[bson.ObjectID]int
	beforeTransition func(t transition)
}

func newMemStore() *memStore {
	return &memStore{reqs: map[bson.ObjectID]*Request{}, order: map[bson.ObjectID]int{}}
}

func storedOpen(s Status) bool { return s == StatusPending || s == StatusApproved }

func (m *memStore) Insert(_ context.Context, r *Request) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, o := range m.reqs {
		if o.RequesterID == r.RequesterID && o.OwnerID == r.OwnerID && storedOpen(o.Status) && storedOpen(r.Status) {
			return ErrAlreadyOpen
		}
	}
	r.ID = bson.NewObjectID()
	cp := *r
	m.reqs[r.ID] = &cp
	m.seq++
	m.order[r.ID] = m.seq
	return nil
}

func actorOf(r *Request, actor string) bson.ObjectID {
	if actor == actorOwner {
		return r.OwnerID
	}
	return r.RequesterID
}

func (m *memStore) Find(_ context.Context, id bson.ObjectID, actor string, actorID bson.ObjectID) (*Request, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.reqs[id]
	if !ok || actorOf(r, actor) != actorID {
		return nil, ErrNotFound
	}
	cp := *r
	return &cp, nil
}

func (m *memStore) List(_ context.Context, actor string, actorID bson.ObjectID, limit int) ([]Request, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Request
	for _, r := range m.reqs {
		if actorOf(r, actor) == actorID {
			out = append(out, *r)
		}
	}
	slices.SortFunc(out, func(a, b Request) int {
		if c := b.CreatedAt.Compare(a.CreatedAt); c != 0 {
			return c
		}
		return cmp.Compare(m.order[b.ID], m.order[a.ID])
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *memStore) CountPending(_ context.Context, requesterID bson.ObjectID, now time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, r := range m.reqs {
		if r.RequesterID == requesterID && r.Status == StatusPending && r.ExpiresAt.After(now) {
			n++
		}
	}
	return n, nil
}

func (m *memStore) ListLapsed(_ context.Context, requesterID, ownerID bson.ObjectID, now time.Time) ([]Request, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Request
	for _, r := range m.reqs {
		if r.RequesterID == requesterID && r.OwnerID == ownerID && storedOpen(r.Status) && !r.ExpiresAt.After(now) {
			out = append(out, *r)
		}
	}
	return out, nil
}

func (m *memStore) Transition(_ context.Context, t transition) (bool, error) {
	if m.beforeTransition != nil {
		m.beforeTransition(t)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.reqs[t.ID]
	if !ok || actorOf(r, t.Actor) != t.ActorID || r.Status != t.From {
		return false, nil
	}
	if t.RequireUnexpired && !r.ExpiresAt.After(t.Now) {
		return false, nil
	}
	r.Status = t.To
	if t.DecidedAt != nil {
		v := *t.DecidedAt
		r.DecidedAt = &v
	}
	if t.ExpiresAt != nil {
		r.ExpiresAt = *t.ExpiresAt
	}
	if t.EndedAt != nil {
		v := *t.EndedAt
		r.EndedAt = &v
	}
	return true, nil
}

// get returns a copy of the stored request.
func (m *memStore) get(id bson.ObjectID) Request {
	m.mu.Lock()
	defer m.mu.Unlock()
	return *m.reqs[id]
}

// set changes a stored request directly.
func (m *memStore) set(id bson.ObjectID, f func(r *Request)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f(m.reqs[id])
}

// fakeUsers is a userLookup over fixed users, keyed by normalised name.
type fakeUsers map[string]*auth.User

func (f fakeUsers) FindByUsername(_ context.Context, username string) (*auth.User, error) {
	u, ok := f[username]
	if !ok {
		return nil, auth.ErrUserNotFound
	}
	return u, nil
}

// fakeKeys is a keyInfo: every user has keys unless errs names them.
type fakeKeys struct {
	errs map[bson.ObjectID]error
}

func fingerprintOf(id bson.ObjectID) string { return "fp-" + id.Hex() }

func (f *fakeKeys) Info(_ context.Context, userID bson.ObjectID) ([]keypair.Info, error) {
	if err := f.errs[userID]; err != nil {
		return nil, err
	}
	return []keypair.Info{
		{Purpose: keypair.Encryption, Bits: 3072, Fingerprint: fingerprintOf(userID)},
		{Purpose: keypair.Signing, Bits: 3072, Fingerprint: "sig-" + userID.Hex()},
	}, nil
}

// fakeGranter records calls.
type fakeGranter struct {
	mu         sync.Mutex
	grants     []Grant
	destroyed  []bson.ObjectID
	grantErr   error
	destroyErr error
	onGrant    func() // runs inside Grant, e.g. to move the clock
}

func (g *fakeGranter) Grant(_ context.Context, gr Grant) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.grants = append(g.grants, gr)
	if g.onGrant != nil {
		g.onGrant()
	}
	return g.grantErr
}

func (g *fakeGranter) Destroy(_ context.Context, id bson.ObjectID) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.destroyed = append(g.destroyed, id)
	return g.destroyErr
}

func (g *fakeGranter) destroyCount(id bson.ObjectID) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	n := 0
	for _, d := range g.destroyed {
		if d == id {
			n++
		}
	}
	return n
}

var errFake = errors.New("fake failure")
