package applications

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
	"github.com/eggboixd/infosec-assignment1-group3/internal/files"
)

// fixedNow is before both deadlines.
var fixedNow = time.Date(2026, time.October, 27, 9, 0, 0, 0, time.UTC)

// memStore behaves like the applications collection: documents round-trip
// through BSON and the unique index on index is enforced.
type memStore struct {
	mu   sync.Mutex
	docs [][]byte
}

func (m *memStore) Insert(_ context.Context, a *Application) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, raw := range m.docs {
		var other Application
		if err := bson.Unmarshal(raw, &other); err != nil {
			return err
		}
		if bytes.Equal(other.Index, a.Index) {
			return ErrAlreadyApplied
		}
	}
	raw, err := bson.Marshal(a)
	if err != nil {
		return err
	}
	m.docs = append(m.docs, raw)
	return nil
}

func (m *memStore) Exists(_ context.Context, index []byte) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, raw := range m.docs {
		var a Application
		if err := bson.Unmarshal(raw, &a); err != nil {
			return false, err
		}
		if bytes.Equal(a.Index, index) {
			return true, nil
		}
	}
	return false, nil
}

func (m *memStore) ListByUser(_ context.Context, userID bson.ObjectID) ([]Application, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Application
	for _, raw := range m.docs {
		var a Application
		if err := bson.Unmarshal(raw, &a); err != nil {
			return nil, err
		}
		if a.UserID == userID {
			out = append(out, a)
		}
	}
	return out, nil
}

// edit rewrites stored document i.
func (m *memStore) edit(t *testing.T, i int, fn func(a *Application)) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	var a Application
	if err := bson.Unmarshal(m.docs[i], &a); err != nil {
		t.Fatal(err)
	}
	fn(&a)
	raw, err := bson.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	m.docs[i] = raw
}

// fakeProfiles and fakeDocs stand in for the profile and files services.
type fakeProfiles map[bson.ObjectID]bool

func (f fakeProfiles) HasProfile(_ context.Context, id bson.ObjectID) (bool, error) {
	return f[id], nil
}

type fakeDocs map[bson.ObjectID][]files.FileView

func (f fakeDocs) List(_ context.Context, id bson.ObjectID) ([]files.FileView, error) {
	return f[id], nil
}

// allDocuments fills every slot of the checklist.
func allDocuments() []files.FileView {
	var out []files.FileView
	for _, si := range files.Slots() {
		out = append(out, files.FileView{ID: bson.NewObjectID(), Name: "x", NameOK: true, Kind: si.Kind, Slot: si.Slot, Size: 1})
	}
	return out
}

func randomKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

type fixture struct {
	svc      *Service
	store    *memStore
	profiles fakeProfiles
	docs     fakeDocs
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	enc, err := crypto.NewEnvelope(randomKey(t))
	if err != nil {
		t.Fatal(err)
	}
	f := fixture{store: &memStore{}, profiles: fakeProfiles{}, docs: fakeDocs{}}
	f.svc = NewService(f.store, f.profiles, f.docs, enc, randomKey(t))
	f.svc.now = func() time.Time { return fixedNow }
	return f
}

// ready gives a new user applicant data and every document.
func (f fixture) ready() bson.ObjectID {
	id := bson.NewObjectID()
	f.profiles[id] = true
	f.docs[id] = allDocuments()
	return id
}

func TestCatalogue(t *testing.T) {
	all := All()
	if len(all) != 2 {
		t.Fatalf("%d scholarships, want 2", len(all))
	}
	all[0].Name = "changed"
	if All()[0].Name == "changed" {
		t.Error("All returned the catalogue itself, not a copy")
	}
	for _, s := range All() {
		got, ok := Find(s.ID)
		if !ok || got.Name != s.Name {
			t.Errorf("Find(%q) = %v, %v", s.ID, got.Name, ok)
		}
		if !s.Open(fixedNow) || s.Open(s.Deadline.Add(time.Second)) || !s.Open(s.Deadline) {
			t.Errorf("%s: deadline boundaries wrong", s.ID)
		}
	}
	if _, ok := Find("lpdp"); ok {
		t.Error("unknown id found")
	}
}

func TestSubmitThenSubmitted(t *testing.T) {
	f := newFixture(t)
	user := f.ready()
	if err := f.svc.Submit(context.Background(), user, "bakti-keluarga"); err != nil {
		t.Fatal(err)
	}
	got, err := f.svc.Submitted(context.Background(), user)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !got["bakti-keluarga"].Equal(fixedNow) {
		t.Errorf("Submitted = %v", got)
	}
	// The second scholarship is still open to the same student.
	if err := f.svc.Submit(context.Background(), user, "prestasi-nusantara"); err != nil {
		t.Fatalf("second scholarship: %v", err)
	}
	if got, _ := f.svc.Submitted(context.Background(), user); len(got) != 2 {
		t.Errorf("Submitted after two = %v", got)
	}
}

func TestSubmitStoresThreeCiphertextsAndNoPlaintext(t *testing.T) {
	f := newFixture(t)
	user := f.ready()
	const id = "bakti-keluarga"
	if err := f.svc.Submit(context.Background(), user, id); err != nil {
		t.Fatal(err)
	}
	raw := f.store.docs[0]
	if bytes.Contains(raw, []byte(id)) || bytes.Contains(raw, []byte("bakti")) {
		t.Error("stored document contains the scholarship ID in plaintext")
	}
	var a Application
	if err := bson.Unmarshal(raw, &a); err != nil {
		t.Fatal(err)
	}
	if len(a.Scholarship) != len(crypto.All()) {
		t.Fatalf("%d ciphertexts, want %d", len(a.Scholarship), len(crypto.All()))
	}
	seen := map[string]bool{}
	for _, alg := range crypto.All() {
		s, ok := a.Scholarship[alg]
		if !ok {
			t.Fatalf("no %s copy", alg)
		}
		if seen[string(s.Ciphertext)] {
			t.Errorf("%s ciphertext repeats another algorithm's", alg)
		}
		seen[string(s.Ciphertext)] = true
		pt, err := f.svc.enc.DecryptField(alg, s.Meta, s.Ciphertext)
		if err != nil || string(pt) != id {
			t.Errorf("%s copy decrypts to %q, %v", alg, pt, err)
		}
	}
}

func TestSubmitRefusals(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)

	user := f.ready()
	if err := f.svc.Submit(ctx, user, "nope"); !errors.Is(err, ErrUnknownScholarship) {
		t.Errorf("unknown: %v", err)
	}
	if err := f.svc.Submit(ctx, user, "bakti-keluarga"); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Submit(ctx, user, "bakti-keluarga"); !errors.Is(err, ErrAlreadyApplied) {
		t.Errorf("twice: %v", err)
	}

	noProfile := bson.NewObjectID()
	f.docs[noProfile] = allDocuments()
	if err := f.svc.Submit(ctx, noProfile, "bakti-keluarga"); !errors.Is(err, ErrNotReady) {
		t.Errorf("no profile: %v", err)
	}
	oneMissing := bson.NewObjectID()
	f.profiles[oneMissing] = true
	f.docs[oneMissing] = allDocuments()[1:]
	if err := f.svc.Submit(ctx, oneMissing, "bakti-keluarga"); !errors.Is(err, ErrNotReady) {
		t.Errorf("one document missing: %v", err)
	}

	late := f.ready()
	f.svc.now = func() time.Time { return time.Date(2027, time.February, 1, 0, 0, 0, 0, time.UTC) }
	if err := f.svc.Submit(ctx, late, "bakti-keluarga"); !errors.Is(err, ErrClosed) {
		t.Errorf("after deadline: %v", err)
	}
	if n := len(f.store.docs); n != 1 {
		t.Errorf("%d stored applications, want only the first", n)
	}
}

func TestApplicationsArePerUser(t *testing.T) {
	f := newFixture(t)
	a, b := f.ready(), f.ready()
	if err := f.svc.Submit(context.Background(), a, "bakti-keluarga"); err != nil {
		t.Fatal(err)
	}
	// Another student's application to the same scholarship is not a duplicate.
	if err := f.svc.Submit(context.Background(), b, "bakti-keluarga"); err != nil {
		t.Fatalf("second student: %v", err)
	}
	got, _ := f.svc.Submitted(context.Background(), bson.NewObjectID())
	if len(got) != 0 {
		t.Errorf("a third student sees %v", got)
	}
}

func TestSubmittedFailsClosedOnTampering(t *testing.T) {
	tests := []struct {
		name string
		edit func(a *Application, other Application)
		want error
	}{
		{"flipped ciphertext bit", func(a *Application, _ Application) {
			s := a.Scholarship[crypto.AES]
			s.Ciphertext[0] ^= 1
			a.Scholarship[crypto.AES] = s
		}, crypto.ErrAuthentication},
		{"missing AES copy", func(a *Application, _ Application) {
			delete(a.Scholarship, crypto.AES)
		}, ErrCorrupt},
		// A valid ciphertext of the other scholarship, copied from another
		// record: the field HMAC passes, the blind index does not.
		{"ciphertext swapped in", func(a *Application, other Application) {
			a.Scholarship = other.Scholarship
		}, ErrCorrupt},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			user := f.ready()
			for _, id := range []string{"bakti-keluarga", "prestasi-nusantara"} {
				if err := f.svc.Submit(context.Background(), user, id); err != nil {
					t.Fatal(err)
				}
			}
			var other Application
			if err := bson.Unmarshal(f.store.docs[1], &other); err != nil {
				t.Fatal(err)
			}
			f.store.edit(t, 0, func(a *Application) { tt.edit(a, other) })
			got, err := f.svc.Submitted(context.Background(), user)
			if !errors.Is(err, tt.want) || got != nil {
				t.Errorf("Submitted = %v, %v; want error %v and no data", got, err, tt.want)
			}
			if !IsIntegrityError(err) {
				t.Errorf("%v is not an integrity error", err)
			}
		})
	}
}

func TestBlindIndex(t *testing.T) {
	f := newFixture(t)
	u1, u2 := bson.NewObjectID(), bson.NewObjectID()
	a, _ := f.svc.blindIndex(u1, "bakti-keluarga")
	b, _ := f.svc.blindIndex(u1, "bakti-keluarga")
	if !bytes.Equal(a, b) || len(a) != 32 {
		t.Error("index is not a deterministic 32-byte HMAC")
	}
	for _, other := range [][2]any{{u2, "bakti-keluarga"}, {u1, "prestasi-nusantara"}} {
		c, _ := f.svc.blindIndex(other[0].(bson.ObjectID), other[1].(string))
		if bytes.Equal(a, c) {
			t.Errorf("index collides for %v", other)
		}
	}
	for _, key := range [][]byte{nil, make([]byte, 16)} {
		f.svc.indexKey = key
		if _, err := f.svc.blindIndex(u1, "bakti-keluarga"); err == nil {
			t.Errorf("a %d-byte key was accepted", len(key))
		}
	}
}

func TestReadinessAndCards(t *testing.T) {
	f := newFixture(t)
	user := bson.NewObjectID()
	f.docs[user] = allDocuments()[:4]
	r, err := f.svc.Readiness(context.Background(), user)
	if err != nil {
		t.Fatal(err)
	}
	if r.Ready() || r.Uploaded != 4 || r.Total != 6 || len(r.Missing) != 2 || r.MissingCount() != 3 {
		t.Errorf("readiness %+v, missing count %d", r, r.MissingCount())
	}

	sub := map[string]time.Time{"bakti-keluarga": fixedNow}
	cards := BuildCards(true, r, sub, fixedNow)
	if cards[0].State != StateIncomplete || cards[0].Missing != 3 || cards[1].State != StateSubmitted {
		t.Errorf("cards %+v", cards)
	}
	ready := Readiness{HasProfile: true, Uploaded: 6, Total: 6}
	if c := BuildCards(true, ready, nil, fixedNow); c[0].State != StateReady {
		t.Errorf("ready card %q", c[0].State)
	}
	late := time.Date(2027, time.March, 1, 0, 0, 0, 0, time.UTC)
	if c := BuildCards(true, ready, sub, late); c[0].State != StateClosed || c[1].State != StateSubmitted {
		t.Errorf("after deadline: %q, %q", c[0].State, c[1].State)
	}
	for _, c := range BuildCards(false, Readiness{}, nil, fixedNow) {
		if c.State != StateGuest {
			t.Errorf("guest card %q", c.State)
		}
	}
}
