package sharekey

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"sync"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
	"github.com/eggboixd/infosec-assignment1-group3/internal/files"
	"github.com/eggboixd/infosec-assignment1-group3/internal/keypair"
	"github.com/eggboixd/infosec-assignment1-group3/internal/profile"
	"github.com/eggboixd/infosec-assignment1-group3/internal/sharing"
)

// memStore is an in-memory materialStore.
type memStore struct {
	mu sync.Mutex
	m  map[bson.ObjectID]*Material // by request ID
}

func newMemStore() *memStore { return &memStore{m: map[bson.ObjectID]*Material{}} }

func (s *memStore) Insert(_ context.Context, m *Material) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[m.RequestID]; ok {
		return errExists
	}
	m.ID = bson.NewObjectID()
	// Store a BSON round-trip copy, so every test also checks that
	// Material encodes and decodes the way MongoDB will store it.
	raw, err := bson.Marshal(m)
	if err != nil {
		return err
	}
	var cp Material
	if err := bson.Unmarshal(raw, &cp); err != nil {
		return err
	}
	s.m[m.RequestID] = &cp
	return nil
}

func (s *memStore) Exists(_ context.Context, id bson.ObjectID) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.m[id]
	return ok, nil
}

func (s *memStore) Find(_ context.Context, id bson.ObjectID, actor string, actorID bson.ObjectID) (*Material, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.m[id]
	if !ok || (actor == actorOwner && m.OwnerID != actorID) || (actor == actorRequester && m.RequesterID != actorID) {
		return nil, ErrNotFound
	}
	cp := *m
	return &cp, nil
}

func (s *memStore) SetImported(_ context.Context, id, requesterID bson.ObjectID, sealed []byte, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.m[id]
	if !ok || m.RequesterID != requesterID {
		return ErrNotFound
	}
	m.ImportedKey, m.ImportedAt = sealed, &at
	return nil
}

func (s *memStore) Delete(_ context.Context, id bson.ObjectID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, id)
	return nil
}

// raw returns the stored material itself, for tests that tamper with it.
func (s *memStore) raw(id bson.ObjectID) *Material {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[id]
}

// fakeKeys holds one RSA key and password per user.
type fakeKeys struct {
	priv map[bson.ObjectID]*rsa.PrivateKey
	pass map[bson.ObjectID]string
}

func (k *fakeKeys) PublicKey(_ context.Context, id bson.ObjectID, p keypair.Purpose) (*rsa.PublicKey, error) {
	if p != keypair.Encryption {
		return nil, keypair.ErrUnknownPurpose
	}
	priv, ok := k.priv[id]
	if !ok {
		return nil, keypair.ErrNoKeys
	}
	return &priv.PublicKey, nil
}

func (k *fakeKeys) Unlock(_ context.Context, id bson.ObjectID, password string, p keypair.Purpose) (*rsa.PrivateKey, error) {
	if p != keypair.Encryption {
		return nil, keypair.ErrUnknownPurpose
	}
	priv, ok := k.priv[id]
	if !ok {
		return nil, keypair.ErrNoKeys
	}
	if password != k.pass[id] {
		return nil, keypair.ErrUnlock
	}
	return priv, nil
}

type fakeProfiles map[bson.ObjectID]*profile.Profile

func (f fakeProfiles) FindByUserID(_ context.Context, id bson.ObjectID) (*profile.Profile, error) {
	if p, ok := f[id]; ok {
		return p, nil
	}
	return nil, profile.ErrNotFound
}

type fakeFiles map[bson.ObjectID][]files.FileRecord

func (f fakeFiles) ListByOwner(_ context.Context, id bson.ObjectID) ([]files.FileRecord, error) {
	return f[id], nil
}

type fakeObjects map[string][]byte

type nopCloser struct{ *bytes.Reader }

func (nopCloser) Close() error { return nil }

func (f fakeObjects) Get(_ context.Context, key string) (io.ReadSeekCloser, error) {
	b, ok := f[key]
	if !ok {
		return nil, ErrNotFound
	}
	return nopCloser{bytes.NewReader(b)}, nil
}

// testUser is a test account with keys.
type testUser struct {
	id       bson.ObjectID
	password string
}

// env is a Service over fakes, with an owner who has a profile and two
// files, and two other users with keys.
type env struct {
	svc      *Service
	store    *memStore
	keys     *fakeKeys
	enc      *crypto.Envelope
	profiles fakeProfiles
	files    fakeFiles
	objects  fakeObjects
	owner    testUser
	alice    testUser
	eve      testUser
	data     profile.PrivateData
	plain    map[bson.ObjectID][]byte // file ID -> content
	names    map[bson.ObjectID]string // file ID -> name
}

// testRSA is generated once: RSA key generation is slow, and the tests only
// need distinct keys, not fresh ones per test.
var (
	testRSAOnce sync.Once
	testRSA     []*rsa.PrivateKey
)

func rsaKeys(t *testing.T) []*rsa.PrivateKey {
	t.Helper()
	testRSAOnce.Do(func() {
		for range 3 {
			k, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				panic(err)
			}
			testRSA = append(testRSA, k)
		}
	})
	return testRSA
}

func newEnv(t *testing.T) *env {
	t.Helper()
	master := make([]byte, crypto.MasterKeySize)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	enc, err := crypto.NewEnvelope(master)
	if err != nil {
		t.Fatal(err)
	}
	keys := rsaKeys(t)
	e := &env{
		store: newMemStore(), enc: enc,
		keys:     &fakeKeys{priv: map[bson.ObjectID]*rsa.PrivateKey{}, pass: map[bson.ObjectID]string{}},
		profiles: fakeProfiles{}, files: fakeFiles{}, objects: fakeObjects{},
		owner: testUser{bson.NewObjectID(), "owner-password"},
		alice: testUser{bson.NewObjectID(), "alice-password"},
		eve:   testUser{bson.NewObjectID(), "eve-password"},
		plain: map[bson.ObjectID][]byte{}, names: map[bson.ObjectID]string{},
		data: profile.PrivateData{
			FullName: "Budi Santoso", NIK: "3374010101990001", DateOfBirth: "1999-01-01",
			Address: "Jl. Pemuda 1, Semarang", Phone: "081234567890", Email: "budi@example.com",
		},
	}
	for i, u := range []testUser{e.owner, e.alice, e.eve} {
		e.keys.priv[u.id] = keys[i]
		e.keys.pass[u.id] = u.password
	}
	e.profiles[e.owner.id] = e.sealProfile(t, e.data)
	e.addFile(t, "ktp.png", files.KindIDCard, files.SlotKTP, bytes.Repeat([]byte("PNG-ish "), 9000))
	e.addFile(t, "cv.pdf", files.KindDocument, files.SlotCV, []byte("%PDF-1.7 a short cv"))

	e.svc, err = NewService(e.store, e.keys, e.profiles, e.files, e.objects, master)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) sealSet(t *testing.T, v string) crypto.SealedSet {
	t.Helper()
	set := crypto.SealedSet{}
	for _, alg := range crypto.All() {
		ct, meta, err := e.enc.EncryptField(alg, []byte(v))
		if err != nil {
			t.Fatal(err)
		}
		set[alg] = crypto.Sealed{Ciphertext: ct, Meta: meta}
	}
	return set
}

func (e *env) sealProfile(t *testing.T, d profile.PrivateData) *profile.Profile {
	t.Helper()
	return &profile.Profile{
		UserID: e.owner.id, FullName: e.sealSet(t, d.FullName), NIK: e.sealSet(t, d.NIK),
		DateOfBirth: e.sealSet(t, d.DateOfBirth), Address: e.sealSet(t, d.Address),
		Phone: e.sealSet(t, d.Phone), Email: e.sealSet(t, d.Email),
	}
}

func (e *env) addFile(t *testing.T, name string, kind files.Kind, slot files.Slot, content []byte) {
	t.Helper()
	rec := files.FileRecord{
		ID: bson.NewObjectID(), OwnerID: e.owner.id, Kind: kind, Slot: slot,
		FileName: e.sealSet(t, name), MIMEType: "application/octet-stream", Size: int64(len(content)),
		Variants: map[crypto.Algorithm]files.Variant{},
	}
	for _, alg := range crypto.All() {
		var ct bytes.Buffer
		meta, err := e.enc.Encrypt(context.Background(), alg, &ct, bytes.NewReader(content))
		if err != nil {
			t.Fatal(err)
		}
		key := rec.ID.Hex() + "/" + string(alg)
		e.objects[key] = ct.Bytes()
		rec.Variants[alg] = files.Variant{ObjectKey: key, Meta: meta, CiphertextSize: int64(ct.Len())}
	}
	e.files[e.owner.id] = append(e.files[e.owner.id], rec)
	e.plain[rec.ID] = content
	e.names[rec.ID] = name
}

// grant approves a new request from requester to the owner and returns it
// as sharing.Service.Active would.
func (e *env) grant(t *testing.T, requester testUser) *sharing.Request {
	t.Helper()
	req := &sharing.Request{
		ID: bson.NewObjectID(), OwnerID: e.owner.id, RequesterID: requester.id,
		Status: sharing.StatusApproved, ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	err := e.svc.Grant(context.Background(), sharing.Grant{
		RequestID: req.ID, OwnerID: req.OwnerID, RequesterID: req.RequesterID, ExpiresAt: req.ExpiresAt,
	})
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	return req
}

// sentKey is the encrypted share key the owner would copy into WhatsApp.
func (e *env) sentKey(t *testing.T, req *sharing.Request) string {
	t.Helper()
	kv, err := e.svc.EncryptedKey(context.Background(), e.owner.id, req.ID)
	if err != nil {
		t.Fatalf("EncryptedKey: %v", err)
	}
	return kv.Encoded
}
