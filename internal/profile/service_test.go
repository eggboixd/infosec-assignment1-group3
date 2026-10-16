package profile

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/eggboixd/infosec-assignment1-group3/internal/benchmark"
	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
)

// memStore is an in-memory profileStore that behaves like the MongoDB
// collection: profiles round-trip through BSON, and the unique indexes on
// user_id and nik_index are enforced.
type memStore struct {
	mu   sync.Mutex
	docs map[bson.ObjectID][]byte // user ID -> BSON document
}

func newMemStore() *memStore { return &memStore{docs: map[bson.ObjectID][]byte{}} }

func (m *memStore) Upsert(_ context.Context, p *Profile) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for uid, raw := range m.docs {
		if uid == p.UserID {
			continue
		}
		var other Profile
		if err := bson.Unmarshal(raw, &other); err != nil {
			return err
		}
		if len(p.NIKIndex) > 0 && bytes.Equal(other.NIKIndex, p.NIKIndex) {
			return ErrNIKTaken
		}
	}
	doc := *p
	if doc.ID.IsZero() {
		doc.ID = bson.NewObjectID()
	}
	raw, err := bson.Marshal(doc)
	if err != nil {
		return err
	}
	m.docs[p.UserID] = raw
	return nil
}

func (m *memStore) FindByUserID(_ context.Context, userID bson.ObjectID) (*Profile, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	raw, ok := m.docs[userID]
	if !ok {
		return nil, ErrNotFound
	}
	var p Profile
	if err := bson.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// raw returns the stored BSON document, as an attacker reading the database
// would see it.
func (m *memStore) raw(userID bson.ObjectID) []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return bytes.Clone(m.docs[userID])
}

// edit lets a test tamper with a stored profile.
func (m *memStore) edit(t *testing.T, userID bson.ObjectID, fn func(p *Profile)) {
	t.Helper()
	p, err := m.FindByUserID(context.Background(), userID)
	if err != nil {
		t.Fatal(err)
	}
	fn(p)
	raw, err := bson.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	m.docs[userID] = raw
	m.mu.Unlock()
}

type memBench struct {
	mu      sync.Mutex
	records []benchmark.Record
	err     error
}

func (b *memBench) Save(_ context.Context, r benchmark.Record) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.err != nil {
		return b.err
	}
	b.records = append(b.records, r)
	return nil
}

func (b *memBench) take() []benchmark.Record {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := b.records
	b.records = nil
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

func newTestService(t *testing.T) (*Service, *memStore, *memBench) {
	t.Helper()
	enc, err := crypto.NewEnvelope(randomKey(t))
	if err != nil {
		t.Fatal(err)
	}
	store, bench := newMemStore(), &memBench{}
	svc := NewService(store, enc, randomKey(t), bench)
	svc.now = func() time.Time { return fixedNow }
	return svc, store, bench
}

func TestSaveGetRoundTripEveryAlgorithm(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	user := bson.NewObjectID()
	want := validData()
	if err := svc.Save(ctx, user, want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	for _, alg := range crypto.All() {
		t.Run(string(alg), func(t *testing.T) {
			got, err := svc.Get(ctx, user, alg)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if *got != want {
				t.Errorf("Get(%s) = %+v, want %+v", alg, *got, want)
			}
		})
	}
}

// Field values around the DES (8 B) and AES (16 B) block sizes, empty, and
// long multi-byte UTF-8. CTR and RC4 need no padding, so every length must
// round-trip and the ciphertext must be exactly as long as the plaintext.
func TestSealFieldSizes(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	long := strings.Repeat("Jl. Kertajaya Indah é 漢字 ", 11)[:301] // odd length, multi-byte
	for _, n := range []int{0, 1, 7, 8, 9, 15, 16, 17, 31, 33} {
		for _, alg := range crypto.All() {
			pt := strings.Repeat("a", n)
			sealed, err := svc.sealField(ctx, alg, pt)
			if err != nil {
				t.Fatalf("%s/%d: seal: %v", alg, n, err)
			}
			if len(sealed.Ciphertext) != n {
				t.Errorf("%s/%d: ciphertext len %d", alg, n, len(sealed.Ciphertext))
			}
			if sealed.Meta.Algorithm != alg {
				t.Errorf("%s/%d: meta alg %q", alg, n, sealed.Meta.Algorithm)
			}
			got, err := svc.openField(ctx, alg, crypto.SealedSet{alg: sealed})
			if err != nil || got != pt {
				t.Errorf("%s/%d: open = %q, %v", alg, n, got, err)
			}
		}
	}
	for _, alg := range crypto.All() {
		sealed, err := svc.sealField(ctx, alg, long)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := svc.openField(ctx, alg, crypto.SealedSet{alg: sealed}); err != nil || got != long {
			t.Errorf("%s/long: open = %q, %v", alg, got, err)
		}
	}
}

func TestSaveStoresThreeIndependentCiphertextsAndNoPlaintext(t *testing.T) {
	svc, store, _ := newTestService(t)
	ctx := context.Background()
	user := bson.NewObjectID()
	data := validData()
	if err := svc.Save(ctx, user, data); err != nil {
		t.Fatal(err)
	}

	raw := store.raw(user)
	for _, v := range []string{data.FullName, data.NIK, data.Address, data.Phone, data.Email, "Surabaya"} {
		if bytes.Contains(raw, []byte(v)) {
			t.Errorf("stored document contains plaintext %q", v)
		}
	}

	p, _ := store.FindByUserID(ctx, user)
	for name, set := range map[string]crypto.SealedSet{
		"full_name": p.FullName, "nik": p.NIK, "date_of_birth": p.DateOfBirth,
		"address": p.Address, "phone": p.Phone, "email": p.Email,
	} {
		if len(set) != 3 {
			t.Fatalf("%s: %d ciphertexts, want 3", name, len(set))
		}
		if bytes.Equal(set[crypto.AES].Ciphertext, set[crypto.RC4].Ciphertext) ||
			bytes.Equal(set[crypto.AES].Ciphertext, set[crypto.DES].Ciphertext) ||
			bytes.Equal(set[crypto.DES].Ciphertext, set[crypto.RC4].Ciphertext) {
			t.Errorf("%s: two algorithms produced the same ciphertext", name)
		}
		if len(set[crypto.AES].Meta.IV) != crypto.AESIVSize || len(set[crypto.DES].Meta.IV) != crypto.DESIVSize ||
			len(set[crypto.RC4].Meta.IV) != 0 {
			t.Errorf("%s: wrong IV sizes", name)
		}
	}
	if len(p.NIKIndex) != sha256Size {
		t.Errorf("nik_index len = %d, want %d", len(p.NIKIndex), sha256Size)
	}
}

const sha256Size = 32

func TestSaveTwiceGivesFreshCiphertextAndKeepsCreatedAt(t *testing.T) {
	svc, store, _ := newTestService(t)
	ctx := context.Background()
	user := bson.NewObjectID()
	if err := svc.Save(ctx, user, validData()); err != nil {
		t.Fatal(err)
	}
	first, _ := store.FindByUserID(ctx, user)

	later := fixedNow.Add(time.Hour)
	svc.now = func() time.Time { return later }
	if err := svc.Save(ctx, user, validData()); err != nil {
		t.Fatal(err)
	}
	second, _ := store.FindByUserID(ctx, user)

	if second.ID != first.ID {
		t.Errorf("ID changed: %v -> %v", first.ID, second.ID)
	}
	if !second.CreatedAt.Equal(first.CreatedAt) {
		t.Errorf("CreatedAt changed: %v -> %v", first.CreatedAt, second.CreatedAt)
	}
	if !second.UpdatedAt.Equal(later) {
		t.Errorf("UpdatedAt = %v, want %v", second.UpdatedAt, later)
	}
	// Same plaintext, fresh key and IV: nothing may repeat.
	for _, alg := range crypto.All() {
		a, b := first.NIK[alg], second.NIK[alg]
		if bytes.Equal(a.Ciphertext, b.Ciphertext) {
			t.Errorf("%s: same NIK encrypted twice gave identical ciphertext", alg)
		}
		if alg != crypto.RC4 && bytes.Equal(a.Meta.IV, b.Meta.IV) {
			t.Errorf("%s: IV reused", alg)
		}
		if bytes.Equal(a.Meta.WrappedDEK, b.Meta.WrappedDEK) {
			t.Errorf("%s: wrapped DEK reused", alg)
		}
	}
	// The blind index is deterministic, so it must not change.
	if !bytes.Equal(first.NIKIndex, second.NIKIndex) {
		t.Error("nik_index changed for the same NIK")
	}
}

func TestDuplicateNIKRejected(t *testing.T) {
	svc, _, bench := newTestService(t)
	ctx := context.Background()
	alice, bob := bson.NewObjectID(), bson.NewObjectID()

	if err := svc.Save(ctx, alice, validData()); err != nil {
		t.Fatal(err)
	}
	bench.take()

	dup := validData()
	dup.FullName, dup.Email = "Someone Else", "else@example.com"
	dup.NIK = " " + dup.NIK + " " // normalised before hashing
	if err := svc.Save(ctx, bob, dup); !errors.Is(err, ErrNIKTaken) {
		t.Fatalf("Save(bob, alice's NIK) = %v, want ErrNIKTaken", err)
	}
	if _, err := svc.Get(ctx, bob, crypto.AES); !errors.Is(err, ErrNotFound) {
		t.Errorf("bob's profile exists after rejected save: %v", err)
	}
	if recs := bench.take(); len(recs) != 0 {
		t.Errorf("rejected save stored %d benchmark records", len(recs))
	}

	// Re-saving your own NIK is fine.
	if err := svc.Save(ctx, alice, validData()); err != nil {
		t.Errorf("alice re-saving her own NIK: %v", err)
	}
	// A different NIK for bob is fine.
	other := validData()
	other.NIK = "3578010101990002"
	if err := svc.Save(ctx, bob, other); err != nil {
		t.Errorf("bob with a different NIK: %v", err)
	}
}

func TestAnotherUsersProfileIsNotReadable(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	alice, mallory := bson.NewObjectID(), bson.NewObjectID()
	if err := svc.Save(ctx, alice, validData()); err != nil {
		t.Fatal(err)
	}
	for _, alg := range crypto.All() {
		got, err := svc.Get(ctx, mallory, alg)
		if !errors.Is(err, ErrNotFound) || got != nil {
			t.Errorf("Get(mallory, %s) = %v, %v; want nil, ErrNotFound", alg, got, err)
		}
	}
}

func TestGetUnknownAlgorithm(t *testing.T) {
	svc, _, _ := newTestService(t)
	ctx := context.Background()
	user := bson.NewObjectID()
	if err := svc.Save(ctx, user, validData()); err != nil {
		t.Fatal(err)
	}
	for _, alg := range []crypto.Algorithm{"", "xyz", "AES", "ecb", "3des"} {
		if _, err := svc.Get(ctx, user, alg); !errors.Is(err, crypto.ErrUnknownAlgorithm) {
			t.Errorf("Get(%q) = %v, want ErrUnknownAlgorithm", alg, err)
		}
	}
}

func TestGetTamperedProfileFailsClosed(t *testing.T) {
	tests := []struct {
		name    string
		tamper  func(p *Profile)
		alg     crypto.Algorithm
		wantErr error
	}{
		{"flipped ciphertext bit", func(p *Profile) {
			s := p.NIK[crypto.AES]
			s.Ciphertext[0] ^= 0x01
			p.NIK[crypto.AES] = s
		}, crypto.AES, crypto.ErrAuthentication},
		{"truncated ciphertext", func(p *Profile) {
			s := p.Email[crypto.DES]
			s.Ciphertext = s.Ciphertext[:len(s.Ciphertext)-1]
			p.Email[crypto.DES] = s
		}, crypto.DES, crypto.ErrAuthentication},
		{"flipped tag bit", func(p *Profile) {
			s := p.Phone[crypto.RC4]
			s.Meta.Tag[31] ^= 0x80
			p.Phone[crypto.RC4] = s
		}, crypto.RC4, crypto.ErrAuthentication},
		{"changed IV", func(p *Profile) {
			s := p.Address[crypto.AES]
			s.Meta.IV[0] ^= 0x01
			p.Address[crypto.AES] = s
		}, crypto.AES, crypto.ErrAuthentication},
		{"missing algorithm copy", func(p *Profile) {
			delete(p.FullName, crypto.DES)
		}, crypto.DES, ErrCorrupt},
		{"copy filed under the wrong algorithm", func(p *Profile) {
			p.DateOfBirth[crypto.AES] = p.DateOfBirth[crypto.RC4]
		}, crypto.AES, nil}, // any error is fine; see below
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, store, bench := newTestService(t)
			ctx := context.Background()
			user := bson.NewObjectID()
			if err := svc.Save(ctx, user, validData()); err != nil {
				t.Fatal(err)
			}
			bench.take()
			store.edit(t, user, tt.tamper)

			got, err := svc.Get(ctx, user, tt.alg)
			if err == nil || got != nil {
				t.Fatalf("Get = %+v, %v; want nil and an error", got, err)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("err = %v, want %v", err, tt.wantErr)
			}
			if recs := bench.take(); len(recs) != 0 {
				t.Errorf("failed Get stored %d benchmark records", len(recs))
			}
		})
	}
}

func TestSaveRejectsInvalidDataAndStoresNothing(t *testing.T) {
	svc, store, bench := newTestService(t)
	ctx := context.Background()
	user := bson.NewObjectID()
	bad := validData()
	bad.NIK = "12345"
	bad.Email = "not-an-email"
	err := svc.Save(ctx, user, bad)
	var verr *ValidationError
	if !errors.As(err, &verr) {
		t.Fatalf("Save = %v, want *ValidationError", err)
	}
	if len(verr.Messages) != 2 {
		t.Errorf("messages = %q, want 2", verr.Messages)
	}
	if _, err := store.FindByUserID(ctx, user); !errors.Is(err, ErrNotFound) {
		t.Errorf("invalid data was stored: %v", err)
	}
	if len(bench.take()) != 0 {
		t.Error("invalid data produced benchmark records")
	}
}

func TestBenchmarkRecords(t *testing.T) {
	svc, _, bench := newTestService(t)
	ctx := context.Background()
	user := bson.NewObjectID()
	data := validData()
	wantBytes := int64(len(data.FullName) + len(data.NIK) + len(data.DateOfBirth) +
		len(data.Address) + len(data.Phone) + len(data.Email))

	if err := svc.Save(ctx, user, data); err != nil {
		t.Fatal(err)
	}
	recs := bench.take()
	if len(recs) != 3 {
		t.Fatalf("Save stored %d records, want 3 (one per algorithm)", len(recs))
	}
	for i, alg := range crypto.All() {
		r := recs[i]
		if r.Algorithm != alg || r.Operation != benchmark.OpEncrypt || r.FileKind != "" {
			t.Errorf("record %d = %s/%s/%q, want %s/encrypt/\"\"", i, r.Algorithm, r.Operation, r.FileKind, alg)
		}
		if r.Bytes != wantBytes {
			t.Errorf("%s: Bytes = %d, want %d", alg, r.Bytes, wantBytes)
		}
		if r.CryptoDuration < 0 || r.TotalDuration < r.CryptoDuration {
			t.Errorf("%s: crypto %v, total %v", alg, r.CryptoDuration, r.TotalDuration)
		}
	}

	for _, alg := range crypto.All() {
		if _, err := svc.Get(ctx, user, alg); err != nil {
			t.Fatal(err)
		}
		recs := bench.take()
		if len(recs) != 1 || recs[0].Algorithm != alg || recs[0].Operation != benchmark.OpDecrypt || recs[0].Bytes != wantBytes {
			t.Errorf("Get(%s) records = %+v, want one %s/decrypt of %d bytes", alg, recs, alg, wantBytes)
		}
	}

	// A broken benchmark store must not break the user's request.
	bench.err = errors.New("benchmarks down")
	if err := svc.Save(ctx, user, data); err != nil {
		t.Errorf("Save with failing benchmark store: %v", err)
	}
	if _, err := svc.Get(ctx, user, crypto.AES); err != nil {
		t.Errorf("Get with failing benchmark store: %v", err)
	}
}

func TestNilBenchmarkSink(t *testing.T) {
	enc, err := crypto.NewEnvelope(randomKey(t))
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(newMemStore(), enc, randomKey(t), nil)
	user := bson.NewObjectID()
	if err := svc.Save(context.Background(), user, validData()); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Get(context.Background(), user, crypto.RC4); err != nil {
		t.Fatal(err)
	}
}

func TestNIKBlindIndex(t *testing.T) {
	key := randomKey(t)
	svc := &Service{blindKey: key}
	const nik = "3578010101990001"

	a, err := svc.nikBlindIndex(nik)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != sha256Size {
		t.Fatalf("len = %d, want %d", len(a), sha256Size)
	}
	if b, _ := svc.nikBlindIndex(nik); !bytes.Equal(a, b) {
		t.Error("same NIK gave different indexes")
	}
	if c, _ := svc.nikBlindIndex("3578010101990002"); bytes.Equal(a, c) {
		t.Error("different NIKs gave the same index")
	}
	other := &Service{blindKey: randomKey(t)}
	if d, _ := other.nikBlindIndex(nik); bytes.Equal(a, d) {
		t.Error("different keys gave the same index")
	}
	if bytes.Contains(a, []byte(nik)) {
		t.Error("index contains the NIK")
	}

	for _, bad := range []string{"", "357801010199000", "35780101019900011", "3578O10101990001", " 3578010101990001"} {
		if _, err := svc.nikBlindIndex(bad); err == nil {
			t.Errorf("nikBlindIndex(%q) succeeded, want error", bad)
		}
	}
	for _, k := range [][]byte{nil, make([]byte, 16), make([]byte, 33)} {
		s := &Service{blindKey: k}
		if _, err := s.nikBlindIndex(nik); err == nil {
			t.Errorf("key of %d bytes accepted", len(k))
		}
	}
}

func TestSaveWithoutBlindKeyFails(t *testing.T) {
	enc, err := crypto.NewEnvelope(randomKey(t))
	if err != nil {
		t.Fatal(err)
	}
	store := newMemStore()
	svc := NewService(store, enc, nil, nil)
	user := bson.NewObjectID()
	if err := svc.Save(context.Background(), user, validData()); err == nil {
		t.Fatal("Save without a blind-index key succeeded")
	}
	if _, err := store.FindByUserID(context.Background(), user); !errors.Is(err, ErrNotFound) {
		t.Error("profile stored without a NIK index")
	}
}
