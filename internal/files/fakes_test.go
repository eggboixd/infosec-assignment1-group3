package files

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/eggboixd/infosec-assignment1-group3/internal/benchmark"
	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
)

// memObjects is an in-memory ObjectStore. failPut, if set, makes Put fail
// for the keys it returns an error for. The failure comes after the whole
// stream is read (like MinIO rejecting the final commit), so the other
// variants finish and must be cleaned up.
//
// Like minio-go, a Put whose stream fails aborts the multipart upload with
// Put's context; if that context is already done the abort cannot be sent
// and the incomplete upload is counted in leaked.
type memObjects struct {
	mu      sync.Mutex
	objs    map[string][]byte
	failPut func(key string) error
	leaked  int
}

func newMemObjects() *memObjects { return &memObjects{objs: map[string][]byte{}} }

var errNoObject = errors.New("memObjects: no such key")

func (m *memObjects) Put(ctx context.Context, key string, r io.Reader, _ int64, _ string) error {
	if m.failPut != nil {
		if err := m.failPut(key); err != nil {
			_, _ = io.Copy(io.Discard, r)
			return err
		}
	}
	b, err := io.ReadAll(r)
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		if ctx.Err() != nil {
			m.leaked++
		}
		return err
	}
	m.objs[key] = b
	return nil
}

func (m *memObjects) Leaked() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.leaked
}

type nopSeekCloser struct{ *bytes.Reader }

func (nopSeekCloser) Close() error { return nil }

func (m *memObjects) Get(_ context.Context, key string) (io.ReadSeekCloser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.objs[key]
	if !ok {
		return nil, errNoObject
	}
	return nopSeekCloser{bytes.NewReader(slices.Clone(b))}, nil
}

func (m *memObjects) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.objs, key)
	return nil
}

func (m *memObjects) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.objs)
}

// Tamper flips one bit of the stored object key.
func (m *memObjects) Tamper(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.objs[key][len(m.objs[key])/2] ^= 1
}

// memMeta is an in-memory metadataStore with the same owner scoping as
// Store.
type memMeta struct {
	mu         sync.Mutex
	recs       map[bson.ObjectID]FileRecord
	failInsert error
}

func newMemMeta() *memMeta { return &memMeta{recs: map[bson.ObjectID]FileRecord{}} }

func (m *memMeta) Insert(_ context.Context, rec *FileRecord) error {
	if m.failInsert != nil {
		return m.failInsert
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recs[rec.ID] = *rec
	return nil
}

func (m *memMeta) Get(_ context.Context, ownerID, id bson.ObjectID) (*FileRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.recs[id]
	if !ok || rec.OwnerID != ownerID {
		return nil, ErrNotFound
	}
	return &rec, nil
}

func (m *memMeta) ListByOwner(_ context.Context, ownerID bson.ObjectID) ([]FileRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []FileRecord
	for _, r := range m.recs {
		if r.OwnerID == ownerID {
			out = append(out, r)
		}
	}
	slices.SortFunc(out, func(a, b FileRecord) int { return b.CreatedAt.Compare(a.CreatedAt) })
	return out, nil
}

func (m *memMeta) Delete(_ context.Context, ownerID, id bson.ObjectID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.recs[id]
	if !ok || rec.OwnerID != ownerID {
		return ErrNotFound
	}
	delete(m.recs, id)
	return nil
}

func (m *memMeta) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.recs)
}

// memBench collects benchmark records. Like the MongoDB store, it fails on
// a done context.
type memBench struct {
	mu   sync.Mutex
	recs []benchmark.Record
}

func (b *memBench) Save(ctx context.Context, r benchmark.Record) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.recs = append(b.recs, r)
	return nil
}

func (b *memBench) Records() []benchmark.Record {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.recs)
}

// testRig is a Service wired to the fakes and a real Envelope.
type testRig struct {
	svc     *Service
	objects *memObjects
	meta    *memMeta
	bench   *memBench
}

func newTestRig(t *testing.T) *testRig {
	t.Helper()
	key := make([]byte, crypto.MasterKeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	enc, err := crypto.NewEnvelope(key)
	if err != nil {
		t.Fatal(err)
	}
	r := &testRig{objects: newMemObjects(), meta: newMemMeta(), bench: &memBench{}}
	r.svc = NewService(r.meta, r.objects, enc, r.bench)
	// Strictly increasing timestamps, so list order is deterministic.
	clock := time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	r.svc.now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		clock = clock.Add(time.Second)
		return clock
	}
	return r
}

// sample reads a fake test file from scripts/testdata.
func sample(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "scripts", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// setMaxSize lowers a kind's size limit for the rest of the test.
func setMaxSize(t *testing.T, k Kind, n int64) {
	t.Helper()
	old := maxSize[k]
	maxSize[k] = n
	t.Cleanup(func() { maxSize[k] = old })
}
