package keypair

import (
	"bytes"
	"context"
	"sync"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// memStore is an in-memory keyStore that enforces the unique user_id index.
// It keeps each document as BSON bytes, so every test also round-trips the
// real MongoDB encoding (uint fields, millisecond dates) and no caller can
// change a stored document through a shared slice.
type memStore struct {
	mu      sync.Mutex
	docs    map[bson.ObjectID][]byte
	findErr error // returned by FindByUserID when set
}

func newMemStore() *memStore { return &memStore{docs: map[bson.ObjectID][]byte{}} }

func (m *memStore) Insert(_ context.Context, d *Document) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.docs[d.UserID]; ok {
		return errExists
	}
	d.ID = bson.NewObjectID()
	b, err := bson.Marshal(d)
	if err != nil {
		return err
	}
	m.docs[d.UserID] = b
	return nil
}

func (m *memStore) FindByUserID(_ context.Context, userID bson.ObjectID) (*Document, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.findErr != nil {
		return nil, m.findErr
	}
	b, ok := m.docs[userID]
	if !ok {
		return nil, ErrNoKeys
	}
	var d Document
	if err := bson.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

func (m *memStore) ReplaceWrapped(_ context.Context, userID bson.ObjectID, oldSalt []byte, kdf KDFParams, enc, sign []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.docs[userID]
	if !ok {
		return errConflict
	}
	var d Document
	if err := bson.Unmarshal(b, &d); err != nil {
		return err
	}
	if !bytes.Equal(d.KDF.Salt, oldSalt) {
		return errConflict
	}
	d.KDF, d.Encryption.WrappedPrivate, d.Signing.WrappedPrivate = kdf, enc, sign
	nb, err := bson.Marshal(&d)
	if err != nil {
		return err
	}
	m.docs[userID] = nb
	return nil
}

// get returns a copy of the stored document.
func (m *memStore) get(t *testing.T, userID bson.ObjectID) *Document {
	t.Helper()
	d, err := m.FindByUserID(context.Background(), userID)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// put replaces the stored document, for tampering tests.
func (m *memStore) put(t *testing.T, d *Document) {
	t.Helper()
	b, err := bson.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.docs[d.UserID] = b
}

func (m *memStore) len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.docs)
}
