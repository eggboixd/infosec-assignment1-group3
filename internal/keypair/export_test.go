package keypair

import (
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// NewTestService returns a Service backed by an in-memory store, with a
// cheap KDF and the cached test keys, for the tests in package keypair_test.
func NewTestService(t *testing.T) *Service {
	t.Helper()
	s, _, _ := newTestService(t)
	return s
}

// TamperPublicKey flips one byte of the stored public key of purpose p.
func TamperPublicKey(t *testing.T, s *Service, userID bson.ObjectID, p Purpose) {
	t.Helper()
	st := s.store.(*memStore)
	d := st.get(t, userID)
	sp, err := d.pair(p)
	if err != nil {
		t.Fatal(err)
	}
	sp.PublicDER[40] ^= 1
	st.put(t, d)
}
