package keypair

import (
	"crypto/rand"
	"crypto/rsa"
	"sync"
	"testing"
)

// testKeys are three real RSA-3072 keys, generated once per test binary.
// Generating a 3072-bit key takes up to a few seconds under the race
// detector, so tests share these instead of making new ones every time.
// TestEnsureKeysGeneratesRSA3072 still runs the real generator.
var testKeys = sync.OnceValues(func() ([3]*rsa.PrivateKey, error) {
	var ks [3]*rsa.PrivateKey
	for i := range ks {
		k, err := rsa.GenerateKey(rand.Reader, KeyBits)
		if err != nil {
			return ks, err
		}
		ks[i] = k
	}
	return ks, nil
})

// testKey returns cached key i (0, 1 or 2).
func testKey(t *testing.T, i int) *rsa.PrivateKey {
	t.Helper()
	ks, err := testKeys()
	if err != nil {
		t.Fatal(err)
	}
	return ks[i]
}

// useFastKDF lowers the Argon2id cost for the rest of the test. Keys made
// this way still unlock, because the cost is stored with them.
func useFastKDF(t *testing.T) {
	t.Helper()
	old := cost
	cost = kdfCost{time: 1, memory: 64, threads: 1}
	t.Cleanup(func() { cost = old })
}

// randomBytes returns n bytes from crypto/rand.
func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}
