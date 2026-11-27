package pdfsign

import (
	"crypto/rand"
	"crypto/rsa"
	"sync"
	"testing"
)

// Test keys are generated once per test binary: an RSA-3072 key takes up
// to a second or two to generate. They are throwaway keys that exist only
// in memory.
var (
	keysOnce sync.Once
	keyA     *rsa.PrivateKey // 3072-bit, the size the app uses
	keyB     *rsa.PrivateKey // another 3072-bit key: "wrong key"
	keyC     *rsa.PrivateKey // 2048-bit: minimum accepted size
	keysErr  error
)

func testKeys(t testing.TB) (a, b, c *rsa.PrivateKey) {
	t.Helper()
	keysOnce.Do(func() {
		if keyA, keysErr = rsa.GenerateKey(rand.Reader, 3072); keysErr != nil {
			return
		}
		if keyB, keysErr = rsa.GenerateKey(rand.Reader, 3072); keysErr != nil {
			return
		}
		keyC, keysErr = rsa.GenerateKey(rand.Reader, 2048)
	})
	if keysErr != nil {
		t.Fatalf("generate test keys: %v", keysErr)
	}
	return keyA, keyB, keyC
}
