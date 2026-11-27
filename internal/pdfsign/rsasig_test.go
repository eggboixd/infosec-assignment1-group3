package pdfsign

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // only to show that a non-SHA-256 request is refused
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"testing"
)

// The standard library's rsa.SignPKCS1v15 and rsa.VerifyPKCS1v15 appear
// ONLY in this file, as an independent reference for our implementation.

func digestOf(b []byte) []byte {
	d := sha256.Sum256(b)
	return d[:]
}

// messages covers the edge sizes from CLAUDE.md. What is signed is always
// the 32-byte digest, but the sizes make sure nothing depends on the input.
func testMessages(t *testing.T) map[string][]byte {
	t.Helper()
	large := make([]byte, 1<<20+13)
	if _, err := rand.Read(large); err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{"0 B": {}, "large odd": large}
	for _, n := range []int{1, 7, 8, 9, 15, 16, 17, 255, 256, 257} {
		b := make([]byte, n)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		out[fmt.Sprintf("%d B", n)] = b
	}
	return out
}

func TestEncodeEMSALayout(t *testing.T) {
	digest := digestOf([]byte("abc"))
	for _, k := range []int{62, 256, 384, 512} {
		em, err := encodeEMSA(digest, k)
		if err != nil {
			t.Fatalf("k=%d: %v", k, err)
		}
		if len(em) != k || em[0] != 0x00 || em[1] != 0x01 {
			t.Fatalf("k=%d: bad header % x", k, em[:2])
		}
		psLen := k - 3 - len(digestInfoSHA256) - len(digest)
		if psLen < minPadding {
			t.Fatalf("k=%d: padding %d < 8", k, psLen)
		}
		for i := 2; i < 2+psLen; i++ {
			if em[i] != 0xFF {
				t.Fatalf("k=%d: em[%d] = %#x, want 0xFF", k, i, em[i])
			}
		}
		if em[2+psLen] != 0x00 {
			t.Fatalf("k=%d: missing 0x00 separator", k)
		}
		if !bytes.Equal(em[3+psLen:k-32], digestInfoSHA256) || !bytes.Equal(em[k-32:], digest) {
			t.Fatalf("k=%d: wrong DigestInfo or digest", k)
		}
	}
}

func TestEncodeEMSARejects(t *testing.T) {
	digest := digestOf(nil)
	// 51-byte T + 3 fixed bytes + 8 bytes of padding = 62: one less fails.
	if _, err := encodeEMSA(digest, 61); !errors.Is(err, errBadKey) {
		t.Errorf("k=61: err = %v, want errBadKey", err)
	}
	for _, n := range []int{0, 20, 31, 33, 64} {
		if _, err := encodeEMSA(make([]byte, n), 384); !errors.Is(err, errDigestSize) {
			t.Errorf("%d-byte digest: err = %v, want errDigestSize", n, err)
		}
	}
}

// PKCS #1 v1.5 signatures are deterministic, so ours must equal the
// standard library's byte for byte, despite our random blinding.
func TestSignMatchesStdlib(t *testing.T) {
	a, _, c := testKeys(t)
	for _, key := range []*rsa.PrivateKey{a, c} {
		for name, msg := range testMessages(t) {
			d := digestOf(msg)
			ours, err := signDigest(key, d)
			if err != nil {
				t.Fatalf("%d bits, %s: sign: %v", key.N.BitLen(), name, err)
			}
			ref, err := rsa.SignPKCS1v15(nil, key, crypto.SHA256, d)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(ours, ref) {
				t.Fatalf("%d bits, %s: our signature differs from crypto/rsa", key.N.BitLen(), name)
			}
			if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, d, ours); err != nil {
				t.Fatalf("%d bits, %s: crypto/rsa rejects our signature: %v", key.N.BitLen(), name, err)
			}
		}
	}
}

func TestVerifyAcceptsStdlibSignatures(t *testing.T) {
	a, _, c := testKeys(t)
	for _, key := range []*rsa.PrivateKey{a, c} {
		for name, msg := range testMessages(t) {
			d := digestOf(msg)
			ref, err := rsa.SignPKCS1v15(nil, key, crypto.SHA256, d)
			if err != nil {
				t.Fatal(err)
			}
			if err := verifyDigest(&key.PublicKey, d, ref); err != nil {
				t.Fatalf("%d bits, %s: we reject a crypto/rsa signature: %v", key.N.BitLen(), name, err)
			}
		}
	}
}

func TestVerifyRejects(t *testing.T) {
	a, b, _ := testKeys(t)
	d := digestOf([]byte("the signed bytes"))
	sig, err := signDigest(a, d)
	if err != nil {
		t.Fatal(err)
	}
	k := len(sig)
	flipped := bytes.Clone(sig)
	flipped[k/2] ^= 0x01
	otherDigest := bytes.Clone(d)
	otherDigest[0] ^= 0x80
	nBytes := a.N.FillBytes(make([]byte, k))
	nPlus1 := new(big.Int).Add(a.N, big.NewInt(1)).FillBytes(make([]byte, k))
	sPlusN := new(big.Int).Add(new(big.Int).SetBytes(sig), a.N)

	cases := []struct {
		name   string
		pub    *rsa.PublicKey
		digest []byte
		sig    []byte
	}{
		{"wrong key", &b.PublicKey, d, sig},
		{"other digest", &a.PublicKey, otherDigest, sig},
		{"flipped bit", &a.PublicKey, d, flipped},
		{"all zero", &a.PublicKey, d, make([]byte, k)},
		{"s = 1", &a.PublicKey, d, big.NewInt(1).FillBytes(make([]byte, k))},
		{"s = n", &a.PublicKey, d, nBytes},
		{"s = n+1", &a.PublicKey, d, nPlus1},
		{"all FF (s > n)", &a.PublicKey, d, bytes.Repeat([]byte{0xFF}, k)},
		{"empty", &a.PublicKey, d, nil},
		{"truncated (k-1)", &a.PublicKey, d, sig[:k-1]},
		{"leading zero (k+1)", &a.PublicKey, d, append([]byte{0}, sig...)},
		{"trailing byte (k+1)", &a.PublicKey, d, append(bytes.Clone(sig), 0)},
		// s + n is the same value mod n but not the canonical encoding.
		{"s + n", &a.PublicKey, d, sPlusN.Bytes()},
	}
	for _, tc := range cases {
		if err := verifyDigest(tc.pub, tc.digest, tc.sig); !errors.Is(err, ErrBadSignature) {
			t.Errorf("%s: err = %v, want ErrBadSignature", tc.name, err)
		}
	}
	if err := verifyDigest(&a.PublicKey, d[:31], sig); !errors.Is(err, errDigestSize) {
		t.Errorf("31-byte digest: err = %v, want errDigestSize", err)
	}
}

func TestVerifyRejectsBadKeys(t *testing.T) {
	a, _, _ := testKeys(t)
	d := digestOf(nil)
	sig, err := signDigest(a, d)
	if err != nil {
		t.Fatal(err)
	}
	small := new(big.Int).Lsh(big.NewInt(1), 1023)
	small.Add(small, big.NewInt(1)) // 1024-bit odd modulus
	huge := new(big.Int).Lsh(big.NewInt(1), maxKeyBits)
	huge.Add(huge, big.NewInt(1))
	even := new(big.Int).Add(a.N, big.NewInt(1))

	for name, pub := range map[string]*rsa.PublicKey{
		"nil":         nil,
		"nil modulus": {E: 65537},
		"1024-bit":    {N: small, E: 65537},
		"8193-bit":    {N: huge, E: 65537},
		"even n":      {N: even, E: 65537},
		// e = 1 makes s^e = s, so anyone could "sign" by writing the
		// expected encoding as the signature.
		"e = 1":    {N: a.N, E: 1},
		"e = 2":    {N: a.N, E: 2},
		"e even":   {N: a.N, E: 65536},
		"e = 0":    {N: a.N, E: 0},
		"e < 0":    {N: a.N, E: -3},
		"zero n":   {N: new(big.Int), E: 65537},
		"neg n":    {N: new(big.Int).Neg(a.N), E: 65537},
		"too long": {N: new(big.Int).Lsh(a.N, maxKeyBits), E: 65537},
	} {
		if err := verifyDigest(pub, d, sig); !errors.Is(err, errBadKey) {
			t.Errorf("%s: err = %v, want errBadKey", name, err)
		}
	}
}

// naiveParseVerify is the kind of verifier Bleichenbacher (2006) broke: it
// parses the block (skip 0xFF bytes, find 0x00, check the DigestInfo and the
// hash that follow) and ignores whatever comes after. It exists only to
// show what our verifier refuses.
func naiveParseVerify(pub *rsa.PublicKey, digest, sig []byte) bool {
	s := new(big.Int).SetBytes(sig)
	em := new(big.Int).Exp(s, big.NewInt(int64(pub.E)), pub.N).FillBytes(make([]byte, len(sig)))
	if em[0] != 0 || em[1] != 1 {
		return false
	}
	i := 2
	for i < len(em) && em[i] == 0xFF {
		i++
	}
	if i >= len(em) || em[i] != 0 {
		return false
	}
	rest := em[i+1:]
	return bytes.HasPrefix(rest, digestInfoSHA256) &&
		bytes.HasPrefix(rest[len(digestInfoSHA256):], digest)
}

// rawSign computes EM^d mod n directly, so the test can produce a
// "signature" of a malformed block (which our signer never would).
func rawSign(priv *rsa.PrivateKey, em []byte) []byte {
	m := new(big.Int).SetBytes(em)
	return new(big.Int).Exp(m, priv.D, priv.N).FillBytes(make([]byte, len(em)))
}

// Blocks that contain the right hash but are not the one valid encoding
// must be rejected. The first shows why we compare instead of parsing:
// a parsing verifier accepts it.
func TestVerifyRejectsMalformedEncodings(t *testing.T) {
	a, _, _ := testKeys(t)
	d := digestOf([]byte("pay 100"))
	k := (a.N.BitLen() + 7) / 8
	good, err := encodeEMSA(d, k)
	if err != nil {
		t.Fatal(err)
	}

	// Short padding, then DigestInfo ‖ hash, then garbage to fill k bytes.
	garbageAfter := make([]byte, k)
	garbageAfter[1] = 0x01
	for i := 2; i < 2+minPadding; i++ {
		garbageAfter[i] = 0xFF
	}
	pos := 2 + minPadding + 1
	pos += copy(garbageAfter[pos:], digestInfoSHA256)
	pos += copy(garbageAfter[pos:], d)
	for i := pos; i < k; i++ {
		garbageAfter[i] = 0x5A
	}
	sigGarbage := rawSign(a, garbageAfter)
	if !naiveParseVerify(&a.PublicKey, d, sigGarbage) {
		t.Fatal("test setup: the naive verifier should accept the garbage-after-hash block")
	}

	// DigestInfo without the NULL parameters (another "valid-looking" ASN.1).
	noNull := bytes.Clone(good)
	tNoNull := append([]byte{0x30, 0x2f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x04, 0x20}, d...)
	for i := 2; i < k-len(tNoNull)-1; i++ {
		noNull[i] = 0xFF
	}
	noNull[k-len(tNoNull)-1] = 0x00
	copy(noNull[k-len(tNoNull):], tNoNull)

	blockType2 := bytes.Clone(good)
	blockType2[1] = 0x02
	padNotFF := bytes.Clone(good)
	padNotFF[10] = 0xFE

	for name, em := range map[string][]byte{
		"garbage after hash":      garbageAfter,
		"DigestInfo without NULL": noNull,
		"block type 2":            blockType2,
		"padding byte not FF":     padNotFF,
	} {
		if err := verifyDigest(&a.PublicKey, d, rawSign(a, em)); !errors.Is(err, ErrBadSignature) {
			t.Errorf("%s: err = %v, want ErrBadSignature", name, err)
		}
	}
	// And the correct block, signed the same raw way, is accepted.
	if err := verifyDigest(&a.PublicKey, d, rawSign(a, good)); err != nil {
		t.Errorf("correct block: %v", err)
	}
}

// A signature that fails our own check is never returned (fault defence).
func TestSignDiscardsFaultySignature(t *testing.T) {
	a, _, _ := testKeys(t)
	faulty := *a
	faulty.D = new(big.Int).Add(a.D, big.NewInt(2)) // simulate a corrupted exponent
	sig, err := signDigest(&faulty, digestOf([]byte("x")))
	if !errors.Is(err, errSelfCheck) || sig != nil {
		t.Fatalf("got sig=%v err=%v, want nil and errSelfCheck", sig != nil, err)
	}
}

func TestSignRejectsBadInput(t *testing.T) {
	a, _, _ := testKeys(t)
	if _, err := signDigest(a, make([]byte, 31)); !errors.Is(err, errDigestSize) {
		t.Errorf("short digest: %v", err)
	}
	if _, err := signDigest(nil, digestOf(nil)); !errors.Is(err, errBadKey) {
		t.Errorf("nil key: %v", err)
	}
	noD := *a
	noD.D = nil
	if _, err := signDigest(&noD, digestOf(nil)); !errors.Is(err, errBadKey) {
		t.Errorf("no D: %v", err)
	}
	weak := *a
	weak.E = 1
	if _, err := signDigest(&weak, digestOf(nil)); !errors.Is(err, errBadKey) {
		t.Errorf("e = 1: %v", err)
	}
}

func TestRSASignerInterface(t *testing.T) {
	a, _, _ := testKeys(t)
	var s crypto.Signer = rsaSigner{priv: a}
	if !a.PublicKey.Equal(s.Public()) {
		t.Fatal("Public() is not the key's public key")
	}
	d := digestOf([]byte("certificate TBS bytes"))
	sig, err := s.Sign(rand.Reader, d, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if err := rsa.VerifyPKCS1v15(&a.PublicKey, crypto.SHA256, d, sig); err != nil {
		t.Fatalf("crypto/rsa rejects rsaSigner output: %v", err)
	}

	sha1Digest := sha1.Sum([]byte("x"))
	for name, call := range map[string]func() ([]byte, error){
		"PSS":                           func() ([]byte, error) { return s.Sign(rand.Reader, d, &rsa.PSSOptions{Hash: crypto.SHA256}) },
		"SHA-1":                         func() ([]byte, error) { return s.Sign(rand.Reader, sha1Digest[:], crypto.SHA1) },
		"nil opts":                      func() ([]byte, error) { return s.Sign(rand.Reader, d, nil) },
		"SHA-256 with a 20-byte digest": func() ([]byte, error) { return s.Sign(rand.Reader, sha1Digest[:], crypto.SHA256) },
	} {
		if sig, err := call(); err == nil || sig != nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
