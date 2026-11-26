package keypair

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

var (
	userA = bson.ObjectID{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xa}
	userB = bson.ObjectID{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xb}
)

func TestLengthPrefixedIsUnambiguous(t *testing.T) {
	if bytes.Equal(lengthPrefixed([]byte("ab"), []byte("c")), lengthPrefixed([]byte("a"), []byte("bc"))) {
		t.Error(`("ab","c") and ("a","bc") encode the same`)
	}
	if bytes.Equal(lengthPrefixed([]byte("a"), nil), lengthPrefixed([]byte("a"))) {
		t.Error("a trailing empty field is not encoded")
	}
}

// Sizes around the AES block size and a large odd size. GCM is a stream
// mode, so none of them needs padding.
func TestWrapRoundtrip(t *testing.T) {
	kek := randomBytes(t, kekSize)
	aad := wrapAAD(userA, Encryption, randomBytes(t, 32))
	for _, n := range []int{1, 7, 8, 9, 15, 16, 17, 1000, 2_345} {
		data := randomBytes(t, n)
		w, err := wrapPrivate(kek, data, aad)
		if err != nil {
			t.Fatalf("%d B: %v", n, err)
		}
		if len(w) != n+gcmOverhead {
			t.Errorf("%d B: wrapped is %d B, want %d", n, len(w), n+gcmOverhead)
		}
		got, err := unwrapPrivate(kek, w, aad)
		if err != nil || !bytes.Equal(got, data) {
			t.Errorf("%d B: roundtrip = %v, equal %v", n, err, bytes.Equal(got, data))
		}
	}
}

func TestWrapRefusesEmptyKeyAndBadKEK(t *testing.T) {
	if _, err := wrapPrivate(randomBytes(t, kekSize), nil, nil); err == nil {
		t.Error("wrapping 0 bytes succeeded")
	}
	for _, n := range []int{0, 16, 31, 33} {
		if _, err := wrapPrivate(make([]byte, n), []byte{1}, nil); err == nil {
			t.Errorf("wrapping under a %d-byte KEK succeeded", n)
		}
	}
}

func TestWrapIsRandomized(t *testing.T) {
	kek, data := randomBytes(t, kekSize), randomBytes(t, 100)
	a, _ := wrapPrivate(kek, data, nil)
	b, _ := wrapPrivate(kek, data, nil)
	if bytes.Equal(a, b) {
		t.Error("wrapping the same key twice gave the same bytes; want a fresh nonce")
	}
}

func TestUnwrapRejectsTampering(t *testing.T) {
	kek := randomBytes(t, kekSize)
	aad := wrapAAD(userA, Signing, randomBytes(t, 32))
	w, err := wrapPrivate(kek, randomBytes(t, 100), aad)
	if err != nil {
		t.Fatal(err)
	}
	flip := func(i int) []byte {
		c := bytes.Clone(w)
		c[i] ^= 0x01
		return c
	}
	tests := []struct {
		name string
		blob []byte
	}{
		{"nonce bit flipped", flip(0)},
		{"ciphertext bit flipped", flip(12 + 50)},
		{"tag bit flipped", flip(len(w) - 1)},
		{"empty", nil},
		{"1 byte", w[:1]},
		{"27 bytes", w[:27]},
		{"28 bytes (nonce + tag, no key)", w[:28]},
		{"29 bytes", w[:29]},
		{"last byte cut", w[:len(w)-1]},
		{"byte appended", append(bytes.Clone(w), 0)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := unwrapPrivate(kek, tt.blob, aad); !errors.Is(err, ErrUnlock) {
				t.Errorf("err = %v, want ErrUnlock", err)
			}
		})
	}
	if _, err := unwrapPrivate(randomBytes(t, kekSize), w, aad); !errors.Is(err, ErrUnlock) {
		t.Errorf("wrong KEK: err = %v, want ErrUnlock", err)
	}
}

// The AAD binds a wrapped key to its user, purpose and public key (D41).
func TestUnwrapRejectsOtherContext(t *testing.T) {
	kek, fp := randomBytes(t, kekSize), randomBytes(t, 32)
	w, err := wrapPrivate(kek, randomBytes(t, 100), wrapAAD(userA, Encryption, fp))
	if err != nil {
		t.Fatal(err)
	}
	for name, aad := range map[string][]byte{
		"another user":        wrapAAD(userB, Encryption, fp),
		"another purpose":     wrapAAD(userA, Signing, fp),
		"another public key":  wrapAAD(userA, Encryption, randomBytes(t, 32)),
		"no associated data":  nil,
		"unknown purpose":     wrapAAD(userA, "admin", fp),
		"truncated fingerpr.": wrapAAD(userA, Encryption, fp[:31]),
	} {
		if _, err := unwrapPrivate(kek, w, aad); !errors.Is(err, ErrUnlock) {
			t.Errorf("%s: err = %v, want ErrUnlock", name, err)
		}
	}
}

func TestStoredPairRoundtrip(t *testing.T) {
	kek, macKey := randomBytes(t, kekSize), randomBytes(t, PublicMACKeySize)
	priv := testKey(t, 0)
	now := time.Date(2026, 11, 26, 10, 0, 0, 123_456_789, time.UTC)
	sp, err := newStoredPair(kek, macKey, userA, Encryption, priv, now)
	if err != nil {
		t.Fatal(err)
	}

	wantDER, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if fp := sha256.Sum256(wantDER); !bytes.Equal(sp.PublicDER, wantDER) || !bytes.Equal(sp.Fingerprint, fp[:]) {
		t.Error("public DER or fingerprint wrong")
	}
	if !sp.CreatedAt.Equal(now.Truncate(time.Millisecond)) {
		t.Errorf("created_at = %v, want millisecond precision", sp.CreatedAt)
	}
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(priv)
	if bytes.Contains(sp.WrappedPrivate, pkcs8[:64]) {
		t.Fatal("wrapped private key contains plaintext PKCS#8 bytes")
	}

	pub, err := verifyPublic(macKey, userA, Encryption, &sp)
	if err != nil || !pub.Equal(&priv.PublicKey) {
		t.Fatalf("verifyPublic = %v", err)
	}
	got, err := unwrapPrivate(kek, sp.WrappedPrivate, wrapAAD(userA, Encryption, sp.Fingerprint))
	if err != nil || !bytes.Equal(got, pkcs8) {
		t.Fatalf("unwrap = %v, PKCS#8 equal %v", err, bytes.Equal(got, pkcs8))
	}
}

func TestVerifyPublicDetectsTampering(t *testing.T) {
	macKey := randomBytes(t, PublicMACKeySize)
	sp, err := newStoredPair(randomBytes(t, kekSize), macKey, userA, Signing, testKey(t, 1), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	other, _ := x509.MarshalPKIXPublicKey(&testKey(t, 0).PublicKey)
	otherFP := sha256.Sum256(other)

	tests := []struct {
		name   string
		user   bson.ObjectID
		p      Purpose
		mutate func(*StoredPair)
	}{
		{"DER byte flipped", userA, Signing, func(s *StoredPair) { s.PublicDER[40] ^= 1 }},
		{"public key swapped with matching fingerprint", userA, Signing, func(s *StoredPair) { s.PublicDER, s.Fingerprint = other, otherFP[:] }},
		{"fingerprint flipped", userA, Signing, func(s *StoredPair) { s.Fingerprint[0] ^= 1 }},
		{"created_at changed", userA, Signing, func(s *StoredPair) { s.CreatedAt = s.CreatedAt.Add(-time.Hour) }},
		{"MAC flipped", userA, Signing, func(s *StoredPair) { s.PublicMAC[0] ^= 1 }},
		{"MAC missing", userA, Signing, func(s *StoredPair) { s.PublicMAC = nil }},
		{"pair moved to another user", userB, Signing, func(*StoredPair) {}},
		{"pair moved to the other purpose", userA, Encryption, func(*StoredPair) {}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := sp
			c.PublicDER, c.Fingerprint, c.PublicMAC = bytes.Clone(sp.PublicDER), bytes.Clone(sp.Fingerprint), bytes.Clone(sp.PublicMAC)
			tt.mutate(&c)
			if _, err := verifyPublic(macKey, tt.user, tt.p, &c); !errors.Is(err, ErrCorrupt) {
				t.Errorf("err = %v, want ErrCorrupt", err)
			}
		})
	}
	if _, err := verifyPublic(randomBytes(t, PublicMACKeySize), userA, Signing, &sp); !errors.Is(err, ErrCorrupt) {
		t.Errorf("another MAC key: err = %v, want ErrCorrupt", err)
	}
}

func TestFormatFingerprint(t *testing.T) {
	fp := sha256.Sum256([]byte("abc"))
	got := FormatFingerprint(fp[:])
	if len(got) != 64+15 || strings.Count(got, " ") != 15 {
		t.Errorf("FormatFingerprint = %q, want 16 groups of 4 hex digits", got)
	}
	if strings.ReplaceAll(got, " ", "") != hex.EncodeToString(fp[:]) {
		t.Errorf("without spaces %q is not the plain hex", got)
	}
	if !strings.HasPrefix(got, "ba78 16bf ") {
		t.Errorf("FormatFingerprint(SHA-256(\"abc\")) = %q, want prefix %q", got, "ba78 16bf")
	}
	if FormatFingerprint(nil) != "" || FormatFingerprint([]byte{0xab}) != "ab" {
		t.Error("short inputs formatted wrongly")
	}
}

func TestPublicKeyPEM(t *testing.T) {
	pub := &testKey(t, 0).PublicKey
	out, err := PublicKeyPEM(pub)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(out)
	if block == nil || block.Type != "PUBLIC KEY" || len(rest) != 0 || len(block.Headers) != 0 {
		t.Fatalf("PEM = %q", out)
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := key.(*rsa.PublicKey); !ok || !got.Equal(pub) {
		t.Error("PEM does not decode to the same public key")
	}
}
