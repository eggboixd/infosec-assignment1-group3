package keypair

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	pwA = "correct horse battery staple"
	pwB = "another long password"
)

// useTestKeys makes s hand out the cached keys alternately (encryption gets
// key 0 and signing key 1 when one EnsureKeys runs alone) and returns a
// counter of how many keys it was asked for.
func useTestKeys(t *testing.T, s *Service) *atomic.Int64 {
	t.Helper()
	ks, err := testKeys()
	if err != nil {
		t.Fatal(err)
	}
	var n atomic.Int64
	s.genKey = func() (*rsa.PrivateKey, error) {
		i := n.Add(1) - 1
		return ks[i%2], nil
	}
	return &n
}

func newTestService(t *testing.T) (*Service, *memStore, *atomic.Int64) {
	t.Helper()
	useFastKDF(t)
	st := newMemStore()
	s, err := NewService(st, randomBytes(t, PublicMACKeySize))
	if err != nil {
		t.Fatal(err)
	}
	return s, st, useTestKeys(t, s)
}

// withKeys is newTestService plus key pairs for userA (password pwA).
func withKeys(t *testing.T) (*Service, *memStore, *atomic.Int64) {
	t.Helper()
	s, st, n := newTestService(t)
	if err := s.EnsureKeys(context.Background(), userA, pwA); err != nil {
		t.Fatal(err)
	}
	return s, st, n
}

func TestNewServiceRejectsBadMACKey(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := NewService(newMemStore(), make([]byte, n)); err == nil {
			t.Errorf("%d-byte MAC key accepted", n)
		}
	}
}

// The real generator, once: both pairs are RSA-3072 with e = 65537, and the
// encryption and signing pairs are different keys (D39).
func TestEnsureKeysGeneratesRSA3072(t *testing.T) {
	s, st, _ := newTestService(t)
	s.genKey = generateKey
	ctx := context.Background()
	if err := s.EnsureKeys(ctx, userA, pwA); err != nil {
		t.Fatal(err)
	}

	enc, err := s.Unlock(ctx, userA, pwA, Encryption)
	if err != nil {
		t.Fatal(err)
	}
	sign, err := s.Unlock(ctx, userA, pwA, Signing)
	if err != nil {
		t.Fatal(err)
	}
	for name, k := range map[string]*rsa.PrivateKey{"encryption": enc, "signing": sign} {
		if k.N.BitLen() != 3072 || k.E != 65537 {
			t.Errorf("%s key: %d bits, e=%d; want 3072, 65537", name, k.N.BitLen(), k.E)
		}
	}
	if enc.N.Cmp(sign.N) == 0 {
		t.Error("encryption and signing pairs share a modulus")
	}

	d := st.get(t, userA)
	if bytes.Equal(d.Encryption.Fingerprint, d.Signing.Fingerprint) {
		t.Error("encryption and signing fingerprints are equal")
	}
	if d.Version != 1 || len(d.KDF.Salt) != saltSize || d.CreatedAt.IsZero() ||
		d.Encryption.CreatedAt.IsZero() || d.Signing.CreatedAt.IsZero() {
		t.Errorf("stored document incomplete: version %d, salt %d B, created %v", d.Version, len(d.KDF.Salt), d.CreatedAt)
	}
}

// The encryption pair works for RSA-OAEP with SHA-256, the way
// feature/share-keys will use it.
func TestEncryptionPairWorksWithOAEP(t *testing.T) {
	s, _, _ := withKeys(t)
	ctx := context.Background()
	pub, err := s.PublicKey(ctx, userA, Encryption)
	if err != nil {
		t.Fatal(err)
	}
	shareKey := randomBytes(t, 32)
	ct, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, shareKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := s.Unlock(ctx, userA, pwA, Encryption)
	if err != nil {
		t.Fatal(err)
	}
	got, err := rsa.DecryptOAEP(sha256.New(), nil, priv, ct, nil)
	if err != nil || !bytes.Equal(got, shareKey) {
		t.Fatalf("OAEP roundtrip: %v", err)
	}
	// The signing key must not open it: the pairs are independent.
	sign, _ := s.Unlock(ctx, userA, pwA, Signing)
	if _, err := rsa.DecryptOAEP(sha256.New(), nil, sign, ct, nil); err == nil {
		t.Error("signing key decrypted a message for the encryption key")
	}
}

func TestUnlockMatchesPublicKey(t *testing.T) {
	s, _, _ := withKeys(t)
	ctx := context.Background()
	for _, p := range []Purpose{Encryption, Signing} {
		priv, err := s.Unlock(ctx, userA, pwA, p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		pub, err := s.PublicKey(ctx, userA, p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if !priv.PublicKey.Equal(pub) {
			t.Errorf("%s: unlocked key does not match the public key", p)
		}
	}
}

func TestEnsureKeysIsIdempotent(t *testing.T) {
	s, st, gen := withKeys(t)
	before := st.get(t, userA)
	// A second call, even with another password, changes nothing.
	if err := s.EnsureKeys(context.Background(), userA, pwB); err != nil {
		t.Fatal(err)
	}
	after := st.get(t, userA)
	if st.len() != 1 || gen.Load() != 2 {
		t.Errorf("%d documents, %d keys generated; want 1 and 2", st.len(), gen.Load())
	}
	if !bytes.Equal(before.Encryption.Fingerprint, after.Encryption.Fingerprint) ||
		!bytes.Equal(before.Signing.Fingerprint, after.Signing.Fingerprint) ||
		!bytes.Equal(before.KDF.Salt, after.KDF.Salt) {
		t.Error("second EnsureKeys changed the stored keys")
	}
	if _, err := s.Unlock(context.Background(), userA, pwA, Signing); err != nil {
		t.Errorf("original password no longer unlocks: %v", err)
	}
}

// Two logins at once: both may generate, but the unique index keeps one set
// and neither caller sees an error.
func TestEnsureKeysConcurrent(t *testing.T) {
	s, st, _ := newTestService(t)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() { errs <- s.EnsureKeys(context.Background(), userA, pwA) })
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("EnsureKeys: %v", err)
		}
	}
	if st.len() != 1 {
		t.Fatalf("%d documents, want 1", st.len())
	}
	if _, err := s.Unlock(context.Background(), userA, pwA, Encryption); err != nil {
		t.Errorf("the stored set does not unlock: %v", err)
	}
}

func TestEnsureKeysErrors(t *testing.T) {
	ctx := context.Background()
	t.Run("empty password", func(t *testing.T) {
		s, st, _ := newTestService(t)
		if err := s.EnsureKeys(ctx, userA, ""); err == nil || st.len() != 0 {
			t.Errorf("err = %v, %d documents; want an error and none", err, st.len())
		}
	})
	t.Run("zero user ID", func(t *testing.T) {
		s, st, _ := newTestService(t)
		if err := s.EnsureKeys(ctx, [12]byte{}, pwA); err == nil || st.len() != 0 {
			t.Errorf("err = %v, %d documents; want an error and none", err, st.len())
		}
	})
	t.Run("store error is returned, nothing generated", func(t *testing.T) {
		s, st, gen := newTestService(t)
		st.findErr = errors.New("mongo down")
		if err := s.EnsureKeys(ctx, userA, pwA); err == nil || gen.Load() != 0 {
			t.Errorf("err = %v, %d keys generated; want an error and 0", err, gen.Load())
		}
	})
	t.Run("generator error", func(t *testing.T) {
		s, st, _ := newTestService(t)
		s.genKey = func() (*rsa.PrivateKey, error) { return nil, errors.New("no entropy") }
		if err := s.EnsureKeys(ctx, userA, pwA); err == nil || st.len() != 0 {
			t.Errorf("err = %v, %d documents; want an error and none", err, st.len())
		}
	})
	t.Run("cancelled context", func(t *testing.T) {
		s, st, gen := newTestService(t)
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		if err := s.EnsureKeys(cctx, userA, pwA); !errors.Is(err, context.Canceled) || st.len() != 0 || gen.Load() != 0 {
			t.Errorf("err = %v, %d documents, %d keys; want Canceled, 0, 0", err, st.len(), gen.Load())
		}
	})
}

func TestUnlockWrongPassword(t *testing.T) {
	s, _, _ := withKeys(t)
	for _, pw := range []string{pwB, "", pwA + " ", "Correct horse battery staple"} {
		if _, err := s.Unlock(context.Background(), userA, pw, Signing); !errors.Is(err, ErrUnlock) {
			t.Errorf("password %q: err = %v, want ErrUnlock", pw, err)
		}
	}
}

// Another user's ID behaves exactly like a user without keys: every lookup
// is by the given ID only (IDOR).
func TestNoKeysAndOtherUser(t *testing.T) {
	s, _, _ := withKeys(t)
	ctx := context.Background()
	if _, err := s.Unlock(ctx, userB, pwA, Encryption); !errors.Is(err, ErrNoKeys) {
		t.Errorf("Unlock: err = %v, want ErrNoKeys", err)
	}
	if _, err := s.PublicKey(ctx, userB, Encryption); !errors.Is(err, ErrNoKeys) {
		t.Errorf("PublicKey: err = %v, want ErrNoKeys", err)
	}
	if _, err := s.Info(ctx, userB); !errors.Is(err, ErrNoKeys) {
		t.Errorf("Info: err = %v, want ErrNoKeys", err)
	}
	if err := s.Rewrap(ctx, userB, pwA, pwB); !errors.Is(err, ErrNoKeys) {
		t.Errorf("Rewrap: err = %v, want ErrNoKeys", err)
	}
}

func TestUnknownPurpose(t *testing.T) {
	s, _, _ := withKeys(t)
	ctx := context.Background()
	for _, p := range []Purpose{"", "admin", "Encryption", "signing "} {
		if _, err := s.Unlock(ctx, userA, pwA, p); !errors.Is(err, ErrUnknownPurpose) {
			t.Errorf("Unlock(%q): err = %v, want ErrUnknownPurpose", p, err)
		}
		if _, err := s.PublicKey(ctx, userA, p); !errors.Is(err, ErrUnknownPurpose) {
			t.Errorf("PublicKey(%q): err = %v, want ErrUnknownPurpose", p, err)
		}
		if _, err := ParsePurpose(string(p)); !errors.Is(err, ErrUnknownPurpose) {
			t.Errorf("ParsePurpose(%q): err = %v, want ErrUnknownPurpose", p, err)
		}
	}
	for _, p := range []Purpose{Encryption, Signing} {
		if got, err := ParsePurpose(string(p)); err != nil || got != p {
			t.Errorf("ParsePurpose(%q) = %q, %v", p, got, err)
		}
	}
}

// Tampering with the stored document, with the right password. Changes to
// the encrypted key fail as ErrUnlock (GCM can't tell them from a wrong
// password); changes to anything public fail as ErrCorrupt.
func TestUnlockDetectsTampering(t *testing.T) {
	tests := []struct {
		name    string
		purpose Purpose
		mutate  func(d, other *Document)
		want    error
	}{
		{"wrapped key bit flipped", Encryption, func(d, _ *Document) { d.Encryption.WrappedPrivate[20] ^= 1 }, ErrUnlock},
		{"wrapped key truncated", Signing, func(d, _ *Document) { d.Signing.WrappedPrivate = d.Signing.WrappedPrivate[:40] }, ErrUnlock},
		{"wrapped key empty", Signing, func(d, _ *Document) { d.Signing.WrappedPrivate = nil }, ErrUnlock},
		{"wrapped keys swapped between purposes", Encryption, func(d, _ *Document) {
			d.Encryption.WrappedPrivate, d.Signing.WrappedPrivate = d.Signing.WrappedPrivate, d.Encryption.WrappedPrivate
		}, ErrUnlock},
		{"another user's wrapped key copied in", Encryption, func(d, o *Document) { d.Encryption.WrappedPrivate = o.Encryption.WrappedPrivate }, ErrUnlock},
		{"salt changed", Encryption, func(d, _ *Document) { d.KDF.Salt[0] ^= 1 }, ErrUnlock},
		{"KDF time changed", Encryption, func(d, _ *Document) { d.KDF.Time++ }, ErrUnlock},
		{"whole pair swapped between purposes", Encryption, func(d, _ *Document) { d.Encryption, d.Signing = d.Signing, d.Encryption }, ErrCorrupt},
		{"another user's whole pair copied in", Signing, func(d, o *Document) { d.Signing = o.Signing }, ErrCorrupt},
		{"public key byte flipped", Signing, func(d, _ *Document) { d.Signing.PublicDER[50] ^= 1 }, ErrCorrupt},
		{"fingerprint flipped", Encryption, func(d, _ *Document) { d.Encryption.Fingerprint[3] ^= 1 }, ErrCorrupt},
		{"public MAC flipped", Encryption, func(d, _ *Document) { d.Encryption.PublicMAC[0] ^= 1 }, ErrCorrupt},
		{"created_at changed", Signing, func(d, _ *Document) { d.Signing.CreatedAt = d.Signing.CreatedAt.Add(time.Second) }, ErrCorrupt},
		{"KDF memory 4 GiB planted", Encryption, func(d, _ *Document) { d.KDF.Memory = 1 << 22 }, ErrCorrupt},
		{"KDF algorithm changed", Encryption, func(d, _ *Document) { d.KDF.Alg = "pbkdf2" }, ErrCorrupt},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, st, _ := withKeys(t)
			// userB with the same password gives "another user's" data.
			if err := s.EnsureKeys(context.Background(), userB, pwA); err != nil {
				t.Fatal(err)
			}
			d, other := st.get(t, userA), st.get(t, userB)
			tt.mutate(d, other)
			st.put(t, d)
			if _, err := s.Unlock(context.Background(), userA, pwA, tt.purpose); !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestPublicKeyAndInfoDetectTampering(t *testing.T) {
	s, st, _ := withKeys(t)
	d := st.get(t, userA)
	d.Encryption.PublicDER[60] ^= 1
	st.put(t, d)
	ctx := context.Background()
	if _, err := s.PublicKey(ctx, userA, Encryption); !errors.Is(err, ErrCorrupt) {
		t.Errorf("PublicKey: err = %v, want ErrCorrupt", err)
	}
	if _, err := s.Info(ctx, userA); !errors.Is(err, ErrCorrupt) {
		t.Errorf("Info: err = %v, want ErrCorrupt", err)
	}
	// The untouched pair is still served.
	if _, err := s.PublicKey(ctx, userA, Signing); err != nil {
		t.Errorf("signing PublicKey: %v", err)
	}
}

func TestInfo(t *testing.T) {
	s, st, _ := withKeys(t)
	infos, err := s.Info(context.Background(), userA)
	if err != nil {
		t.Fatal(err)
	}
	d := st.get(t, userA)
	want := []struct {
		p  Purpose
		sp StoredPair
	}{{Encryption, d.Encryption}, {Signing, d.Signing}}
	if len(infos) != len(want) {
		t.Fatalf("%d infos, want %d", len(infos), len(want))
	}
	for i, w := range want {
		got := infos[i]
		if got.Purpose != w.p || got.Bits != 3072 || got.Fingerprint != FormatFingerprint(w.sp.Fingerprint) || !got.CreatedAt.Equal(w.sp.CreatedAt) {
			t.Errorf("info[%d] = %+v", i, got)
		}
	}
}

func TestRewrap(t *testing.T) {
	s, st, _ := withKeys(t)
	ctx := context.Background()
	before := st.get(t, userA)

	if err := s.Rewrap(ctx, userA, pwA, pwB); err != nil {
		t.Fatal(err)
	}
	after := st.get(t, userA)
	if bytes.Equal(before.KDF.Salt, after.KDF.Salt) {
		t.Error("salt unchanged; want a fresh salt for the new KEK")
	}
	for _, p := range []Purpose{Encryption, Signing} {
		b, _ := before.pair(p)
		a, _ := after.pair(p)
		if bytes.Equal(b.WrappedPrivate, a.WrappedPrivate) {
			t.Errorf("%s: wrapped key unchanged", p)
		}
		if !bytes.Equal(b.PublicDER, a.PublicDER) || !bytes.Equal(b.PublicMAC, a.PublicMAC) || !b.CreatedAt.Equal(a.CreatedAt) {
			t.Errorf("%s: public half changed; the key pair must stay the same", p)
		}
		if _, err := s.Unlock(ctx, userA, pwB, p); err != nil {
			t.Errorf("%s: new password does not unlock: %v", p, err)
		}
		if _, err := s.Unlock(ctx, userA, pwA, p); !errors.Is(err, ErrUnlock) {
			t.Errorf("%s: old password: err = %v, want ErrUnlock", p, err)
		}
	}
}

func TestRewrapWrongOldPasswordWritesNothing(t *testing.T) {
	s, st, _ := withKeys(t)
	before := st.get(t, userA)
	if err := s.Rewrap(context.Background(), userA, pwB, "a brand new password"); !errors.Is(err, ErrUnlock) {
		t.Fatalf("err = %v, want ErrUnlock", err)
	}
	after := st.get(t, userA)
	if !bytes.Equal(before.KDF.Salt, after.KDF.Salt) || !bytes.Equal(before.Signing.WrappedPrivate, after.Signing.WrappedPrivate) {
		t.Error("a failed rewrap changed the stored document")
	}
	if err := s.Rewrap(context.Background(), userA, pwA, ""); err == nil {
		t.Error("rewrap to an empty password succeeded")
	}
}

// The store contract Rewrap relies on: a password change that lost the race
// (it read the old salt) must not overwrite the winner's keys. *Store does
// this with the kdf.salt filter in ReplaceWrapped; this checks the contract
// through the fake.
func TestRewrapConflict(t *testing.T) {
	s, st, _ := withKeys(t)
	ctx := context.Background()
	d := st.get(t, userA)
	stale := d.KDF.Salt
	if err := s.Rewrap(ctx, userA, pwA, pwB); err != nil {
		t.Fatal(err)
	}
	if err := st.ReplaceWrapped(ctx, userA, stale, d.KDF, d.Encryption.WrappedPrivate, d.Signing.WrappedPrivate); !errors.Is(err, errConflict) {
		t.Errorf("replace with a stale salt: err = %v, want errConflict", err)
	}
	if _, err := s.Unlock(ctx, userA, pwB, Encryption); err != nil {
		t.Errorf("winner's password no longer unlocks: %v", err)
	}
}
