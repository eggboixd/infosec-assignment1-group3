package crypto

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
)

// edgeSizes are the plaintext sizes every algorithm is tested at: empty, one
// byte, one below/at/above the DES block (8) and the AES block (16), and a
// large odd size that spans many 32 KiB chunks and ends mid-block.
var edgeSizes = []int{0, 1, 7, 8, 9, 15, 16, 17, 1<<20 + 3}

func newTestEnvelope(t testing.TB) *Envelope {
	t.Helper()
	e, err := NewEnvelope(randBytes(t, MasterKeySize))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// encryptBytes runs the streaming Encrypt on an in-memory plaintext.
func encryptBytes(t testing.TB, e *Envelope, alg Algorithm, pt []byte) ([]byte, Meta) {
	t.Helper()
	var ct bytes.Buffer
	meta, err := e.Encrypt(context.Background(), alg, &ct, bytes.NewReader(pt))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	return ct.Bytes(), meta
}

func TestNewEnvelopeRejectsBadMasterKey(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := NewEnvelope(make([]byte, n)); err == nil {
			t.Errorf("NewEnvelope accepted a %d-byte master key", n)
		}
	}
}

func TestNewEnvelopeCopiesMasterKey(t *testing.T) {
	master := randBytes(t, MasterKeySize)
	e, err := NewEnvelope(master)
	if err != nil {
		t.Fatal(err)
	}
	ct, meta, err := e.EncryptField(AES, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	clear(master) // the caller wiping its copy must not break the Envelope
	if _, err := e.DecryptField(AES, meta, ct); err != nil {
		t.Fatalf("DecryptField after caller cleared master: %v", err)
	}
}

func TestEnvelopeStreamRoundTrip(t *testing.T) {
	e := newTestEnvelope(t)
	for _, alg := range All() {
		for _, size := range edgeSizes {
			t.Run(fmt.Sprintf("%s/%dB", alg, size), func(t *testing.T) {
				plaintext := randBytes(t, size)
				ctx, clock := WithClock(context.Background())

				var ct bytes.Buffer
				meta, err := e.Encrypt(ctx, alg, &ct, bytes.NewReader(plaintext))
				if err != nil {
					t.Fatalf("Encrypt: %v", err)
				}
				checkMeta(t, alg, meta)
				if ct.Len() != size {
					t.Errorf("ciphertext is %d bytes, want %d (CTR and RC4 add no padding)", ct.Len(), size)
				}
				if size >= 16 && bytes.Equal(ct.Bytes(), plaintext) {
					t.Error("ciphertext equals plaintext")
				}

				// Start the reader at EOF to check that Decrypt seeks back
				// to the start itself, as the two-pass flow requires.
				src := bytes.NewReader(ct.Bytes())
				if _, err := src.Seek(0, io.SeekEnd); err != nil {
					t.Fatal(err)
				}
				var pt bytes.Buffer
				if err := e.Decrypt(ctx, alg, meta, &pt, src); err != nil {
					t.Fatalf("Decrypt: %v", err)
				}
				if !bytes.Equal(pt.Bytes(), plaintext) {
					t.Errorf("round trip mismatch: got %d bytes, want %d", pt.Len(), size)
				}
				if size > 1<<20 && clock.Elapsed() <= 0 {
					t.Errorf("clock recorded %v for a 1 MiB operation", clock.Elapsed())
				}
			})
		}
	}
}

func TestEnvelopeFieldRoundTrip(t *testing.T) {
	e := newTestEnvelope(t)
	for _, alg := range All() {
		for _, size := range edgeSizes {
			t.Run(fmt.Sprintf("%s/%dB", alg, size), func(t *testing.T) {
				plaintext := randBytes(t, size)
				ct, meta, err := e.EncryptField(alg, plaintext)
				if err != nil {
					t.Fatalf("EncryptField: %v", err)
				}
				checkMeta(t, alg, meta)
				if len(ct) != size {
					t.Errorf("ciphertext is %d bytes, want %d", len(ct), size)
				}
				got, err := e.DecryptField(alg, meta, ct)
				if err != nil {
					t.Fatalf("DecryptField: %v", err)
				}
				if !bytes.Equal(got, plaintext) {
					t.Errorf("round trip mismatch: got %d bytes, want %d", len(got), size)
				}
			})
		}
	}
}

// checkMeta checks the sizes of every Meta field.
func checkMeta(t *testing.T, alg Algorithm, m Meta) {
	t.Helper()
	if m.Algorithm != alg {
		t.Errorf("meta.Algorithm = %q, want %q", m.Algorithm, alg)
	}
	if len(m.IV) != alg.IVSize() {
		t.Errorf("len(IV) = %d, want %d", len(m.IV), alg.IVSize())
	}
	if want := dekSize(alg) + 28; len(m.WrappedDEK) != want {
		t.Errorf("len(WrappedDEK) = %d, want %d", len(m.WrappedDEK), want)
	}
	if want := macKeySize + 28; len(m.WrappedMACKey) != want {
		t.Errorf("len(WrappedMACKey) = %d, want %d", len(m.WrappedMACKey), want)
	}
	if len(m.Tag) != tagSize {
		t.Errorf("len(Tag) = %d, want %d", len(m.Tag), tagSize)
	}
}

// TestEnvelopeSamePlaintextDiffers encrypts the same plaintext twice and
// checks that nothing repeats. 64 bytes is used because with 1 byte the two
// ciphertexts would match by pure chance once in 256 runs.
func TestEnvelopeSamePlaintextDiffers(t *testing.T) {
	e := newTestEnvelope(t)
	plaintext := bytes.Repeat([]byte("A"), 64) // highly repetitive on purpose
	for _, alg := range All() {
		t.Run(string(alg), func(t *testing.T) {
			ct1, m1 := encryptBytes(t, e, alg, plaintext)
			ct2, m2 := encryptBytes(t, e, alg, plaintext)
			if bytes.Equal(ct1, ct2) {
				t.Error("same plaintext gave the same ciphertext")
			}
			if alg != RC4 && bytes.Equal(m1.IV, m2.IV) {
				t.Error("IV repeated")
			}
			if bytes.Equal(m1.WrappedDEK, m2.WrappedDEK) {
				t.Error("wrapped DEK repeated")
			}
			if bytes.Equal(m1.Tag, m2.Tag) {
				t.Error("tag repeated")
			}
			// Unlike ECB, repeated plaintext blocks must not show up as
			// repeated ciphertext blocks.
			if bytes.Equal(ct1[:8], ct1[8:16]) || bytes.Equal(ct1[:16], ct1[16:32]) {
				t.Error("identical plaintext blocks gave identical ciphertext blocks")
			}
		})
	}
}

// TestEnvelopeDetectsTampering changes one thing at a time in the stored
// ciphertext or Meta and checks that Decrypt reports ErrAuthentication
// without writing any plaintext.
func TestEnvelopeDetectsTampering(t *testing.T) {
	e := newTestEnvelope(t)
	plaintext := randBytes(t, 1000)

	type mutation func(ct []byte, m *Meta, other Meta) []byte
	flip := func(b []byte, i int) []byte { b = bytes.Clone(b); b[i] ^= 0x01; return b }
	mutations := map[string]mutation{
		"flip first ct byte":    func(ct []byte, m *Meta, _ Meta) []byte { return flip(ct, 0) },
		"flip middle ct byte":   func(ct []byte, m *Meta, _ Meta) []byte { return flip(ct, len(ct)/2) },
		"flip last ct byte":     func(ct []byte, m *Meta, _ Meta) []byte { return flip(ct, len(ct)-1) },
		"truncate ct":           func(ct []byte, m *Meta, _ Meta) []byte { return ct[:len(ct)-1] },
		"append to ct":          func(ct []byte, m *Meta, _ Meta) []byte { return append(bytes.Clone(ct), 0) },
		"empty ct":              func(ct []byte, m *Meta, _ Meta) []byte { return nil },
		"flip tag":              func(ct []byte, m *Meta, _ Meta) []byte { m.Tag = flip(m.Tag, 5); return ct },
		"truncate tag":          func(ct []byte, m *Meta, _ Meta) []byte { m.Tag = m.Tag[:16]; return ct },
		"missing tag":           func(ct []byte, m *Meta, _ Meta) []byte { m.Tag = nil; return ct },
		"flip wrapped dek":      func(ct []byte, m *Meta, _ Meta) []byte { m.WrappedDEK = flip(m.WrappedDEK, 20); return ct },
		"flip wrapped mac key":  func(ct []byte, m *Meta, _ Meta) []byte { m.WrappedMACKey = flip(m.WrappedMACKey, 20); return ct },
		"dek from other object": func(ct []byte, m *Meta, o Meta) []byte { m.WrappedDEK = o.WrappedDEK; return ct },
		"mac key from other":    func(ct []byte, m *Meta, o Meta) []byte { m.WrappedMACKey = o.WrappedMACKey; return ct },
		"whole meta from other": func(ct []byte, m *Meta, o Meta) []byte { *m = o; return ct },
		"keys and tag from other": func(ct []byte, m *Meta, o Meta) []byte {
			m.WrappedDEK, m.WrappedMACKey, m.Tag = o.WrappedDEK, o.WrappedMACKey, o.Tag
			return ct
		},
		"iv wrong length": func(ct []byte, m *Meta, _ Meta) []byte {
			m.IV = make([]byte, len(m.IV)+8) // RC4 gains an IV it must not have
			return ct
		},
	}

	for _, alg := range All() {
		ct, meta := encryptBytes(t, e, alg, plaintext)
		_, other := encryptBytes(t, e, alg, plaintext)

		muts := mutations
		if alg != RC4 {
			muts = map[string]mutation{"flip iv": func(ct []byte, m *Meta, _ Meta) []byte { m.IV = flip(m.IV, 0); return ct }}
			for k, v := range mutations {
				muts[k] = v
			}
		}
		for name, mutate := range muts {
			t.Run(string(alg)+"/"+name, func(t *testing.T) {
				m := meta
				badCT := mutate(ct, &m, other)

				var pt bytes.Buffer
				err := e.Decrypt(context.Background(), alg, m, &pt, bytes.NewReader(badCT))
				if !errors.Is(err, ErrAuthentication) {
					t.Errorf("Decrypt err = %v, want ErrAuthentication", err)
				}
				if pt.Len() != 0 {
					t.Errorf("Decrypt wrote %d plaintext bytes before failing", pt.Len())
				}

				if _, err := e.DecryptField(alg, m, badCT); !errors.Is(err, ErrAuthentication) {
					t.Errorf("DecryptField err = %v, want ErrAuthentication", err)
				}
			})
		}
	}
}

func TestEnvelopeWrongMasterKey(t *testing.T) {
	e1, e2 := newTestEnvelope(t), newTestEnvelope(t)
	for _, alg := range All() {
		ct, meta := encryptBytes(t, e1, alg, []byte("3171234567890001"))
		var pt bytes.Buffer
		if err := e2.Decrypt(context.Background(), alg, meta, &pt, bytes.NewReader(ct)); !errors.Is(err, ErrAuthentication) {
			t.Errorf("%s: err = %v, want ErrAuthentication", alg, err)
		}
		if pt.Len() != 0 {
			t.Errorf("%s: wrote %d bytes with the wrong key", alg, pt.Len())
		}
	}
}

func TestEnvelopeRejectsBadInput(t *testing.T) {
	e := newTestEnvelope(t)
	ctx := context.Background()

	if _, err := e.Encrypt(ctx, "xor", io.Discard, bytes.NewReader(nil)); !errors.Is(err, ErrUnknownAlgorithm) {
		t.Errorf("Encrypt unknown alg: err = %v", err)
	}
	if _, _, err := e.EncryptField("", nil); !errors.Is(err, ErrUnknownAlgorithm) {
		t.Errorf("EncryptField empty alg: err = %v", err)
	}

	ct, meta := encryptBytes(t, e, AES, []byte("data"))
	if err := e.Decrypt(ctx, "xor", meta, io.Discard, bytes.NewReader(ct)); !errors.Is(err, ErrUnknownAlgorithm) {
		t.Errorf("Decrypt unknown alg: err = %v", err)
	}
	if err := e.Decrypt(ctx, DES, meta, io.Discard, bytes.NewReader(ct)); err == nil {
		t.Error("Decrypt with alg different from meta.Algorithm succeeded")
	}
	if _, err := e.DecryptField(RC4, meta, ct); err == nil {
		t.Error("DecryptField with alg different from meta.Algorithm succeeded")
	}

	for _, alg := range []Algorithm{AES, DES} {
		ct, meta := encryptBytes(t, e, alg, []byte("data"))
		for name, iv := range map[string][]byte{"missing": nil, "short": meta.IV[:len(meta.IV)-1]} {
			m := meta
			m.IV = iv
			if err := e.Decrypt(ctx, alg, m, io.Discard, bytes.NewReader(ct)); !errors.Is(err, ErrAuthentication) {
				t.Errorf("%s %s IV: err = %v, want ErrAuthentication", alg, name, err)
			}
		}
	}
}

var errBoom = errors.New("boom")

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errBoom }

type failReader struct{}

func (failReader) Read([]byte) (int, error)       { return 0, errBoom }
func (failReader) Seek(int64, int) (int64, error) { return 0, nil }

func TestEnvelopePropagatesIOErrors(t *testing.T) {
	e := newTestEnvelope(t)
	ctx := context.Background()
	for _, alg := range All() {
		if _, err := e.Encrypt(ctx, alg, failWriter{}, bytes.NewReader([]byte("x"))); !errors.Is(err, errBoom) {
			t.Errorf("%s Encrypt write error: err = %v", alg, err)
		}
		if _, err := e.Encrypt(ctx, alg, io.Discard, failReader{}); !errors.Is(err, errBoom) {
			t.Errorf("%s Encrypt read error: err = %v", alg, err)
		}
		ct, meta := encryptBytes(t, e, alg, []byte("x"))
		if err := e.Decrypt(ctx, alg, meta, failWriter{}, bytes.NewReader(ct)); !errors.Is(err, errBoom) {
			t.Errorf("%s Decrypt write error: err = %v", alg, err)
		}
		if err := e.Decrypt(ctx, alg, meta, io.Discard, failReader{}); !errors.Is(err, errBoom) {
			t.Errorf("%s Decrypt read error: err = %v", alg, err)
		}
	}
}

// swappingReader serves good bytes until it is rewound for the second time,
// then serves bad bytes: it simulates the stored object being replaced
// between Decrypt's verify pass and its decrypt pass.
type swappingReader struct {
	good, bad []byte
	seeks     int
	r         *bytes.Reader
}

func (s *swappingReader) Seek(offset int64, whence int) (int64, error) {
	s.seeks++
	if s.seeks >= 2 {
		s.r = bytes.NewReader(s.bad)
	} else {
		s.r = bytes.NewReader(s.good)
	}
	return s.r.Seek(offset, whence)
}

func (s *swappingReader) Read(p []byte) (int, error) { return s.r.Read(p) }

func TestEnvelopeDetectsChangeBetweenPasses(t *testing.T) {
	e := newTestEnvelope(t)
	for _, alg := range All() {
		ct, meta := encryptBytes(t, e, alg, randBytes(t, 5000))
		bad := bytes.Clone(ct)
		bad[4000] ^= 0x01
		src := &swappingReader{good: ct, bad: bad}
		if err := e.Decrypt(context.Background(), alg, meta, io.Discard, src); !errors.Is(err, ErrAuthentication) {
			t.Errorf("%s: err = %v, want ErrAuthentication", alg, err)
		}
	}
}

// TestEnvelopeConcurrent uses one Envelope from many goroutines at once, as
// the files service does (one goroutine per algorithm). Run with -race.
func TestEnvelopeConcurrent(t *testing.T) {
	e := newTestEnvelope(t)
	var wg sync.WaitGroup
	for range 4 {
		for _, alg := range All() {
			plaintext := randBytes(t, 100_000) // t.Fatal must not be called from a goroutine
			wg.Add(1)
			go func() {
				defer wg.Done()
				var ct bytes.Buffer
				meta, err := e.Encrypt(context.Background(), alg, &ct, bytes.NewReader(plaintext))
				if err != nil {
					t.Errorf("Encrypt: %v", err)
					return
				}
				var pt bytes.Buffer
				if err := e.Decrypt(context.Background(), alg, meta, &pt, bytes.NewReader(ct.Bytes())); err != nil {
					t.Errorf("Decrypt: %v", err)
					return
				}
				if !bytes.Equal(pt.Bytes(), plaintext) {
					t.Errorf("%s: concurrent round trip mismatch", alg)
				}
			}()
		}
	}
	wg.Wait()
}

// FuzzEnvelopeRoundTrip checks Decrypt(Encrypt(x)) == x for arbitrary inputs.
// The seed corpus runs as part of the normal test suite; run the fuzzer with
//
//	go test -run=^$ -fuzz=FuzzEnvelopeRoundTrip -fuzztime=30s ./internal/crypto
func FuzzEnvelopeRoundTrip(f *testing.F) {
	for i, size := range edgeSizes[:len(edgeSizes)-1] {
		f.Add(bytes.Repeat([]byte{byte(i)}, size), uint8(i))
	}
	e := newTestEnvelope(f)
	algs := All()
	f.Fuzz(func(t *testing.T, plaintext []byte, a uint8) {
		alg := algs[int(a)%len(algs)]
		ct, meta := encryptBytes(t, e, alg, plaintext)
		if len(ct) != len(plaintext) {
			t.Fatalf("ciphertext %d bytes, plaintext %d", len(ct), len(plaintext))
		}
		var pt bytes.Buffer
		if err := e.Decrypt(context.Background(), alg, meta, &pt, bytes.NewReader(ct)); err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		if !bytes.Equal(pt.Bytes(), plaintext) {
			t.Fatal("round trip mismatch")
		}
	})
}
