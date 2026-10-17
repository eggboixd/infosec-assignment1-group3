package cipheranalysis

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"testing"

	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
)

func newTestEnvelope(t *testing.T) *crypto.Envelope {
	t.Helper()
	master := make([]byte, crypto.MasterKeySize)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	enc, err := crypto.NewEnvelope(master)
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAnalyzeSizes(t *testing.T) {
	enc := newTestEnvelope(t)
	// 0 B, sizes around both block sizes (8 for DES, 16 for AES), and a large odd size.
	for _, size := range []int{0, 1, 7, 8, 9, 15, 16, 17, 1<<20 + 13} {
		plain := randomBytes(t, size)
		rows, err := Analyze(context.Background(), enc, "x.bin", plain)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if len(rows) != 3 {
			t.Fatalf("size %d: got %d rows, want 3", size, len(rows))
		}
		for _, r := range rows {
			if r.CipherSize != size || r.PlainSize != size {
				t.Errorf("size %d %s: cipher %d, plain %d; CTR/RC4 must not change the length", size, r.Algorithm, r.CipherSize, r.PlainSize)
			}
			if !r.RoundTripOK {
				t.Errorf("size %d %s: round trip failed", size, r.Algorithm)
			}
			if !r.TamperDetected {
				t.Errorf("size %d %s: tampering was not detected", size, r.Algorithm)
			}
			if r.MetaSize <= 0 {
				t.Errorf("size %d %s: expected stored overhead in Meta", size, r.Algorithm)
			}
			if size == 0 {
				if r.OneBitCipherBits != NotApplicable || r.TwiceDiffPercent != 0 || r.PlainHex != "" {
					t.Errorf("empty file: unexpected row %+v", r)
				}
				continue
			}
			// No diffusion: one flipped plaintext bit flips exactly one ciphertext bit.
			if r.OneBitCipherBytes != 1 || r.OneBitCipherBits != 1 {
				t.Errorf("size %d %s: one-bit change gave %d bytes / %d bits, want 1 / 1", size, r.Algorithm, r.OneBitCipherBytes, r.OneBitCipherBits)
			}
		}
	}
}

func TestAnalyzeTwiceDiffersForEveryAlgorithm(t *testing.T) {
	enc := newTestEnvelope(t)
	// All-zero input is the worst case for a broken (fixed-key) implementation.
	rows, err := Analyze(context.Background(), enc, "zeros.bin", make([]byte, 64<<10))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		// Independent random streams differ in 255/256 = 99.6% of positions.
		if r.TwiceDiffPercent < 99 {
			t.Errorf("%s: two encryptions differ in only %.2f%% of bytes", r.Algorithm, r.TwiceDiffPercent)
		}
		if r.CipherEntropy < 7.99 {
			t.Errorf("%s: ciphertext of all zeros has entropy %.4f, want about 8", r.Algorithm, r.CipherEntropy)
		}
		if r.PlainEntropy != 0 {
			t.Errorf("%s: plaintext entropy = %v, want 0", r.Algorithm, r.PlainEntropy)
		}
		if !r.ChiReliable || r.CipherChi > ChiSquareCritical5+60 {
			t.Errorf("%s: ciphertext chi-square %.1f (reliable=%v) is too far from uniform", r.Algorithm, r.CipherChi, r.ChiReliable)
		}
	}
}

func TestAnalyzeShortFileIsNotChiSquareReliable(t *testing.T) {
	rows, err := Analyze(context.Background(), newTestEnvelope(t), "tiny.bin", randomBytes(t, 100))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.ChiReliable {
			t.Errorf("%s: 100 bytes must not be flagged as chi-square reliable", r.Algorithm)
		}
	}
}

func TestAnalyzeHexPrefix(t *testing.T) {
	plain := append([]byte("%PDF-1.4"), make([]byte, 100)...)
	rows, err := Analyze(context.Background(), newTestEnvelope(t), "a.pdf", plain)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if len(r.PlainHex) != 2*HexPrefixLen || len(r.CipherHex) != 2*HexPrefixLen {
			t.Errorf("%s: hex lengths %d/%d, want %d", r.Algorithm, len(r.PlainHex), len(r.CipherHex), 2*HexPrefixLen)
		}
		if r.PlainHex[:16] != "255044462d312e34" { // "%PDF-1.4"
			t.Errorf("plaintext hex = %s", r.PlainHex)
		}
		if r.CipherHex == r.PlainHex {
			t.Errorf("%s: ciphertext prefix equals plaintext prefix", r.Algorithm)
		}
	}
}

// errEncryptor fails every Encrypt call.
type errEncryptor struct {
	crypto.Encryptor
	err error
}

func (e errEncryptor) Encrypt(context.Context, crypto.Algorithm, io.Writer, io.Reader) (crypto.Meta, error) {
	return crypto.Meta{}, e.err
}

func TestAnalyzeEncryptError(t *testing.T) {
	boom := errors.New("boom")
	_, err := Analyze(context.Background(), errEncryptor{err: boom}, "x", []byte("data"))
	if !errors.Is(err, boom) {
		t.Errorf("error = %v, want wrapping %v", err, boom)
	}
}

func TestAnalyzeUnknownAlgorithmFromEnvelope(t *testing.T) {
	_, _, err := encrypt(context.Background(), newTestEnvelope(t), "blowfish", []byte("x"))
	if !errors.Is(err, crypto.ErrUnknownAlgorithm) {
		t.Errorf("error = %v, want ErrUnknownAlgorithm", err)
	}
}

// noMAC copies bytes through with no integrity check, like CTR or RC4 on their own.
type noMAC struct{ crypto.Encryptor }

func (noMAC) Encrypt(_ context.Context, alg crypto.Algorithm, dst io.Writer, src io.Reader) (crypto.Meta, error) {
	_, err := io.Copy(dst, src)
	return crypto.Meta{Algorithm: alg}, err
}

func (noMAC) Decrypt(_ context.Context, _ crypto.Algorithm, _ crypto.Meta, dst io.Writer, src io.ReadSeeker) error {
	_, err := io.Copy(dst, src)
	return err
}

// The tamper check must be able to fail: without a MAC, a flipped bit goes through.
func TestAnalyzeTamperCheckIsNotVacuous(t *testing.T) {
	rows, err := Analyze(context.Background(), noMAC{}, "x", []byte("some plaintext to flip a bit in"))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.TamperDetected {
			t.Errorf("%s: a cipher with no MAC cannot detect tampering", r.Algorithm)
		}
	}
}
