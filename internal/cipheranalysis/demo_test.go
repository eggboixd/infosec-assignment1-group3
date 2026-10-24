package cipheranalysis

import (
	"bytes"
	"crypto/aes"
	"crypto/des" // #nosec G502 -- test of the demo-only DES path; see docs/decisions-analysis.md A3.
	"errors"
	"testing"

	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
)

func TestDemoEncryptIsDeterministicAndSymmetric(t *testing.T) {
	plain := []byte("the same plaintext, encrypted twice under the fixed demo key")
	for _, alg := range crypto.All() {
		t.Run(string(alg), func(t *testing.T) {
			a, err := DemoEncrypt(alg, plain)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := DemoEncrypt(alg, plain)
			if !bytes.Equal(a, b) {
				t.Error("fixed key and IV must give identical output")
			}
			if bytes.Equal(a, plain) {
				t.Error("ciphertext equals plaintext")
			}
			back, _ := DemoEncrypt(alg, a) // XOR keystream: encrypting again decrypts
			if !bytes.Equal(back, plain) {
				t.Error("applying the keystream twice must restore the plaintext")
			}
		})
	}
}

func TestDemoEncryptUnknownAlgorithm(t *testing.T) {
	if _, err := DemoEncrypt("blowfish", []byte("x")); !errors.Is(err, crypto.ErrUnknownAlgorithm) {
		t.Errorf("error = %v, want ErrUnknownAlgorithm", err)
	}
}

// CTR's first keystream block is the block cipher applied to the IV, so
// encrypting zeros shows that DemoEncrypt really is CTR and not ECB or XOR with
// a constant.
func TestDemoCTRFirstBlockIsEncryptedIV(t *testing.T) {
	t.Run("aes", func(t *testing.T) {
		block, _ := aes.NewCipher(demoKey(crypto.AES))
		want := make([]byte, aes.BlockSize)
		block.Encrypt(want, demoIV(crypto.AES))
		got, _ := DemoEncrypt(crypto.AES, make([]byte, aes.BlockSize))
		if !bytes.Equal(got, want) {
			t.Errorf("got %x, want %x", got, want)
		}
	})
	t.Run("des", func(t *testing.T) {
		block, _ := des.NewCipher(demoKey(crypto.DES)) // #nosec G405 -- test of the demo-only DES path.
		want := make([]byte, des.BlockSize)
		block.Encrypt(want, demoIV(crypto.DES))
		got, _ := DemoEncrypt(crypto.DES, make([]byte, des.BlockSize))
		if !bytes.Equal(got, want) {
			t.Errorf("got %x, want %x", got, want)
		}
	})
}

// The reason ECB is forbidden, as a test: two equal plaintext blocks give two
// equal ciphertext blocks in ECB, and different ones in CTR.
func TestECBLeaksRepeatedBlocksCTRDoesNot(t *testing.T) {
	block := bytes.Repeat([]byte{0xAB}, aes.BlockSize)
	plain := append(append([]byte(nil), block...), block...)

	ecb, err := DemoECBEncrypt(plain)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ecb[:16], ecb[16:]) {
		t.Error("ECB: equal plaintext blocks should give equal ciphertext blocks")
	}
	ctr, _ := DemoEncrypt(crypto.AES, plain)
	if bytes.Equal(ctr[:16], ctr[16:]) {
		t.Error("CTR: equal plaintext blocks must give different ciphertext blocks")
	}
}

func TestDemoECBEncrypt(t *testing.T) {
	tests := []struct {
		name    string
		size    int
		wantErr error
	}{
		{"empty", 0, nil},
		{"one block", 16, nil},
		{"many blocks", 16 * 100, nil},
		{"15 bytes", 15, ErrNotBlockAligned},
		{"17 bytes", 17, ErrNotBlockAligned},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := DemoECBEncrypt(make([]byte, tt.size))
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
			if err == nil && len(out) != tt.size {
				t.Errorf("len = %d, want %d", len(out), tt.size)
			}
		})
	}
}

func TestFlipBit(t *testing.T) {
	in := []byte{0x00, 0xff}
	out := FlipBit(in, 1, 7)
	if out[1] != 0x7f || out[0] != 0 {
		t.Errorf("got %x", out)
	}
	if in[1] != 0xff {
		t.Error("FlipBit must not modify its input")
	}
}
