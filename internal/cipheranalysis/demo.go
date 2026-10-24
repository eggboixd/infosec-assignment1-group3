package cipheranalysis

// DEMO ONLY. Nothing in this file is used by the application, and nothing it
// produces is ever stored in MongoDB or MinIO.
//
// The real encryptor (internal/crypto.Envelope) draws a fresh key and IV on
// every call, so it can never encrypt two different plaintexts under the same
// key. Two of the experiments need exactly that:
//
//   - the one-bit test: flip one plaintext bit, encrypt both versions under the
//     same key and IV, and count how many ciphertext bits changed;
//   - the "why not ECB" picture: encrypt the same image with AES-ECB and with
//     AES-CTR.
//
// Reusing a (key, IV) pair is exactly what CLAUDE.md forbids in the app, so it
// is confined to this file, uses fixed non-secret demo values, and works on
// in-memory slices only. See docs/decisions-analysis.md (A3, "Amends D15").

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des" // #nosec G502 -- DES is one of the three ciphers the assignment compares; demo-only use, see docs/decisions-analysis.md A3.
	"crypto/rc4" // #nosec G503 -- RC4 is one of the three ciphers the assignment compares; demo-only use, see docs/decisions-analysis.md A3.
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
)

// Fixed, public demo key material. These are NOT secrets and are derived from
// the algorithm name only so the output of the experiments is reproducible.
func demoKey(alg crypto.Algorithm) []byte {
	sum := sha256.Sum256([]byte("securestore-analysis-demo-key/" + string(alg)))
	switch alg {
	case crypto.DES:
		return sum[:8]
	default: // AES-256 and RC4 both use 32 bytes here.
		return sum[:32]
	}
}

func demoIV(alg crypto.Algorithm) []byte {
	sum := sha256.Sum256([]byte("securestore-analysis-demo-iv/" + string(alg)))
	return sum[:alg.IVSize()] // empty for RC4
}

// demoStream builds the same keystream generators as internal/crypto does
// (AES-256-CTR, DES-CTR, RC4) but with the fixed demo key and IV.
func demoStream(alg crypto.Algorithm) (cipher.Stream, error) {
	key, iv := demoKey(alg), demoIV(alg)
	switch alg {
	case crypto.AES:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewCTR(block, iv), nil
	case crypto.DES:
		block, err := des.NewCipher(key) // #nosec G405 -- required by the assignment; demo-only, see docs/decisions-analysis.md A3.
		if err != nil {
			return nil, err
		}
		return cipher.NewCTR(block, iv), nil
	case crypto.RC4:
		return rc4.NewCipher(key) // #nosec G405 -- required by the assignment; demo-only, see docs/decisions-analysis.md A3.
	}
	return nil, fmt.Errorf("%w: %q", crypto.ErrUnknownAlgorithm, alg)
}

// DemoEncrypt returns data encrypted under the fixed demo key and IV. The same
// call twice gives the same output: that determinism is the point of the demo
// and the reason it must never be used on real data.
func DemoEncrypt(alg crypto.Algorithm, data []byte) ([]byte, error) {
	s, err := demoStream(alg)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	s.XORKeyStream(out, data)
	return out, nil
}

// ErrNotBlockAligned is returned by DemoECBEncrypt for input that is not a
// whole number of 16-byte blocks. The demo does not pad.
var ErrNotBlockAligned = errors.New("cipheranalysis: ECB demo input is not a multiple of 16 bytes")

// DemoECBEncrypt encrypts data with AES-256 in ECB mode: every 16-byte block
// is encrypted on its own, independently of every other block.
//
// ECB IS NOT USED ANYWHERE IN THE APPLICATION AND IS FORBIDDEN BY THE
// ASSIGNMENT. It exists only to show, in the report, what goes wrong: equal
// plaintext blocks give equal ciphertext blocks, so the picture survives
// encryption. The Go standard library deliberately has no ECB mode, so this is
// a plain loop over the block cipher.
func DemoECBEncrypt(data []byte) ([]byte, error) {
	if len(data)%aes.BlockSize != 0 {
		return nil, ErrNotBlockAligned
	}
	block, err := aes.NewCipher(demoKey(crypto.AES))
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += aes.BlockSize {
		block.Encrypt(out[i:i+aes.BlockSize], data[i:i+aes.BlockSize])
	}
	return out, nil
}

// FlipBit returns a copy of data with bit `bit` (0 = least significant) of
// byte `index` inverted.
func FlipBit(data []byte, index int, bit uint) []byte {
	out := append([]byte(nil), data...)
	out[index] ^= 1 << bit
	return out
}
