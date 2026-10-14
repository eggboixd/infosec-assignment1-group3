package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des" // #nosec G502 -- DES is one of the three ciphers the assignment requires us to compare; see docs/decisions.md D15.
	"crypto/rc4" // #nosec G503 -- RC4 is one of the three ciphers the assignment requires us to compare; see docs/decisions.md D15.
	"fmt"
)

// Data-key (DEK) sizes in bytes.
const (
	aesKeySize = 32 // AES-256: the largest AES key size.
	desKeySize = 8  // DES only has one key size: 64 bits, of which 56 are used (one parity bit per byte is ignored).
	rc4KeySize = 32 // RC4 accepts 1 to 256 bytes; 256 bits matches AES-256.
)

// dekSize returns the data-key length for alg, or 0 if alg is unknown.
func dekSize(alg Algorithm) int {
	switch alg {
	case AES:
		return aesKeySize
	case DES:
		return desKeySize
	case RC4:
		return rc4KeySize
	}
	return 0
}

// newStream returns the keystream generator for alg. It is the only place in
// the code base where AES, DES and RC4 are constructed.
//
// AES and DES are block ciphers, so they are run in CTR mode: the block
// cipher encrypts a counter (iv, iv+1, iv+2, ...) and the output is the
// keystream. The plaintext itself never goes through the block cipher, which
// is why identical plaintext blocks do not give identical ciphertext blocks
// (the weakness of ECB), and why no padding is needed. RC4 is already a
// stream cipher and takes no IV.
//
// Encryption and decryption are the same operation: XOR with the keystream.
// key and iv must be fresh for every encryption; reusing a (key, iv) pair, or
// an RC4 key, reuses the keystream and leaks the XOR of the two plaintexts.
func newStream(alg Algorithm, key, iv []byte) (cipher.Stream, error) {
	if !alg.Valid() {
		return nil, fmt.Errorf("%w: %q", ErrUnknownAlgorithm, alg)
	}
	// Strict lengths: a wrong length here is always a bug or tampering, never
	// something to silently accept. Errors report lengths, never key bytes.
	if len(key) != dekSize(alg) {
		return nil, fmt.Errorf("%s key must be %d bytes, got %d", alg, dekSize(alg), len(key))
	}
	if len(iv) != alg.IVSize() {
		return nil, fmt.Errorf("%s IV must be %d bytes, got %d", alg, alg.IVSize(), len(iv))
	}

	switch alg {
	case AES:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("aes: %w", err)
		}
		return cipher.NewCTR(block, iv), nil
	case DES:
		block, err := des.NewCipher(key) // #nosec G405 -- required by the assignment; see docs/decisions.md D15.
		if err != nil {
			return nil, fmt.Errorf("des: %w", err)
		}
		return cipher.NewCTR(block, iv), nil
	default: // RC4; alg.Valid() was checked above.
		c, err := rc4.NewCipher(key) // #nosec G405 -- required by the assignment; see docs/decisions.md D15.
		if err != nil {
			return nil, fmt.Errorf("rc4: %w", err)
		}
		return c, nil
	}
}
