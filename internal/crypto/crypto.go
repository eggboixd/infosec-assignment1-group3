// Package crypto is the team-wide encryption contract.
//
// Every stored object and every private-data field is encrypted once per
// Algorithm. AES-256 and DES run in CTR mode and RC4 runs as a native stream
// cipher, so all three are driven through cipher.Stream by one streaming code
// path. Each encryption uses a fresh random data key (DEK), a fresh random IV
// (none for RC4), and a separate HMAC-SHA256 key; the MAC is computed over the
// ciphertext (encrypt-then-MAC). DEK and MAC key are wrapped with the master
// key (KEK) and stored in Meta next to the ciphertext.
//
// This package must not import Gin or any feature package.
package crypto

import (
	"context"
	"errors"
	"fmt"
	"io"
)

// Algorithm identifies one of the three ciphers under comparison.
type Algorithm string

// Supported algorithms. The string values are used in URLs (?alg=aes),
// MongoDB documents, and benchmark records, so they must not change.
const (
	AES Algorithm = "aes" // AES-256-CTR
	DES Algorithm = "des" // DES-CTR
	RC4 Algorithm = "rc4" // RC4 stream cipher
)

// IV sizes in bytes, equal to the block size of each cipher.
const (
	AESIVSize = 16
	DESIVSize = 8
)

// ErrUnknownAlgorithm is returned for an Algorithm outside All().
var ErrUnknownAlgorithm = errors.New("crypto: unknown algorithm")

// ErrAuthentication is returned when an HMAC tag does not verify. Callers
// must treat the data as tampered and must not use any of it.
var ErrAuthentication = errors.New("crypto: message authentication failed")

// All returns every supported algorithm in a stable order.
func All() []Algorithm {
	return []Algorithm{AES, DES, RC4}
}

// Valid reports whether a is one of All().
func (a Algorithm) Valid() bool {
	switch a {
	case AES, DES, RC4:
		return true
	}
	return false
}

// ParseAlgorithm converts user input such as a query parameter into an
// Algorithm.
func ParseAlgorithm(s string) (Algorithm, error) {
	a := Algorithm(s)
	if !a.Valid() {
		return "", fmt.Errorf("%w: %q", ErrUnknownAlgorithm, s)
	}
	return a, nil
}

// IVSize returns the IV length for a, or 0 for RC4.
func (a Algorithm) IVSize() int {
	switch a {
	case AES:
		return AESIVSize
	case DES:
		return DESIVSize
	}
	return 0
}

// Meta is everything needed, together with the master key, to verify and
// decrypt one ciphertext. It is safe to store: all key material is wrapped.
type Meta struct {
	Algorithm     Algorithm `bson:"alg" json:"alg"`
	IV            []byte    `bson:"iv,omitempty" json:"iv,omitempty"` // AESIVSize or DESIVSize bytes; empty for RC4
	WrappedDEK    []byte    `bson:"wrapped_dek" json:"-"`
	WrappedMACKey []byte    `bson:"wrapped_mac_key" json:"-"`
	Tag           []byte    `bson:"tag" json:"tag"` // HMAC-SHA256 over the ciphertext
}

// Encryptor encrypts and decrypts data under one master key.
//
// Implementations must:
//   - generate all keys and IVs with crypto/rand, fresh for every call;
//   - never reuse an IV or an RC4 key;
//   - stream data without buffering whole files in memory;
//   - add time spent in cipher and MAC operations to ClockFrom(ctx), if set;
//   - never log plaintext or key material.
type Encryptor interface {
	// Encrypt reads plaintext from src until EOF, writes ciphertext to dst,
	// and returns the Meta (including the HMAC tag) for the ciphertext.
	Encrypt(ctx context.Context, alg Algorithm, dst io.Writer, src io.Reader) (Meta, error)

	// Decrypt verifies meta.Tag over the whole of src first and returns
	// ErrAuthentication on mismatch without writing anything to dst. Only
	// after verification succeeds does it seek src back to the start and
	// write the plaintext to dst. alg must equal meta.Algorithm.
	Decrypt(ctx context.Context, alg Algorithm, meta Meta, dst io.Writer, src io.ReadSeeker) error

	// EncryptField encrypts a small in-memory value such as a MongoDB field.
	EncryptField(alg Algorithm, plaintext []byte) ([]byte, Meta, error)

	// DecryptField verifies and decrypts a value produced by EncryptField.
	DecryptField(alg Algorithm, meta Meta, ciphertext []byte) ([]byte, error)
}

// Sealed is a small value encrypted with EncryptField, stored as-is in
// MongoDB (for example one private-data field or an original filename).
type Sealed struct {
	Ciphertext []byte `bson:"ct"`
	Meta       Meta   `bson:"meta"`
}

// SealedSet holds the same value encrypted once with each algorithm.
type SealedSet map[Algorithm]Sealed
