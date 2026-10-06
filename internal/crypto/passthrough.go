package crypto

import (
	"context"
	"fmt"
	"io"
	"time"
)

// PassthroughEncryptor satisfies Encryptor without encrypting anything. It
// exists so the other features can be built and tested before the real
// implementation lands. It must never ship.
//
// TODO(feature/crypto-core): replace with real implementation.
type PassthroughEncryptor struct{}

var _ Encryptor = PassthroughEncryptor{}

// placeholderMeta returns a Meta with correctly sized but meaningless fields.
func placeholderMeta(alg Algorithm) Meta {
	return Meta{
		Algorithm:     alg,
		IV:            make([]byte, alg.IVSize()),
		WrappedDEK:    []byte("placeholder-dek"),
		WrappedMACKey: []byte("placeholder-mac-key"),
		Tag:           []byte("placeholder-tag"),
	}
}

// Encrypt copies src to dst unchanged.
//
// TODO(feature/crypto-core): replace with real implementation.
func (PassthroughEncryptor) Encrypt(ctx context.Context, alg Algorithm, dst io.Writer, src io.Reader) (Meta, error) {
	if !alg.Valid() {
		return Meta{}, fmt.Errorf("%w: %q", ErrUnknownAlgorithm, alg)
	}
	start := time.Now()
	defer func() { ClockFrom(ctx).Add(time.Since(start)) }()
	if _, err := io.Copy(dst, src); err != nil {
		return Meta{}, fmt.Errorf("passthrough encrypt: %w", err)
	}
	return placeholderMeta(alg), nil
}

// Decrypt copies src to dst unchanged.
//
// TODO(feature/crypto-core): replace with real implementation.
func (PassthroughEncryptor) Decrypt(ctx context.Context, alg Algorithm, meta Meta, dst io.Writer, src io.ReadSeeker) error {
	if !alg.Valid() {
		return fmt.Errorf("%w: %q", ErrUnknownAlgorithm, alg)
	}
	if meta.Algorithm != alg {
		return fmt.Errorf("passthrough decrypt: meta is for %q, not %q", meta.Algorithm, alg)
	}
	start := time.Now()
	defer func() { ClockFrom(ctx).Add(time.Since(start)) }()
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("passthrough decrypt: %w", err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("passthrough decrypt: %w", err)
	}
	return nil
}

// EncryptField returns a copy of plaintext.
//
// TODO(feature/crypto-core): replace with real implementation.
func (PassthroughEncryptor) EncryptField(alg Algorithm, plaintext []byte) ([]byte, Meta, error) {
	if !alg.Valid() {
		return nil, Meta{}, fmt.Errorf("%w: %q", ErrUnknownAlgorithm, alg)
	}
	return append([]byte(nil), plaintext...), placeholderMeta(alg), nil
}

// DecryptField returns a copy of ciphertext.
//
// TODO(feature/crypto-core): replace with real implementation.
func (PassthroughEncryptor) DecryptField(alg Algorithm, meta Meta, ciphertext []byte) ([]byte, error) {
	if !alg.Valid() {
		return nil, fmt.Errorf("%w: %q", ErrUnknownAlgorithm, alg)
	}
	if meta.Algorithm != alg {
		return nil, fmt.Errorf("passthrough decrypt field: meta is for %q, not %q", meta.Algorithm, alg)
	}
	return append([]byte(nil), ciphertext...), nil
}
