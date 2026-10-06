package crypto

import (
	"encoding/base64"
	"errors"
	"fmt"
)

// MasterKeySize is the required length of the master key (KEK) in bytes.
const MasterKeySize = 32

// ErrNotImplemented marks key operations that are still stubs.
var ErrNotImplemented = errors.New("crypto: not implemented")

// LoadMasterKey decodes a standard-base64 master key and checks its length.
// The error never contains the key or any part of it.
func LoadMasterKey(b64 string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, errors.New("master key must be standard base64")
	}
	if len(key) != MasterKeySize {
		return nil, fmt.Errorf("master key must decode to %d bytes, got %d", MasterKeySize, len(key))
	}
	return key, nil
}

// WrapKey encrypts a DEK or MAC key under the master key (KEK) so it can be
// stored in MongoDB.
//
// TODO(feature/crypto-core): implement authenticated key wrapping (for
// example AES-256-GCM with a random nonce, or AES key wrap) under a key
// derived from kek with DeriveKey.
func WrapKey(kek, key []byte) ([]byte, error) {
	return nil, fmt.Errorf("wrap key: %w", ErrNotImplemented)
}

// UnwrapKey reverses WrapKey and fails if the wrapped key was modified.
//
// TODO(feature/crypto-core): implement together with WrapKey.
func UnwrapKey(kek, wrapped []byte) ([]byte, error) {
	return nil, fmt.Errorf("unwrap key: %w", ErrNotImplemented)
}

// DeriveKey derives an independent 32-byte subkey from the master key for
// one purpose, named by info (for example "nik-blind-index" or "key-wrap").
//
// TODO(feature/crypto-core): implement with crypto/hkdf.Key(sha256.New, master, nil, info, 32).
func DeriveKey(master []byte, info string) ([]byte, error) {
	return nil, fmt.Errorf("derive key %q: %w", info, ErrNotImplemented)
}
