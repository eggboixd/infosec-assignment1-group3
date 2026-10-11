package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

// MasterKeySize is the required length of the master key (KEK) in bytes.
const MasterKeySize = 32

// subkeySize is the length of every key returned by DeriveKey.
const subkeySize = 32

// keyWrapInfo is the HKDF info string for the key that wraps DEKs and MAC
// keys. Using a derived key instead of the master key itself means the
// master key is never used directly by any cipher (domain separation).
const keyWrapInfo = "key-wrap"

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
// It uses AES-256-GCM, an authenticated cipher, under a key derived from
// kek with DeriveKey(kek, "key-wrap"). The output is
// nonce (12 B) || encrypted key || GCM tag (16 B), so it is len(key)+28 bytes.
// The nonce is random (crypto/rand, inside cipher.NewGCMWithRandomNonce), so
// wrapping the same key twice gives different output.
func WrapKey(kek, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, errors.New("wrap key: key is empty")
	}
	aead, err := keyWrapAEAD(kek)
	if err != nil {
		return nil, fmt.Errorf("wrap key: %w", err)
	}
	return aead.Seal(nil, nil, key, nil), nil
}

// UnwrapKey reverses WrapKey and fails if the wrapped key was modified.
//
// Any failure to authenticate (wrong master key, modified or truncated input)
// returns an error wrapping ErrAuthentication, because the caller must treat
// all of them the same way: the stored data cannot be trusted.
func UnwrapKey(kek, wrapped []byte) ([]byte, error) {
	aead, err := keyWrapAEAD(kek)
	if err != nil {
		return nil, fmt.Errorf("unwrap key: %w", err)
	}
	// A valid wrapped key holds at least one key byte on top of the nonce
	// and tag; WrapKey never wraps an empty key.
	if len(wrapped) <= aead.Overhead() {
		return nil, fmt.Errorf("unwrap key: %w", ErrAuthentication)
	}
	key, err := aead.Open(nil, nil, wrapped, nil)
	if err != nil {
		return nil, fmt.Errorf("unwrap key: %w", ErrAuthentication)
	}
	return key, nil
}

// keyWrapAEAD returns the AES-256-GCM instance used by WrapKey and UnwrapKey.
func keyWrapAEAD(kek []byte) (cipher.AEAD, error) {
	wk, err := DeriveKey(kek, keyWrapInfo)
	if err != nil {
		return nil, err
	}
	// aes.NewCipher expands wk into its own key schedule, so our copy can be
	// cleared straight away.
	defer clear(wk)
	block, err := aes.NewCipher(wk)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

// DeriveKey derives an independent 32-byte subkey from the master key for
// one purpose, named by info (for example "nik-blind-index" or "key-wrap").
//
// It uses HKDF-SHA256 (RFC 5869) with no salt. A salt is only needed when the
// input key is not already uniformly random; the master key is 32 random
// bytes, so RFC 5869 section 3.1 allows omitting it. Different info strings
// give unrelated keys, so a key derived for one purpose is useless for
// another.
func DeriveKey(master []byte, info string) ([]byte, error) {
	if len(master) != MasterKeySize {
		return nil, fmt.Errorf("derive key %q: master key must be %d bytes, got %d", info, MasterKeySize, len(master))
	}
	if info == "" {
		return nil, errors.New("derive key: info must not be empty")
	}
	key, err := hkdf.Key(sha256.New, master, nil, info, subkeySize)
	if err != nil {
		return nil, fmt.Errorf("derive key %q: %w", info, err)
	}
	return key, nil
}
