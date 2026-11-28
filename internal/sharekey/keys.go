package sharekey

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
)

// ShareKeySize is the share key length: an AES-256 key, and the length
// crypto.WrapKey needs for its key-encryption key.
const ShareKeySize = 32

const (
	// oaepLabelPrefix starts the RSA-OAEP label. The request ID follows, so
	// a share key encrypted for one request can't be imported into another.
	oaepLabelPrefix = "securestore/share-key/v1:"
	// keyCheckPrefix starts the input of the KeyCheck HMAC.
	keyCheckPrefix = "securestore/share-key-check/v1:"
	// importAADPrefix starts the GCM associated data of ImportedKey.
	importAADPrefix = "securestore/share-key-import/v1:"
	// importKeyInfo names the master-key subkey that wraps imported keys.
	importKeyInfo = "share-key-import"
)

// oaepLabel is the RSA-OAEP label for requestID's share key.
func oaepLabel(requestID bson.ObjectID) []byte {
	return []byte(oaepLabelPrefix + requestID.Hex())
}

// keyCheck returns HMAC-SHA256(shareKey, prefix || request ID). Storing it
// reveals nothing about the 256-bit key.
func keyCheck(shareKey []byte, requestID bson.ObjectID) []byte {
	mac := hmac.New(sha256.New, shareKey)
	mac.Write([]byte(keyCheckPrefix + requestID.Hex()))
	return mac.Sum(nil)
}

// importAEAD returns AES-256-GCM under the import subkey.
func importAEAD(importKey []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(importKey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

// sealShareKey wraps shareKey for storage after import. The request ID is
// associated data, so a wrapped key copied to another request fails to open.
func sealShareKey(importKey, shareKey []byte, requestID bson.ObjectID) ([]byte, error) {
	aead, err := importAEAD(importKey)
	if err != nil {
		return nil, fmt.Errorf("sharekey: seal: %w", err)
	}
	return aead.Seal(nil, nil, shareKey, []byte(importAADPrefix+requestID.Hex())), nil // #nosec G407 -- nonce is random, generated inside NewGCMWithRandomNonce.
}

// openShareKey reverses sealShareKey.
func openShareKey(importKey, sealed []byte, requestID bson.ObjectID) ([]byte, error) {
	aead, err := importAEAD(importKey)
	if err != nil {
		return nil, fmt.Errorf("sharekey: open key: %w", err)
	}
	if len(sealed) <= aead.Overhead() {
		return nil, fmt.Errorf("sharekey: open key: %w", crypto.ErrAuthentication)
	}
	k, err := aead.Open(nil, nil, sealed, []byte(importAADPrefix+requestID.Hex()))
	if err != nil || len(k) != ShareKeySize {
		return nil, fmt.Errorf("sharekey: open key: %w", crypto.ErrAuthentication)
	}
	return k, nil
}

// rewrap unwraps meta's keys with the master key and wraps them under the
// share key.
func rewrap(master, shareKey []byte, meta crypto.Meta) (sharedKeys, error) {
	dek, err := crypto.UnwrapKey(master, meta.WrappedDEK)
	if err != nil {
		return sharedKeys{}, fmt.Errorf("data key: %w", err)
	}
	defer clear(dek)
	macKey, err := crypto.UnwrapKey(master, meta.WrappedMACKey)
	if err != nil {
		return sharedKeys{}, fmt.Errorf("mac key: %w", err)
	}
	defer clear(macKey)

	var k sharedKeys
	if k.DEK, err = crypto.WrapKey(shareKey, dek); err != nil {
		return sharedKeys{}, err
	}
	if k.MACKey, err = crypto.WrapKey(shareKey, macKey); err != nil {
		return sharedKeys{}, err
	}
	return k, nil
}

// unwrapShared returns an item's DEK and MAC key from under the share key.
// The caller clears both.
func unwrapShared(shareKey []byte, k sharedKeys) (dek, macKey []byte, err error) {
	dek, err = crypto.UnwrapKey(shareKey, k.DEK)
	if err != nil {
		return nil, nil, err
	}
	macKey, err = crypto.UnwrapKey(shareKey, k.MACKey)
	if err != nil {
		clear(dek)
		return nil, nil, err
	}
	return dek, macKey, nil
}
