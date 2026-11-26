// Package keypair gives every user two RSA-3072 key pairs: one for
// encryption (Assignment 2: others encrypt share keys to it with
// RSA-OAEP-SHA256) and one for signing (Assignment 3: PDF signatures).
//
// Public keys are stored in MongoDB as PKIX DER with a SHA-256 fingerprint
// and an HMAC that detects substitution. Private keys are stored only as
// PKCS#8 DER encrypted with AES-256-GCM under a key derived from the user's
// password with Argon2id, so neither the database nor MASTER_KEY alone can
// unlock them (docs/decisions.md D39–D44, docs/keypairs.md).
//
// This package only manages keys. It never encrypts share keys or signs
// anything itself.
package keypair

import (
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// KeyBits is the RSA modulus size of every key pair: about 128-bit security
// (NIST SP 800-57 Part 1, Table 2), the same level as AES-128 (D39).
const KeyBits = 3072

// Purpose names one of a user's two key pairs. A key is only ever used for
// its own purpose (D39).
type Purpose string

const (
	// Encryption is the pair others use to encrypt share keys for this user
	// (RSA-OAEP with SHA-256).
	Encryption Purpose = "encryption"
	// Signing is the pair this user signs documents with.
	Signing Purpose = "signing"
)

// purposes lists every purpose in display order.
var purposes = [...]Purpose{Encryption, Signing}

// ParsePurpose returns the Purpose named s ("encryption" or "signing").
// Matching is exact: s usually comes from a URL.
func ParsePurpose(s string) (Purpose, error) {
	for _, p := range purposes {
		if string(p) == s {
			return p, nil
		}
	}
	return "", ErrUnknownPurpose
}

var (
	// ErrNoKeys means the user has no key pairs yet. It is also what another
	// user's ID returns, because every lookup is by the given user ID only.
	ErrNoKeys = errors.New("keypair: user has no key pairs")

	// ErrUnlock means the private key could not be decrypted: either the
	// password is wrong or the encrypted key was modified. AES-GCM cannot
	// tell these apart (both are a tag mismatch), so neither can we (D43).
	// Show the user "wrong password".
	ErrUnlock = errors.New("keypair: wrong password or damaged private key")

	// ErrCorrupt means stored key data failed a check that does not depend on
	// the password: the public key's MAC or fingerprint, the KDF parameters,
	// or the key size. The stored data must not be used.
	ErrCorrupt = errors.New("keypair: stored key data is damaged")

	// ErrUnknownPurpose is returned for a Purpose other than Encryption or
	// Signing.
	ErrUnknownPurpose = errors.New("keypair: unknown key purpose")
)

// Document holds one user's two key pairs. It is stored in the keypairs
// collection, with a unique index on user_id, so a user has at most one.
type Document struct {
	ID      bson.ObjectID `bson:"_id,omitempty"`
	UserID  bson.ObjectID `bson:"user_id"`
	Version int           `bson:"version"`
	// KDF holds the Argon2id parameters and salt that turn the user's
	// password into the key-encryption key. The salt is not the password
	// hash's salt (D41).
	KDF        KDFParams  `bson:"kdf"`
	Encryption StoredPair `bson:"encryption"`
	Signing    StoredPair `bson:"signing"`
	CreatedAt  time.Time  `bson:"created_at"`
}

// documentVersion is the stored format described by Document.
const documentVersion = 1

// StoredPair is one key pair as stored.
type StoredPair struct {
	// PublicDER is the public key in PKIX (SubjectPublicKeyInfo) DER form.
	PublicDER []byte `bson:"public_der"`
	// Fingerprint is SHA-256(PublicDER).
	Fingerprint []byte `bson:"fingerprint"`
	// WrappedPrivate is the PKCS#8 DER private key encrypted with
	// AES-256-GCM: nonce (12 B) || ciphertext || tag (16 B). Never log it.
	WrappedPrivate []byte `bson:"wrapped_private"`
	// PublicMAC is an HMAC-SHA256 over the user ID, purpose, PublicDER,
	// Fingerprint and CreatedAt, under a MASTER_KEY subkey (D42).
	PublicMAC []byte    `bson:"public_mac"`
	CreatedAt time.Time `bson:"created_at"`
}

// pair returns the stored pair for p.
func (d *Document) pair(p Purpose) (*StoredPair, error) {
	switch p {
	case Encryption:
		return &d.Encryption, nil
	case Signing:
		return &d.Signing, nil
	}
	return nil, ErrUnknownPurpose
}

// Info is the public description of one key pair, for display.
type Info struct {
	Purpose Purpose
	Bits    int
	// Fingerprint is SHA-256 of the PKIX DER public key, formatted by
	// FormatFingerprint.
	Fingerprint string
	CreatedAt   time.Time
}
