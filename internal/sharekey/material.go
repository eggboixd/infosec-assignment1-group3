// Package sharekey makes, stores and uses the share key of an approved share
// request (Assignment 2, docs/sharekeys.md).
//
// When an owner approves a request, Grant generates a random 256-bit share
// key, re-wraps the DEK and MAC key of every item of the owner's private data
// (profile fields and files) under it, and encrypts the share key to the
// requester's RSA public encryption key with RSA-OAEP-SHA256. The owner sends
// that ciphertext to the requester over WhatsApp or email. The requester
// imports it: the app decrypts it with the requester's private key (password
// needed) and only then stores the share key, wrapped under a master-key
// subkey, so the shared data can be opened.
//
// internal/sharing decides who may see whose data and until when; every open
// in this package needs a *sharing.Request that sharing.Service.Active just
// returned.
package sharekey

import (
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
	"github.com/eggboixd/infosec-assignment1-group3/internal/files"
)

// Material is everything stored for one approved request, in the share_keys
// collection. It never holds the share key, a DEK or a MAC key in plaintext.
type Material struct {
	ID          bson.ObjectID `bson:"_id,omitempty"`
	RequestID   bson.ObjectID `bson:"request_id"`
	OwnerID     bson.ObjectID `bson:"owner_id"`
	RequesterID bson.ObjectID `bson:"requester_id"`
	// EncryptedKey is RSA-OAEP-SHA256(requester's encryption key, share
	// key), with the request ID in the label. It is what the owner sends.
	EncryptedKey []byte `bson:"encrypted_key"`
	// RequesterFingerprint is the fingerprint of the public key EncryptedKey
	// was made for, shown to the owner so both sides can compare it.
	RequesterFingerprint string `bson:"requester_fingerprint"`
	// KeyCheck is HMAC-SHA256(share key, request ID). Import compares it to
	// tell a wrong key from a right one without trying to decrypt data.
	KeyCheck []byte `bson:"key_check"`
	// ImportedKey is the share key under AES-256-GCM with a master-key
	// subkey, set when the requester imports the key. Empty before that.
	ImportedKey []byte     `bson:"imported_key,omitempty"`
	ImportedAt  *time.Time `bson:"imported_at,omitempty"`
	// Profile is nil when the owner had no profile at approval time.
	Profile   *sharedProfile `bson:"profile,omitempty"`
	Files     []sharedFile   `bson:"files"`
	CreatedAt time.Time      `bson:"created_at"`
}

// Imported reports whether the requester has imported the share key.
func (m *Material) Imported() bool { return len(m.ImportedKey) > 0 }

// sharedKeys are one item's DEK and MAC key, each wrapped under the share key
// with crypto.WrapKey.
type sharedKeys struct {
	DEK    []byte `bson:"dek"`
	MACKey []byte `bson:"mac_key"`
}

// sharedSealed is a copy of one stored field: the ciphertext and its original
// Meta (still needed for the MAC header), plus its keys under the share key.
type sharedSealed struct {
	Sealed crypto.Sealed `bson:"sealed"`
	Keys   sharedKeys    `bson:"keys"`
}

// sharedSet is one value, once per algorithm.
type sharedSet map[crypto.Algorithm]sharedSealed

// sharedProfile is a snapshot of the owner's profile at approval time. The
// ciphertexts are copied, so the owner editing their profile later doesn't
// break the share (the edit makes new DEKs; the old ones would be gone).
type sharedProfile struct {
	FullName    sharedSet `bson:"full_name"`
	NIK         sharedSet `bson:"nik"`
	DateOfBirth sharedSet `bson:"date_of_birth"`
	Address     sharedSet `bson:"address"`
	Phone       sharedSet `bson:"phone"`
	Email       sharedSet `bson:"email"`
}

// sharedFile is one of the owner's files at approval time. The ciphertext
// stays in object storage; only the keys are re-wrapped.
type sharedFile struct {
	FileID    bson.ObjectID                      `bson:"file_id"`
	Kind      files.Kind                         `bson:"kind"`
	Slot      files.Slot                         `bson:"slot,omitempty"`
	MIMEType  string                             `bson:"mime_type"`
	Size      int64                              `bson:"size"`
	CreatedAt time.Time                          `bson:"created_at"`
	FileName  sharedSet                          `bson:"file_name"`
	Variants  map[crypto.Algorithm]sharedVariant `bson:"variants"`
}

// sharedVariant is one encrypted copy of a shared file.
type sharedVariant struct {
	ObjectKey string      `bson:"object_key"`
	Meta      crypto.Meta `bson:"meta"`
	Keys      sharedKeys  `bson:"keys"`
}

// KeyView is what the owner sees to send the share key.
type KeyView struct {
	RequestID   bson.ObjectID
	Encoded     string // base64 of EncryptedKey
	Fingerprint string
	Imported    bool
	CreatedAt   time.Time
}

// FileView is one shared file as the requester's page lists it.
type FileView struct {
	ID     bson.ObjectID
	Name   string
	NameOK bool
	Kind   files.Kind
	// SlotLabel names the application document, or is empty.
	SlotLabel string
	Size      int64
}

// DownloadHeader describes a file before its plaintext is streamed.
type DownloadHeader struct {
	Name     string
	MIMEType string
	Size     int64
}
