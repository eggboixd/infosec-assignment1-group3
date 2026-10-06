// Package profile stores each user's private personal data (as defined by
// GDPR and Indonesia's UU PDP), encrypted field by field with every
// algorithm.
package profile

import (
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
)

// PrivateData is the plaintext form of a profile. It exists only in memory,
// as validated form input or as the result of decryption, and is never
// persisted or logged.
type PrivateData struct {
	FullName string `form:"full_name" binding:"required,max=100"`
	// NIK is the 16-digit Indonesian national identity number.
	NIK         string `form:"nik" binding:"required,numeric,len=16"`
	DateOfBirth string `form:"date_of_birth" binding:"required,datetime=2006-01-02"`
	Address     string `form:"address" binding:"required,max=300"`
	// Phone is digits only, for example 081234567890.
	Phone string `form:"phone" binding:"required,numeric,min=9,max=15"`
	Email string `form:"email" binding:"required,email,max=254"`
}

// Profile is the stored document. Every private field holds one ciphertext
// per algorithm.
type Profile struct {
	ID          bson.ObjectID    `bson:"_id,omitempty"`
	UserID      bson.ObjectID    `bson:"user_id"`
	FullName    crypto.SealedSet `bson:"full_name"`
	NIK         crypto.SealedSet `bson:"nik"`
	DateOfBirth crypto.SealedSet `bson:"date_of_birth"`
	Address     crypto.SealedSet `bson:"address"`
	Phone       crypto.SealedSet `bson:"phone"`
	Email       crypto.SealedSet `bson:"email"`
	// NIKIndex is a keyed hash (blind index) of the NIK, so uniqueness can
	// be enforced without storing the NIK in plaintext.
	NIKIndex  []byte    `bson:"nik_index,omitempty"`
	CreatedAt time.Time `bson:"created_at"`
	UpdatedAt time.Time `bson:"updated_at"`
}
