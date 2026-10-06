// Package auth owns user accounts: registration, login, password hashing,
// sessions, and the middleware that protects routes.
package auth

import (
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// User is an account stored in the users collection.
type User struct {
	ID       bson.ObjectID `bson:"_id,omitempty"`
	Username string        `bson:"username"`
	// PasswordHash is an Argon2id hash in PHC string format
	// ($argon2id$v=19$m=...,t=...,p=...$salt$hash). Never log it.
	PasswordHash string    `bson:"password_hash"`
	CreatedAt    time.Time `bson:"created_at"`
	UpdatedAt    time.Time `bson:"updated_at"`
}
