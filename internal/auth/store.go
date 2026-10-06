package auth

import (
	"context"
	"errors"
	"fmt"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// ErrUserNotFound is returned when no user matches a lookup.
var ErrUserNotFound = errors.New("auth: user not found")

// ErrUsernameTaken is returned when Create hits the unique username index.
var ErrUsernameTaken = errors.New("auth: username already taken")

// Store persists users in MongoDB.
type Store struct {
	coll *mongo.Collection
}

// NewStore returns a Store backed by the users collection.
func NewStore(coll *mongo.Collection) *Store {
	return &Store{coll: coll}
}

// Create inserts u and sets u.ID.
func (s *Store) Create(ctx context.Context, u *User) error {
	res, err := s.coll.InsertOne(ctx, u)
	if mongo.IsDuplicateKeyError(err) {
		return ErrUsernameTaken
	}
	if err != nil {
		return fmt.Errorf("auth: insert user: %w", err)
	}
	if id, ok := res.InsertedID.(bson.ObjectID); ok {
		u.ID = id
	}
	return nil
}

// FindByUsername returns the user with the given username.
func (s *Store) FindByUsername(ctx context.Context, username string) (*User, error) {
	return s.findOne(ctx, bson.D{{Key: "username", Value: username}})
}

// FindByID returns the user with the given ID.
func (s *Store) FindByID(ctx context.Context, id bson.ObjectID) (*User, error) {
	return s.findOne(ctx, bson.D{{Key: "_id", Value: id}})
}

func (s *Store) findOne(ctx context.Context, filter bson.D) (*User, error) {
	var u User
	err := s.coll.FindOne(ctx, filter).Decode(&u)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("auth: find user: %w", err)
	}
	return &u, nil
}
