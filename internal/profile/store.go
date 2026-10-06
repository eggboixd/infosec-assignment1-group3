package profile

import (
	"context"
	"errors"
	"fmt"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// ErrNotFound is returned when the user has no profile yet.
var ErrNotFound = errors.New("profile: not found")

// ErrNIKTaken is returned when another profile has the same NIK.
var ErrNIKTaken = errors.New("profile: NIK already registered")

// Store persists profiles in MongoDB.
type Store struct {
	coll *mongo.Collection
}

// NewStore returns a Store backed by the profiles collection.
func NewStore(coll *mongo.Collection) *Store {
	return &Store{coll: coll}
}

// Upsert replaces the profile for p.UserID, creating it if needed.
func (s *Store) Upsert(ctx context.Context, p *Profile) error {
	filter := bson.D{{Key: "user_id", Value: p.UserID}}
	_, err := s.coll.ReplaceOne(ctx, filter, p, options.Replace().SetUpsert(true))
	if mongo.IsDuplicateKeyError(err) {
		return ErrNIKTaken
	}
	if err != nil {
		return fmt.Errorf("profile: upsert: %w", err)
	}
	return nil
}

// FindByUserID returns the profile owned by userID.
func (s *Store) FindByUserID(ctx context.Context, userID bson.ObjectID) (*Profile, error) {
	var p Profile
	err := s.coll.FindOne(ctx, bson.D{{Key: "user_id", Value: userID}}).Decode(&p)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("profile: find: %w", err)
	}
	return &p, nil
}
