package applications

import (
	"context"
	"errors"
	"fmt"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// Store persists applications in MongoDB.
type Store struct {
	coll *mongo.Collection
}

// NewStore returns a Store backed by the applications collection.
func NewStore(coll *mongo.Collection) *Store {
	return &Store{coll: coll}
}

// Insert stores a new application. The unique index on index turns a second
// application to the same scholarship into ErrAlreadyApplied.
func (s *Store) Insert(ctx context.Context, a *Application) error {
	_, err := s.coll.InsertOne(ctx, a)
	if mongo.IsDuplicateKeyError(err) {
		return ErrAlreadyApplied
	}
	if err != nil {
		return fmt.Errorf("applications: insert: %w", err)
	}
	return nil
}

// Exists reports whether an application with the given blind index exists.
func (s *Store) Exists(ctx context.Context, index []byte) (bool, error) {
	err := s.coll.FindOne(ctx, bson.D{{Key: "index", Value: index}}).Err()
	if errors.Is(err, mongo.ErrNoDocuments) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("applications: find: %w", err)
	}
	return true, nil
}

// ListByUser returns every application owned by userID.
func (s *Store) ListByUser(ctx context.Context, userID bson.ObjectID) ([]Application, error) {
	cur, err := s.coll.Find(ctx, bson.D{{Key: "user_id", Value: userID}})
	if err != nil {
		return nil, fmt.Errorf("applications: list: %w", err)
	}
	var out []Application
	if err := cur.All(ctx, &out); err != nil {
		return nil, fmt.Errorf("applications: list: %w", err)
	}
	return out, nil
}
