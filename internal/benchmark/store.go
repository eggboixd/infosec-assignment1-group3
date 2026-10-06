package benchmark

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Store persists benchmark records in MongoDB.
type Store struct {
	coll *mongo.Collection
}

// NewStore returns a Store backed by the benchmarks collection.
func NewStore(coll *mongo.Collection) *Store {
	return &Store{coll: coll}
}

// Save inserts one record.
func (s *Store) Save(ctx context.Context, r Record) error {
	if _, err := s.coll.InsertOne(ctx, r); err != nil {
		return fmt.Errorf("benchmark: insert: %w", err)
	}
	return nil
}

// List returns up to limit records, newest first.
func (s *Store) List(ctx context.Context, limit int64) ([]Record, error) {
	opts := options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}}).SetLimit(limit)
	cur, err := s.coll.Find(ctx, bson.D{}, opts)
	if err != nil {
		return nil, fmt.Errorf("benchmark: find: %w", err)
	}
	var out []Record
	if err := cur.All(ctx, &out); err != nil {
		return nil, fmt.Errorf("benchmark: decode: %w", err)
	}
	return out, nil
}
