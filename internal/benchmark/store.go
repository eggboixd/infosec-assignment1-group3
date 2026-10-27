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
	defer cur.Close(ctx)
	var out []Record
	if err := cur.All(ctx, &out); err != nil {
		return nil, fmt.Errorf("benchmark: decode: %w", err)
	}
	return out, nil
}

// Iterate calls visit for each record in newest-first order without holding
// the complete collection in memory.
func (s *Store) Iterate(ctx context.Context, visit func(Record) error) error {
	cur, err := s.coll.Find(ctx, bson.D{}, options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}}))
	if err != nil {
		return fmt.Errorf("benchmark: find: %w", err)
	}
	defer cur.Close(ctx)
	for cur.Next(ctx) {
		var r Record
		if err := cur.Decode(&r); err != nil {
			return fmt.Errorf("benchmark: decode: %w", err)
		}
		if err := visit(r); err != nil {
			return err
		}
	}
	if err := cur.Err(); err != nil {
		return fmt.Errorf("benchmark: cursor: %w", err)
	}
	return nil
}
