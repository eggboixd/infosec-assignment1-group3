package benchmark

import (
	"context"
	"fmt"
	"time"

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

// List returns up to limit records created at or after since, newest
// first. A zero since means no lower bound.
func (s *Store) List(ctx context.Context, since time.Time, limit int64) ([]Record, error) {
	opts := options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}}).SetLimit(limit)
	cur, err := s.coll.Find(ctx, sinceFilter(since), opts)
	if err != nil {
		return nil, fmt.Errorf("benchmark: find: %w", err)
	}
	var out []Record
	if err := cur.All(ctx, &out); err != nil {
		return nil, fmt.Errorf("benchmark: decode: %w", err)
	}
	return out, nil
}

// Each calls fn for every record created at or after since, oldest first,
// reading them from a cursor so they are never all in memory. It stops at
// the first error from fn.
func (s *Store) Each(ctx context.Context, since time.Time, fn func(Record) error) error {
	opts := options.Find().SetSort(bson.D{{Key: "created_at", Value: 1}})
	cur, err := s.coll.Find(ctx, sinceFilter(since), opts)
	if err != nil {
		return fmt.Errorf("benchmark: find: %w", err)
	}
	defer cur.Close(context.WithoutCancel(ctx))
	for cur.Next(ctx) {
		var r Record
		if err := cur.Decode(&r); err != nil {
			return fmt.Errorf("benchmark: decode: %w", err)
		}
		if err := fn(r); err != nil {
			return err
		}
	}
	if err := cur.Err(); err != nil {
		return fmt.Errorf("benchmark: cursor: %w", err)
	}
	return nil
}

func sinceFilter(since time.Time) bson.D {
	if since.IsZero() {
		return bson.D{}
	}
	return bson.D{{Key: "created_at", Value: bson.D{{Key: "$gte", Value: since}}}}
}
