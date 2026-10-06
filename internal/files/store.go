package files

import (
	"context"
	"errors"
	"fmt"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// ErrNotFound is returned when a file does not exist or belongs to another
// user. The two cases are deliberately indistinguishable.
var ErrNotFound = errors.New("files: not found")

// Store persists file metadata in MongoDB. Every query is scoped to the
// owner, so one user can never read another user's records.
type Store struct {
	coll *mongo.Collection
}

// NewStore returns a Store backed by the files collection.
func NewStore(coll *mongo.Collection) *Store {
	return &Store{coll: coll}
}

// Insert stores rec and sets rec.ID.
func (s *Store) Insert(ctx context.Context, rec *FileRecord) error {
	res, err := s.coll.InsertOne(ctx, rec)
	if err != nil {
		return fmt.Errorf("files: insert: %w", err)
	}
	if id, ok := res.InsertedID.(bson.ObjectID); ok {
		rec.ID = id
	}
	return nil
}

// Get returns the record id owned by ownerID.
func (s *Store) Get(ctx context.Context, ownerID, id bson.ObjectID) (*FileRecord, error) {
	var rec FileRecord
	err := s.coll.FindOne(ctx, bson.D{{Key: "_id", Value: id}, {Key: "owner_id", Value: ownerID}}).Decode(&rec)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("files: find: %w", err)
	}
	return &rec, nil
}

// ListByOwner returns ownerID's records, newest first.
func (s *Store) ListByOwner(ctx context.Context, ownerID bson.ObjectID) ([]FileRecord, error) {
	opts := options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}})
	cur, err := s.coll.Find(ctx, bson.D{{Key: "owner_id", Value: ownerID}}, opts)
	if err != nil {
		return nil, fmt.Errorf("files: list: %w", err)
	}
	var out []FileRecord
	if err := cur.All(ctx, &out); err != nil {
		return nil, fmt.Errorf("files: decode: %w", err)
	}
	return out, nil
}

// Delete removes the record id owned by ownerID.
func (s *Store) Delete(ctx context.Context, ownerID, id bson.ObjectID) error {
	res, err := s.coll.DeleteOne(ctx, bson.D{{Key: "_id", Value: id}, {Key: "owner_id", Value: ownerID}})
	if err != nil {
		return fmt.Errorf("files: delete: %w", err)
	}
	if res.DeletedCount == 0 {
		return ErrNotFound
	}
	return nil
}
