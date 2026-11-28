package sharekey

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// errExists is returned by Insert when material for the request already
// exists (unique index request_id_unique).
var errExists = errors.New("sharekey: material already exists")

// The field that scopes a lookup to the acting user.
const (
	actorOwner     = "owner_id"
	actorRequester = "requester_id"
)

// Store persists share material in MongoDB.
type Store struct {
	coll *mongo.Collection
}

// NewStore returns a Store backed by the share_keys collection.
func NewStore(coll *mongo.Collection) *Store {
	return &Store{coll: coll}
}

// Insert stores m. A second insert for the same request returns errExists.
func (s *Store) Insert(ctx context.Context, m *Material) error {
	res, err := s.coll.InsertOne(ctx, m)
	if mongo.IsDuplicateKeyError(err) {
		return errExists
	}
	if err != nil {
		return fmt.Errorf("sharekey: insert: %w", err)
	}
	if id, ok := res.InsertedID.(bson.ObjectID); ok {
		m.ID = id
	}
	return nil
}

// Exists reports whether material for requestID is stored.
func (s *Store) Exists(ctx context.Context, requestID bson.ObjectID) (bool, error) {
	n, err := s.coll.CountDocuments(ctx, bson.D{{Key: "request_id", Value: requestID}})
	if err != nil {
		return false, fmt.Errorf("sharekey: count: %w", err)
	}
	return n > 0, nil
}

// Find returns the material for requestID if actorID is its owner or
// requester (actor names which). Otherwise ErrNotFound.
func (s *Store) Find(ctx context.Context, requestID bson.ObjectID, actor string, actorID bson.ObjectID) (*Material, error) {
	var m Material
	err := s.coll.FindOne(ctx, bson.D{{Key: "request_id", Value: requestID}, {Key: actor, Value: actorID}}).Decode(&m)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("sharekey: find: %w", err)
	}
	return &m, nil
}

// SetImported stores the imported (wrapped) share key.
func (s *Store) SetImported(ctx context.Context, requestID, requesterID bson.ObjectID, sealed []byte, at time.Time) error {
	res, err := s.coll.UpdateOne(ctx,
		bson.D{{Key: "request_id", Value: requestID}, {Key: actorRequester, Value: requesterID}},
		bson.D{{Key: "$set", Value: bson.D{{Key: "imported_key", Value: sealed}, {Key: "imported_at", Value: at}}}})
	if err != nil {
		return fmt.Errorf("sharekey: set imported: %w", err)
	}
	if res.MatchedCount == 0 {
		return ErrNotFound
	}
	return nil
}

// Delete removes all material for requestID. Deleting nothing is not an
// error.
func (s *Store) Delete(ctx context.Context, requestID bson.ObjectID) error {
	if _, err := s.coll.DeleteMany(ctx, bson.D{{Key: "request_id", Value: requestID}}); err != nil {
		return fmt.Errorf("sharekey: delete: %w", err)
	}
	return nil
}
