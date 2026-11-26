package keypair

import (
	"context"
	"errors"
	"fmt"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// errExists is returned by Insert when the user already has a document
// (the unique user_id index). EnsureKeys treats it as success.
var errExists = errors.New("keypair: user already has key pairs")

// errConflict is returned by ReplaceWrapped when the document changed since
// it was read (another password change won the race).
var errConflict = errors.New("keypair: key pairs changed concurrently")

// Store persists key-pair documents in MongoDB. Every method is scoped to
// one user ID.
type Store struct {
	coll *mongo.Collection
}

// NewStore returns a Store backed by the keypairs collection.
func NewStore(coll *mongo.Collection) *Store {
	return &Store{coll: coll}
}

// Insert stores d. It returns errExists if the user already has a document.
func (s *Store) Insert(ctx context.Context, d *Document) error {
	res, err := s.coll.InsertOne(ctx, d)
	if mongo.IsDuplicateKeyError(err) {
		return errExists
	}
	if err != nil {
		return fmt.Errorf("keypair: insert: %w", err)
	}
	if id, ok := res.InsertedID.(bson.ObjectID); ok {
		d.ID = id
	}
	return nil
}

// FindByUserID returns the user's document, or ErrNoKeys.
func (s *Store) FindByUserID(ctx context.Context, userID bson.ObjectID) (*Document, error) {
	var d Document
	err := s.coll.FindOne(ctx, bson.D{{Key: "user_id", Value: userID}}).Decode(&d)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, ErrNoKeys
	}
	if err != nil {
		return nil, fmt.Errorf("keypair: find: %w", err)
	}
	return &d, nil
}

// ReplaceWrapped stores newly wrapped private keys and their KDF
// parameters. It only matches while the document still has oldSalt, so of
// two concurrent password changes exactly one wins and the other gets
// errConflict instead of overwriting keys wrapped under a different KEK.
// The public halves are not touched.
func (s *Store) ReplaceWrapped(ctx context.Context, userID bson.ObjectID, oldSalt []byte, kdf KDFParams, encWrapped, signWrapped []byte) error {
	filter := bson.D{{Key: "user_id", Value: userID}, {Key: "kdf.salt", Value: oldSalt}}
	update := bson.D{{Key: "$set", Value: bson.D{
		{Key: "kdf", Value: kdf},
		{Key: "encryption.wrapped_private", Value: encWrapped},
		{Key: "signing.wrapped_private", Value: signWrapped},
	}}}
	res, err := s.coll.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("keypair: update: %w", err)
	}
	if res.MatchedCount == 0 {
		return errConflict
	}
	return nil
}
