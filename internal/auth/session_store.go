package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// SessionStore persists sessions in MongoDB. The TTL index on expires_at
// (internal/platform/mongodb/indexes.go) deletes expired documents; Find
// also checks the expiry, because the TTL monitor only runs every minute.
type SessionStore struct {
	coll *mongo.Collection
}

// NewSessionStore returns a SessionStore backed by the sessions collection.
func NewSessionStore(coll *mongo.Collection) *SessionStore {
	return &SessionStore{coll: coll}
}

// Create inserts s.
func (s *SessionStore) Create(ctx context.Context, sess *Session) error {
	if _, err := s.coll.InsertOne(ctx, sess); err != nil {
		return fmt.Errorf("auth: insert session: %w", err)
	}
	return nil
}

// Find returns the session with id if it expires after now.
func (s *SessionStore) Find(ctx context.Context, id []byte, now time.Time) (*Session, error) {
	filter := bson.D{
		{Key: "_id", Value: id},
		{Key: "expires_at", Value: bson.D{{Key: "$gt", Value: now}}},
	}
	var sess Session
	err := s.coll.FindOne(ctx, filter).Decode(&sess)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("auth: find session: %w", err)
	}
	return &sess, nil
}

// ClearJustLoggedIn removes the one-time just_logged_in flag.
func (s *SessionStore) ClearJustLoggedIn(ctx context.Context, id []byte) error {
	update := bson.D{{Key: "$unset", Value: bson.D{{Key: "just_logged_in", Value: ""}}}}
	if _, err := s.coll.UpdateByID(ctx, id, update); err != nil {
		return fmt.Errorf("auth: update session: %w", err)
	}
	return nil
}

// Delete removes the session. Deleting a missing session is not an error.
func (s *SessionStore) Delete(ctx context.Context, id []byte) error {
	if _, err := s.coll.DeleteOne(ctx, bson.D{{Key: "_id", Value: id}}); err != nil {
		return fmt.Errorf("auth: delete session: %w", err)
	}
	return nil
}
