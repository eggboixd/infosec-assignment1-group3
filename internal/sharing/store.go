package sharing

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Actor fields: which side of a request the acting user must be on.
const (
	actorOwner     = "owner_id"
	actorRequester = "requester_id"
)

// transition is one compare-and-set status change. It matches only when the
// request has this ID, the actor field equals ActorID, the stored status is
// From and, if RequireUnexpired, expires_at is after Now.
type transition struct {
	ID               bson.ObjectID
	Actor            string
	ActorID          bson.ObjectID
	From, To         Status
	Now              time.Time
	RequireUnexpired bool
	DecidedAt        *time.Time
	ExpiresAt        *time.Time
	EndedAt          *time.Time
}

// Store persists share requests in MongoDB.
type Store struct {
	coll *mongo.Collection
}

// NewStore returns a Store backed by the share_requests collection.
func NewStore(coll *mongo.Collection) *Store {
	return &Store{coll: coll}
}

// Insert stores r and sets r.ID. The partial unique index open_pair_unique
// turns a second open request for the same pair into ErrAlreadyOpen.
func (s *Store) Insert(ctx context.Context, r *Request) error {
	res, err := s.coll.InsertOne(ctx, r)
	if mongo.IsDuplicateKeyError(err) {
		return ErrAlreadyOpen
	}
	if err != nil {
		return fmt.Errorf("sharing: insert: %w", err)
	}
	id, ok := res.InsertedID.(bson.ObjectID)
	if !ok {
		return fmt.Errorf("sharing: insert: unexpected id type %T", res.InsertedID)
	}
	r.ID = id
	return nil
}

// Find returns the request with id whose actor field is actorID.
func (s *Store) Find(ctx context.Context, id bson.ObjectID, actor string, actorID bson.ObjectID) (*Request, error) {
	var r Request
	err := s.coll.FindOne(ctx, bson.D{{Key: "_id", Value: id}, {Key: actor, Value: actorID}}).Decode(&r)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("sharing: find: %w", err)
	}
	return &r, nil
}

// List returns up to limit requests whose actor field is actorID, newest first.
func (s *Store) List(ctx context.Context, actor string, actorID bson.ObjectID, limit int) ([]Request, error) {
	opts := options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}, {Key: "_id", Value: -1}}).SetLimit(int64(limit))
	return s.find(ctx, bson.D{{Key: actor, Value: actorID}}, opts)
}

// CountPending counts the requester's pending requests that haven't lapsed.
func (s *Store) CountPending(ctx context.Context, requesterID bson.ObjectID, now time.Time) (int, error) {
	n, err := s.coll.CountDocuments(ctx, bson.D{
		{Key: "requester_id", Value: requesterID},
		{Key: "status", Value: StatusPending},
		{Key: "expires_at", Value: bson.D{{Key: "$gt", Value: now}}},
	})
	if err != nil {
		return 0, fmt.Errorf("sharing: count pending: %w", err)
	}
	return int(n), nil
}

// ListLapsed returns the pair's requests still stored as pending or approved
// whose expires_at has passed.
func (s *Store) ListLapsed(ctx context.Context, requesterID, ownerID bson.ObjectID, now time.Time) ([]Request, error) {
	return s.find(ctx, bson.D{
		{Key: "requester_id", Value: requesterID},
		{Key: "owner_id", Value: ownerID},
		{Key: "status", Value: bson.D{{Key: "$in", Value: bson.A{StatusPending, StatusApproved}}}},
		{Key: "expires_at", Value: bson.D{{Key: "$lte", Value: now}}},
	}, nil)
}

// Transition applies t as one conditional update and reports whether it matched.
func (s *Store) Transition(ctx context.Context, t transition) (bool, error) {
	filter := bson.D{{Key: "_id", Value: t.ID}, {Key: t.Actor, Value: t.ActorID}, {Key: "status", Value: t.From}}
	if t.RequireUnexpired {
		filter = append(filter, bson.E{Key: "expires_at", Value: bson.D{{Key: "$gt", Value: t.Now}}})
	}
	set := bson.D{{Key: "status", Value: t.To}}
	if t.DecidedAt != nil {
		set = append(set, bson.E{Key: "decided_at", Value: *t.DecidedAt})
	}
	if t.ExpiresAt != nil {
		set = append(set, bson.E{Key: "expires_at", Value: *t.ExpiresAt})
	}
	if t.EndedAt != nil {
		set = append(set, bson.E{Key: "ended_at", Value: *t.EndedAt})
	}
	res, err := s.coll.UpdateOne(ctx, filter, bson.D{{Key: "$set", Value: set}})
	if err != nil {
		return false, fmt.Errorf("sharing: transition: %w", err)
	}
	return res.MatchedCount == 1, nil
}

func (s *Store) find(ctx context.Context, filter bson.D, opts *options.FindOptionsBuilder) ([]Request, error) {
	var cur *mongo.Cursor
	var err error
	if opts != nil {
		cur, err = s.coll.Find(ctx, filter, opts)
	} else {
		cur, err = s.coll.Find(ctx, filter)
	}
	if err != nil {
		return nil, fmt.Errorf("sharing: list: %w", err)
	}
	var out []Request
	if err := cur.All(ctx, &out); err != nil {
		return nil, fmt.Errorf("sharing: list: %w", err)
	}
	return out, nil
}
