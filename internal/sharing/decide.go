package sharing

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// Approve approves a pending request to ownerID for duration ("1d", "7d" or
// "30d"; "" means 7d). The share key is created (Granter.Grant) before the
// status changes, so an approved request always has share material
// (docs/decisions.md D55).
func (s *Service) Approve(ctx context.Context, ownerID, requestID bson.ObjectID, duration string) (*Request, error) {
	d, err := ParseDuration(duration)
	if err != nil {
		return nil, err
	}
	r, err := s.load(ctx, requestID, actorOwner, ownerID, StatusPending, ErrNotPending)
	if err != nil {
		return nil, err
	}
	if _, err := s.encryptionFingerprint(ctx, r.RequesterID); err != nil {
		slog.Warn("sharing: approve refused, requester key", "request_id", r.ID.Hex(), "requester_id", r.RequesterID.Hex(), "error", err)
		return nil, ErrRequesterKeys
	}

	decided := s.now()
	exp := decided.Add(d)
	if err := s.granter.Grant(ctx, Grant{RequestID: r.ID, OwnerID: r.OwnerID, RequesterID: r.RequesterID, ExpiresAt: exp}); err != nil {
		slog.Error("sharing: grant", "request_id", r.ID.Hex(), "error", err)
		return nil, fmt.Errorf("%w: %v", ErrGrant, err)
	}

	// Grant can take a while: check expiry against the time now.
	ok, err := s.store.Transition(ctx, transition{
		ID: r.ID, Actor: actorOwner, ActorID: ownerID,
		From: StatusPending, To: StatusApproved, Now: s.now(), RequireUnexpired: true,
		DecidedAt: &decided, ExpiresAt: &exp,
	})
	if err != nil {
		s.destroy(ctx, r.ID)
		return nil, err
	}
	if !ok {
		cur, ferr := s.store.Find(ctx, r.ID, actorOwner, ownerID)
		if ferr == nil && cur.Status == StatusApproved {
			// A concurrent approve (a double click) won. Its material is
			// keyed by the same request ID: leave it.
			return nil, ErrNotPending
		}
		s.destroy(ctx, r.ID)
		if ferr == nil && cur.EffectiveStatus(s.now()) == StatusExpired {
			return nil, ErrExpired
		}
		return nil, ErrNotPending
	}

	r.Status, r.DecidedAt, r.ExpiresAt = StatusApproved, &decided, exp
	slog.Info("sharing: request approved", "request_id", r.ID.Hex(), "owner_id", ownerID.Hex(), "expires_at", exp)
	return r, nil
}

// Reject rejects a pending request to ownerID.
func (s *Service) Reject(ctx context.Context, ownerID, requestID bson.ObjectID) error {
	now := s.now()
	return s.decide(ctx, transition{
		ID: requestID, Actor: actorOwner, ActorID: ownerID,
		From: StatusPending, To: StatusRejected, RequireUnexpired: true, DecidedAt: &now,
	}, ErrNotPending)
}

// Cancel withdraws a pending request from requesterID.
func (s *Service) Cancel(ctx context.Context, requesterID, requestID bson.ObjectID) error {
	now := s.now()
	return s.decide(ctx, transition{
		ID: requestID, Actor: actorRequester, ActorID: requesterID,
		From: StatusPending, To: StatusCancelled, RequireUnexpired: true, EndedAt: &now,
	}, ErrNotPending)
}

// Revoke ends approved access to ownerID's data. Access stops when the
// status changes; deleting the share material comes after, and a failure
// there is logged, not returned, because Active already refuses access.
func (s *Service) Revoke(ctx context.Context, ownerID, requestID bson.ObjectID) error {
	now := s.now()
	if err := s.decide(ctx, transition{
		ID: requestID, Actor: actorOwner, ActorID: ownerID,
		From: StatusApproved, To: StatusRevoked, RequireUnexpired: true, EndedAt: &now,
	}, ErrNotApproved); err != nil {
		return err
	}
	s.destroy(ctx, requestID)
	return nil
}

// Active returns the request if requesterID is its requester and it is
// approved and unexpired right now. feature/share-keys must call it on
// every request that opens shared data.
func (s *Service) Active(ctx context.Context, requestID, requesterID bson.ObjectID) (*Request, error) {
	return s.load(ctx, requestID, actorRequester, requesterID, StatusApproved, ErrNotApproved)
}

// load finds the request as actor and checks its effective status is want.
func (s *Service) load(ctx context.Context, id bson.ObjectID, actor string, actorID bson.ObjectID, want Status, wrong error) (*Request, error) {
	r, err := s.store.Find(ctx, id, actor, actorID)
	if err != nil {
		return nil, err
	}
	switch r.EffectiveStatus(s.now()) {
	case want:
		return r, nil
	case StatusExpired:
		return nil, ErrExpired
	default:
		return nil, wrong
	}
}

// decide checks the request, then applies t as a compare-and-set. If the
// update loses a race, the current state decides the error.
func (s *Service) decide(ctx context.Context, t transition, wrong error) error {
	if _, err := s.load(ctx, t.ID, t.Actor, t.ActorID, t.From, wrong); err != nil {
		return err
	}
	t.Now = s.now()
	ok, err := s.store.Transition(ctx, t)
	if err != nil {
		return err
	}
	if !ok {
		_, err := s.load(ctx, t.ID, t.Actor, t.ActorID, t.From, wrong)
		if err == nil || errors.Is(err, ErrNotFound) {
			return wrong
		}
		return err
	}
	slog.Info("sharing: request "+string(t.To), "request_id", t.ID.Hex(), "actor_id", t.ActorID.Hex())
	return nil
}
