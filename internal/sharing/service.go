package sharing

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/eggboixd/infosec-assignment1-group3/internal/auth"
	"github.com/eggboixd/infosec-assignment1-group3/internal/keypair"
)

// requestStore is what the service needs from storage. *Store implements it.
type requestStore interface {
	Insert(ctx context.Context, r *Request) error
	Find(ctx context.Context, id bson.ObjectID, actor string, actorID bson.ObjectID) (*Request, error)
	List(ctx context.Context, actor string, actorID bson.ObjectID, limit int) ([]Request, error)
	CountPending(ctx context.Context, requesterID bson.ObjectID, now time.Time) (int, error)
	ListLapsed(ctx context.Context, requesterID, ownerID bson.ObjectID, now time.Time) ([]Request, error)
	Transition(ctx context.Context, t transition) (bool, error)
}

// userLookup finds users by normalised username. auth.Store implements it.
type userLookup interface {
	FindByUsername(ctx context.Context, username string) (*auth.User, error)
}

// keyInfo describes a user's public keys. keypair.Service implements it.
type keyInfo interface {
	Info(ctx context.Context, userID bson.ObjectID) ([]keypair.Info, error)
}

// Granter creates and deletes the share material for a request. It is
// implemented by feature/share-keys (docs/sharing.md).
type Granter interface {
	// Grant generates the share key for an approved request, re-wraps the
	// owner's DEKs under it, encrypts it to the requester's public
	// encryption key and stores what it needs, keyed by g.RequestID. It must
	// be idempotent per RequestID.
	Grant(ctx context.Context, g Grant) error
	// Destroy deletes all share material for requestID. Deleting nothing is
	// not an error.
	Destroy(ctx context.Context, requestID bson.ObjectID) error
}

// Grant is what Granter.Grant gets for one approval.
type Grant struct {
	RequestID   bson.ObjectID
	OwnerID     bson.ObjectID
	RequesterID bson.ObjectID
	ExpiresAt   time.Time
}

// View is a request as a page shows it.
type View struct {
	Request
	// Status is the effective status (expiry applied); Request.Status is
	// the stored one.
	Status Status
	// Fingerprint is the requester's encryption-key fingerprint, set on
	// pending inbox rows so the owner can compare it before approving.
	Fingerprint string
	// KeyProblem is set when that key is missing or failed its check.
	KeyProblem bool
}

// Service runs the share-request lifecycle.
type Service struct {
	store   requestStore
	users   userLookup
	keys    keyInfo
	granter Granter
	limiter *rateLimiter
	now     func() time.Time
}

// NewService returns a Service.
func NewService(store requestStore, users userLookup, keys keyInfo, g Granter) *Service {
	return &Service{
		store:   store,
		users:   users,
		keys:    keys,
		granter: g,
		limiter: newRateLimiter(sendLimit, sendWindow),
		now:     time.Now,
	}
}

// Send creates a pending request from requester to the user named
// ownerUsername, for all of that user's private data.
func (s *Service) Send(ctx context.Context, requester *auth.User, ownerUsername, reason string) (*Request, error) {
	reason = strings.TrimSpace(reason)
	if utf8.RuneCountInString(reason) > MaxReasonRunes {
		return nil, ErrReasonTooLong
	}
	name := auth.NormalizeUsername(ownerUsername)
	if name == "" {
		return nil, ErrUserNotFound
	}
	if name == auth.NormalizeUsername(requester.Username) {
		return nil, ErrSelfRequest
	}
	if !s.limiter.allow(requester.ID.Hex()) {
		return nil, ErrRateLimited
	}
	owner, err := s.users.FindByUsername(ctx, name)
	if errors.Is(err, auth.ErrUserNotFound) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("sharing: find user: %w", err)
	}
	if owner.ID == requester.ID {
		return nil, ErrSelfRequest
	}

	now := s.now()
	n, err := s.store.CountPending(ctx, requester.ID, now)
	if err != nil {
		return nil, err
	}
	if n >= MaxPendingOutgoing {
		return nil, ErrTooManyPending
	}

	// An old request for this pair that lapsed but is still stored open
	// would hit the unique index: mark it expired first.
	lapsed, err := s.store.ListLapsed(ctx, requester.ID, owner.ID, now)
	if err != nil {
		return nil, err
	}
	for i := range lapsed {
		s.markExpired(ctx, &lapsed[i])
	}

	r := &Request{
		RequesterID:   requester.ID,
		OwnerID:       owner.ID,
		RequesterName: auth.NormalizeUsername(requester.Username),
		OwnerName:     owner.Username,
		Reason:        reason,
		Status:        StatusPending,
		CreatedAt:     now,
		ExpiresAt:     now.Add(PendingLifetime),
	}
	if err := s.store.Insert(ctx, r); err != nil {
		return nil, err
	}
	slog.Info("sharing: request sent", "request_id", r.ID.Hex(), "requester_id", r.RequesterID.Hex(), "owner_id", r.OwnerID.Hex())
	return r, nil
}

// Inbox lists requests to ownerID, newest first.
func (s *Service) Inbox(ctx context.Context, ownerID bson.ObjectID) ([]View, error) {
	reqs, err := s.store.List(ctx, actorOwner, ownerID, ListLimit)
	if err != nil {
		return nil, err
	}
	views := s.views(ctx, reqs)
	for i := range views {
		v := &views[i]
		if v.Status != StatusPending {
			continue
		}
		fp, err := s.encryptionFingerprint(ctx, v.RequesterID)
		if err != nil {
			slog.Warn("sharing: requester key info", "request_id", v.ID.Hex(), "requester_id", v.RequesterID.Hex(), "error", err)
			v.KeyProblem = true
			continue
		}
		v.Fingerprint = fp
	}
	return views, nil
}

// Sent lists requests from requesterID, newest first.
func (s *Service) Sent(ctx context.Context, requesterID bson.ObjectID) ([]View, error) {
	reqs, err := s.store.List(ctx, actorRequester, requesterID, ListLimit)
	if err != nil {
		return nil, err
	}
	return s.views(ctx, reqs), nil
}

// views applies expiry, and stores the change for rows that lapsed.
func (s *Service) views(ctx context.Context, reqs []Request) []View {
	now := s.now()
	out := make([]View, len(reqs))
	for i := range reqs {
		eff := reqs[i].EffectiveStatus(now)
		if eff == StatusExpired && reqs[i].Status != StatusExpired {
			s.markExpired(ctx, &reqs[i])
		}
		out[i] = View{Request: reqs[i], Status: eff}
	}
	return out
}

// markExpired stores a lapsed request as expired and, if it was approved,
// destroys its share material. Failures are logged, never returned: the
// effective status already denies access.
func (s *Service) markExpired(ctx context.Context, r *Request) {
	end := r.ExpiresAt
	ok, err := s.store.Transition(ctx, transition{
		ID: r.ID, Actor: actorOwner, ActorID: r.OwnerID,
		From: r.Status, To: StatusExpired, Now: s.now(), EndedAt: &end,
	})
	if err != nil {
		slog.Error("sharing: mark expired", "request_id", r.ID.Hex(), "error", err)
		return
	}
	if !ok {
		return
	}
	was := r.Status
	r.Status, r.EndedAt = StatusExpired, &end
	if was == StatusApproved {
		s.destroy(ctx, r.ID)
	}
}

// destroy calls Granter.Destroy and logs a failure.
func (s *Service) destroy(ctx context.Context, id bson.ObjectID) {
	if err := s.granter.Destroy(ctx, id); err != nil {
		slog.Error("sharing: destroy share material", "request_id", id.Hex(), "error", err)
	}
}

// encryptionFingerprint returns userID's encryption-key fingerprint.
func (s *Service) encryptionFingerprint(ctx context.Context, userID bson.ObjectID) (string, error) {
	infos, err := s.keys.Info(ctx, userID)
	if err != nil {
		return "", err
	}
	for _, in := range infos {
		if in.Purpose == keypair.Encryption {
			return in.Fingerprint, nil
		}
	}
	return "", keypair.ErrNoKeys
}
