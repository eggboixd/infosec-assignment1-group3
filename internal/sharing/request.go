// Package sharing owns share requests (Assignment 2): a user asks another
// user for access to all of their private data, and the owner approves,
// rejects, revokes or lets the request expire. The share-key cryptography is
// behind Granter and lives in feature/share-keys. See
// docs/superpowers/specs/2026-11-28-share-requests-design.md.
package sharing

import (
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// Status is the stored state of a request. EffectiveStatus adds expiry.
type Status string

// Stored statuses.
const (
	StatusPending   Status = "pending"
	StatusApproved  Status = "approved"
	StatusRejected  Status = "rejected"
	StatusCancelled Status = "cancelled"
	StatusRevoked   Status = "revoked"
	StatusExpired   Status = "expired"
)

// Limits from the design (§5.4).
const (
	// PendingLifetime is how long an unanswered request stays open.
	PendingLifetime = 7 * 24 * time.Hour
	// MaxPendingOutgoing caps a requester's open pending requests.
	MaxPendingOutgoing = 20
	// MaxReasonRunes caps the optional reason.
	MaxReasonRunes = 200
	// ListLimit caps the inbox and sent lists.
	ListLimit = 100
	// sendLimit sends are allowed per requester in each sendWindow.
	sendLimit  = 10
	sendWindow = time.Hour
)

// Request is one share request, stored in the share_requests collection. It
// holds no secret: no share key, no DEK and no private data.
type Request struct {
	ID          bson.ObjectID `bson:"_id,omitempty"`
	RequesterID bson.ObjectID `bson:"requester_id"`
	OwnerID     bson.ObjectID `bson:"owner_id"`
	// Usernames are copied in for display. They can't change.
	RequesterName string `bson:"requester_name"`
	OwnerName     string `bson:"owner_name"`
	// Reason is optional free text from the requester. It's not private data,
	// but it is user input: never log it.
	Reason    string     `bson:"reason,omitempty"`
	Status    Status     `bson:"status"`
	CreatedAt time.Time  `bson:"created_at"`
	DecidedAt *time.Time `bson:"decided_at,omitempty"`
	// ExpiresAt is when a pending request lapses, or, once approved, when
	// access ends.
	ExpiresAt time.Time  `bson:"expires_at"`
	EndedAt   *time.Time `bson:"ended_at,omitempty"`
}

// EffectiveStatus is the status at now: a pending or approved request whose
// ExpiresAt has been reached is expired, whatever is stored.
func (r *Request) EffectiveStatus(now time.Time) Status {
	if (r.Status == StatusPending || r.Status == StatusApproved) && !now.Before(r.ExpiresAt) {
		return StatusExpired
	}
	return r.Status
}

// Open reports whether the request is pending or approved at now.
func (r *Request) Open(now time.Time) bool {
	s := r.EffectiveStatus(now)
	return s == StatusPending || s == StatusApproved
}

// durations is the allowlist of access lengths an owner can pick.
var durations = map[string]time.Duration{
	"1d":  24 * time.Hour,
	"7d":  7 * 24 * time.Hour,
	"30d": 30 * 24 * time.Hour,
}

// DefaultDuration is used when the form sends no duration.
const DefaultDuration = "7d"

// ParseDuration maps "1d", "7d" (or "") and "30d" to a duration. Anything
// else is ErrBadDuration.
func ParseDuration(s string) (time.Duration, error) {
	if s == "" {
		s = DefaultDuration
	}
	d, ok := durations[s]
	if !ok {
		return 0, ErrBadDuration
	}
	return d, nil
}
