package sharing

import "errors"

// Errors returned by Service. Check them with errors.Is. None contains user
// input, so they are safe to log next to request and user IDs.
var (
	ErrUserNotFound   = errors.New("sharing: no user with that username")
	ErrSelfRequest    = errors.New("sharing: cannot request your own data")
	ErrReasonTooLong  = errors.New("sharing: reason too long")
	ErrAlreadyOpen    = errors.New("sharing: an open request to this user already exists")
	ErrTooManyPending = errors.New("sharing: too many pending requests")
	ErrRateLimited    = errors.New("sharing: too many requests sent")
	// ErrNotFound is returned for an unknown request ID and for a request
	// the caller isn't party to in that role, so IDs reveal nothing.
	ErrNotFound      = errors.New("sharing: request not found")
	ErrNotPending    = errors.New("sharing: request is not pending")
	ErrNotApproved   = errors.New("sharing: request is not approved")
	ErrExpired       = errors.New("sharing: request has expired")
	ErrBadDuration   = errors.New("sharing: unknown access duration")
	ErrRequesterKeys = errors.New("sharing: requester's public key is missing or failed its integrity check")
	ErrGrant         = errors.New("sharing: could not create the share key")
)
