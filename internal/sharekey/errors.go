package sharekey

import "errors"

// Errors returned by Service. Check them with errors.Is. None contains key
// material or user input, so they are safe to log next to request IDs.
var (
	// ErrNotFound is returned when no share material exists for the request
	// on the caller's side, or a file isn't part of the share.
	ErrNotFound = errors.New("sharekey: not found")
	// ErrNotImported is returned when the requester opens data before
	// importing the share key.
	ErrNotImported = errors.New("sharekey: share key not imported yet")
	// ErrBadKey is returned when the pasted share key isn't valid base64, or
	// doesn't decrypt to this request's share key.
	ErrBadKey = errors.New("sharekey: share key does not match this request")
	// ErrWrongPassword is returned when the requester's private key can't be
	// unlocked (wrong password, or the stored key was modified).
	ErrWrongPassword = errors.New("sharekey: wrong password")
	// ErrRateLimited is returned after too many import attempts.
	ErrRateLimited = errors.New("sharekey: too many import attempts")
	// ErrCorrupt is returned when stored material is structurally broken,
	// for example a missing algorithm copy.
	ErrCorrupt = errors.New("sharekey: stored share material is incomplete")
)
