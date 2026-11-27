package pdfsign

import (
	"errors"
	"fmt"
	"time"
)

// Errors returned by Service methods for the document as a whole. Compare
// them with errors.Is. Their texts never contain key material, passwords or
// file content, so they are safe to log next to a user or file ID.
var (
	// ErrNotPDF means the input is not a PDF we can read: empty, another
	// file type, or damaged beyond parsing.
	ErrNotPDF = errors.New("pdfsign: not a readable PDF")
	// ErrEncrypted means the PDF is password-protected. We don't sign or
	// verify encrypted PDFs.
	ErrEncrypted = errors.New("pdfsign: PDF is encrypted")
	// ErrUnsupportedPDF means the PDF can be read but not safely signed, for
	// example because it has no pages or its cross-reference data is broken.
	ErrUnsupportedPDF = errors.New("pdfsign: PDF structure not supported")
	// ErrTooLarge means the PDF, or its signed copy, exceeds MaxSize.
	ErrTooLarge = errors.New("pdfsign: PDF too large")
	// ErrExistingSignatureInvalid means SignFile refused to add a signature
	// to a PDF whose existing signatures do not all verify.
	ErrExistingSignatureInvalid = errors.New("pdfsign: PDF has an invalid signature")
	// ErrTooManySignatures means the PDF already has the maximum number of
	// signatures this package handles.
	ErrTooManySignatures = errors.New("pdfsign: too many signatures")
	// ErrRateLimited means the user made too many signing attempts (each one
	// is a password guess). The returned error is a *RateLimitError, which
	// says how long to wait.
	ErrRateLimited = errors.New("pdfsign: too many signing attempts")
)

// Problems with one signature, reported in SignatureResult.Problem. They do
// not fail the call: the Report describes them.
var (
	// ErrBadSignature: the RSA signature does not match the signed bytes.
	// The document was changed after signing, or the signature is forged.
	ErrBadSignature = errors.New("pdfsign: signature does not match the document")
	// ErrByteRange: /ByteRange is malformed or does not exclude exactly the
	// /Contents hole, so the signature can't be trusted to cover the file.
	ErrByteRange = errors.New("pdfsign: signed byte range is not valid")
	// ErrMalformedSignature: the signature dictionary or its /Contents
	// can't be parsed.
	ErrMalformedSignature = errors.New("pdfsign: signature is malformed")
	// ErrUnsupportedFormat: the signature was made in a format this app
	// doesn't verify (for example by another program).
	ErrUnsupportedFormat = errors.New("pdfsign: signature format not supported")
	// ErrUnknownSigner: the signature names no user of this app, or the
	// user has no signing key.
	ErrUnknownSigner = errors.New("pdfsign: signer is not known")
	// ErrKeyMismatch: the key fingerprint in the PDF is not the signer's
	// registered signing key.
	ErrKeyMismatch = errors.New("pdfsign: signing key is not the signer's registered key")
)

// RateLimitError is returned (wrapped) by SignFile when the user has made
// too many attempts. errors.Is(err, ErrRateLimited) is true for it.
type RateLimitError struct {
	// RetryAfter is how long until the next attempt is allowed.
	RetryAfter time.Duration
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("%v; retry in %s", ErrRateLimited, e.RetryAfter.Round(time.Second))
}

// Is makes errors.Is(err, ErrRateLimited) match.
func (e *RateLimitError) Is(target error) bool { return target == ErrRateLimited }
