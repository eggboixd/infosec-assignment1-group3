// Package pdfsign signs PDFs with a user's signing key and verifies the
// signatures embedded in them (Assignment 3).
//
// The signature is embedded in the PDF itself as an incremental update: a
// signature dictionary whose /ByteRange covers every byte of the file except
// the /Contents hole that holds the signature. The signing and verification
// logic is our own (EMSA-PKCS1-v1_5 with SHA-256 and the RSA arithmetic in
// math/big); libraries are only used for key generation (internal/keypair),
// hashing, randomness and reading the PDF structure (pdfcpu).
//
// How the UI calls it: docs/pdfsign.md. Why it works this way:
// docs/decisions.md, from D45.
//
// This package must not import Gin.
package pdfsign

import (
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// MaxSize is the largest PDF this package signs or verifies, in bytes. It
// equals the document limit of internal/files (D33), so every stored PDF
// fits. The PDF is held in memory while it is signed or verified (never
// written to disk), and this bounds that memory.
const MaxSize = 50 << 20

// Status is the verdict on a whole document.
type Status string

const (
	// StatusValid: every signature verified with its signer's registered key,
	// and the newest signature covers the whole file.
	StatusValid Status = "valid"
	// StatusModified: every signature verified, but bytes were added after
	// the newest signature (Report.AppendedBytes). Those bytes can change
	// what a PDF reader shows, and no signature covers them.
	StatusModified Status = "modified"
	// StatusInvalid: at least one signature failed or could not be checked.
	// SignatureResult.Problem says why for each one.
	StatusInvalid Status = "invalid"
	// StatusUnsigned: the PDF has no signature fields.
	StatusUnsigned Status = "unsigned"
)

// Format identifies how a signature is encoded in the PDF.
type Format string

const (
	// FormatUnknown is a signature we cannot parse, for example one made
	// by another application with a /SubFilter we don't support.
	FormatUnknown Format = ""
	// FormatInApp is this app's own format: /Filter /SecureStore with the
	// raw RSA signature in /Contents and the signer's user ID and key
	// fingerprint inside the signed bytes.
	FormatInApp Format = "securestore"
	// FormatCMS is /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached:
	// a CMS SignedData with a self-signed certificate, which Adobe Reader and
	// Foxit can also check. Until that format is implemented, such signatures
	// are reported with ErrUnsupportedFormat.
	FormatCMS Format = "adbe.pkcs7.detached"
)

// Identity is the signer as the PDF records it.
type Identity struct {
	UserID   bson.ObjectID
	Username string
}

// SignatureResult is the verdict on one signature.
type SignatureResult struct {
	// Index is the position of this signature, 0 for the oldest.
	Index  int
	Format Format
	// SignerID is the user the signature claims to come from. It is zero if
	// the signature names no signer we can read.
	SignerID bson.ObjectID
	// SignerName is the username written in the PDF when it was signed. It
	// is only a label: trust comes from KeyMatches and Valid.
	SignerName string
	// Fingerprint is the SHA-256 fingerprint of the signing key recorded in
	// the PDF, formatted by keypair.FormatFingerprint. Empty if unreadable.
	Fingerprint string
	// KeyMatches reports whether Fingerprint is the signer's registered
	// signing key in this app.
	KeyMatches bool
	// SignedAt is the signing time written by the signer (/M). It is the
	// signer's claim, not a trusted timestamp.
	SignedAt time.Time
	// ByteRange is the signed part of the file: bytes [0, ByteRange[1]) and
	// [ByteRange[2], ByteRange[2]+ByteRange[3]).
	ByteRange [4]int64
	// RevisionEnd is where the signed revision ends:
	// ByteRange[2] + ByteRange[3].
	RevisionEnd int64
	// CoversWholeFile reports whether RevisionEnd is the end of the file.
	CoversWholeFile bool
	// CoveredByLater reports whether a later valid signature covers this
	// signature's whole revision (the document was signed again).
	CoveredByLater bool
	// Valid reports whether the signature verified with the signer's
	// registered key over exactly its ByteRange.
	Valid bool
	// Problem is nil when Valid, and otherwise one of ErrBadSignature,
	// ErrByteRange, ErrMalformedSignature, ErrUnsupportedFormat,
	// ErrUnknownSigner or ErrKeyMismatch (compare with errors.Is).
	Problem error
}

// Report is the verdict on a whole document.
type Report struct {
	Status Status
	// Signatures are in file order, oldest first.
	Signatures []SignatureResult
	// FileSize is the size of the verified PDF in bytes.
	FileSize int64
	// AppendedBytes is how many bytes follow the newest signature's
	// revision. It is 0 when the newest signature covers the whole file and
	// when the PDF is unsigned.
	AppendedBytes int64
}
