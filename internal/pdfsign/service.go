package pdfsign

import (
	"context"
	"crypto/rsa"
	"io"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
	"github.com/eggboixd/infosec-assignment1-group3/internal/files"
	"github.com/eggboixd/infosec-assignment1-group3/internal/keypair"
)

// fileStore is what the service needs from internal/files. *files.Service
// satisfies it. Every call is scoped to the owner, so another user's file
// is files.ErrNotFound.
type fileStore interface {
	Get(ctx context.Context, ownerID, id bson.ObjectID, alg crypto.Algorithm) (*files.FileRecord, string, error)
	Download(ctx context.Context, rec *files.FileRecord, alg crypto.Algorithm, w io.Writer) error
	Upload(ctx context.Context, ownerID bson.ObjectID, kind files.Kind, filename string, r io.Reader) (*files.FileRecord, error)
	UploadSlot(ctx context.Context, ownerID bson.ObjectID, slot files.SlotInfo, filename string, r io.Reader) (*files.FileRecord, error)
}

// signingKeys is what the service needs from internal/keypair.
// *keypair.Service satisfies it.
type signingKeys interface {
	Unlock(ctx context.Context, userID bson.ObjectID, password string, p keypair.Purpose) (*rsa.PrivateKey, error)
	PublicKey(ctx context.Context, userID bson.ObjectID, p keypair.Purpose) (*rsa.PublicKey, error)
}

// The real services must keep satisfying these interfaces, so that
// cmd/server can pass them straight to NewService.
var (
	_ fileStore   = (*files.Service)(nil)
	_ signingKeys = (*keypair.Service)(nil)
)

// Service signs users' stored PDFs and verifies signed PDFs. It holds no
// private key between calls.
type Service struct {
	files fileStore
	keys  signingKeys
}

// NewService returns a Service. In cmd/server:
// pdfsign.NewService(filesSvc, keySvc).
func NewService(files fileStore, keys signingKeys) *Service {
	return &Service{files: files, keys: keys}
}

// SignFile signs the owner's stored PDF fileID with their signing key,
// unlocked with password, and stores the signed copy as a new file named
// "<name>-signed.pdf" in the same application slot as the original (or
// with no slot if the original has none). The original is kept.
//
// The PDF is decrypted, checked, signed and re-encrypted in memory; the
// signed copy goes through the normal upload pipeline, so it is stored
// encrypted with every algorithm. Existing signatures must all verify
// (otherwise ErrExistingSignatureInvalid); a valid signed PDF can be signed
// again, by the same or another user.
//
// Errors: files.ErrNotFound (no such file, or another user's), ErrNotPDF,
// ErrEncrypted, ErrUnsupportedPDF, ErrTooLarge, ErrTooManySignatures,
// ErrExistingSignatureInvalid, keypair.ErrUnlock (wrong password),
// keypair.ErrNoKeys, and a *RateLimitError (errors.Is ErrRateLimited).
func (s *Service) SignFile(ctx context.Context, signer Identity, fileID bson.ObjectID, password string) (*files.FileRecord, error) {
	return nil, errNotImplemented
}

// VerifyFile verifies every signature in the owner's stored PDF fileID.
// Another user's file is files.ErrNotFound. Problems with individual
// signatures are in the Report, not the error; the error is only for a file
// that can't be checked at all (ErrNotPDF, ErrEncrypted, ErrTooLarge, ...).
func (s *Service) VerifyFile(ctx context.Context, ownerID, fileID bson.ObjectID) (*Report, error) {
	return nil, errNotImplemented
}

// VerifyUpload verifies every signature in a PDF read from r, for example
// one uploaded on the verify page. Nothing is stored. Input over MaxSize is
// ErrTooLarge.
func (s *Service) VerifyUpload(ctx context.Context, r io.Reader) (*Report, error) {
	return nil, errNotImplemented
}
