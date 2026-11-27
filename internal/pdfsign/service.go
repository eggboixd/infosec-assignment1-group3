package pdfsign

import (
	"bytes"
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"path"
	"strings"
	"time"

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

const (
	// maxConcurrent bounds how many PDFs are held in memory at once (each up
	// to MaxSize, plus its signed copy and pdfcpu's parsed objects).
	maxConcurrent = 2
	// readAlg is the variant a stored PDF is decrypted from. Every variant
	// holds the same plaintext; AES is the one the file list uses too.
	readAlg      = crypto.AES
	mimePDF      = "application/pdf"
	signedSuffix = "-signed.pdf" // appended to the original name
)

// errSignedCopyInvalid means the signed copy failed our own end-to-end
// verification, so it was not stored. It indicates a bug, never user error.
var errSignedCopyInvalid = errors.New("pdfsign: signed copy failed verification")

// Service signs users' stored PDFs and verifies signed PDFs. It holds no
// private key between calls.
type Service struct {
	files   fileStore
	keys    signingKeys
	limiter *failureLimiter
	slots   chan struct{}
	now     func() time.Time
}

// NewService returns a Service. In cmd/server:
// pdfsign.NewService(filesSvc, keySvc).
func NewService(files fileStore, keys signingKeys) *Service {
	return &Service{
		files:   files,
		keys:    keys,
		limiter: newFailureLimiter(maxUnlockFailures, unlockWindow),
		slots:   make(chan struct{}, maxConcurrent),
		now:     time.Now,
	}
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
	if signer.UserID.IsZero() {
		return nil, errors.New("pdfsign: sign: empty signer ID")
	}
	// Checked first, so a blocked user can't make us decrypt files either.
	if blocked, retry := s.limiter.blocked(signer.UserID.Hex()); blocked {
		return nil, &RateLimitError{RetryAfter: retry}
	}

	// The signer is the owner: Get is scoped to signer.UserID, so another
	// user's file ID is ErrNotFound (no IDOR).
	rec, name, err := s.files.Get(ctx, signer.UserID, fileID, readAlg)
	if err != nil {
		return nil, err
	}
	if rec.MIMEType != mimePDF {
		return nil, ErrNotPDF
	}

	var stored *files.FileRecord
	err = s.withSlot(ctx, func() error {
		raw, err := s.load(ctx, rec)
		if err != nil {
			return err
		}

		// Don't add a signature to a document whose signatures don't hold:
		// the user would appear to vouch for a broken or forged document.
		before, err := verifyPDF(ctx, raw, s.keys)
		if err != nil {
			return err
		}
		for _, sig := range before.Signatures {
			if !sig.Valid {
				return ErrExistingSignatureInvalid
			}
		}
		if len(before.Signatures) >= maxSignatures {
			return ErrTooManySignatures
		}

		signed, err := s.sign(ctx, signer, password, raw)
		if err != nil {
			return err
		}

		// End-to-end self-check, through the same path any verifier uses:
		// the new signature must verify with the registered key and cover the
		// whole file. A failure here is our bug; nothing is stored.
		after, err := verifyPDF(ctx, signed, s.keys)
		if err != nil {
			return fmt.Errorf("%w: %v", errSignedCopyInvalid, err)
		}
		n := len(after.Signatures)
		if after.Status != StatusValid || n != len(before.Signatures)+1 ||
			after.Signatures[n-1].SignerID != signer.UserID || !after.Signatures[n-1].CoversWholeFile {
			return errSignedCopyInvalid
		}

		stored, err = s.store(ctx, signer.UserID, rec, signedName(name), signed)
		return err
	})
	if err != nil {
		return nil, err
	}
	slog.Info("pdfsign: signed file", "user_id", signer.UserID.Hex(), "file_id", fileID.Hex(), "signed_file_id", stored.ID.Hex())
	return stored, nil
}

// sign unlocks the signing key and signs raw. The key exists only for this
// call (D44): it is not stored anywhere, and its private values are
// overwritten (best effort, D13) before returning.
func (s *Service) sign(ctx context.Context, signer Identity, password string, raw []byte) ([]byte, error) {
	priv, err := s.keys.Unlock(ctx, signer.UserID, password, keypair.Signing)
	if errors.Is(err, keypair.ErrUnlock) {
		s.limiter.fail(signer.UserID.Hex())
		slog.Warn("pdfsign: wrong password for signing key", "user_id", signer.UserID.Hex())
	}
	if err != nil {
		return nil, err
	}
	defer wipeKey(priv)
	return signPDF(ctx, raw, priv, signer, s.now())
}

// VerifyFile verifies every signature in the owner's stored PDF fileID.
// Another user's file is files.ErrNotFound. Problems with individual
// signatures are in the Report, not the error; the error is only for a file
// that can't be checked at all (ErrNotPDF, ErrEncrypted, ErrTooLarge, ...).
func (s *Service) VerifyFile(ctx context.Context, ownerID, fileID bson.ObjectID) (*Report, error) {
	rec, _, err := s.files.Get(ctx, ownerID, fileID, readAlg)
	if err != nil {
		return nil, err
	}
	if rec.MIMEType != mimePDF {
		return nil, ErrNotPDF
	}
	var rep *Report
	err = s.withSlot(ctx, func() error {
		raw, err := s.load(ctx, rec)
		if err != nil {
			return err
		}
		rep, err = verifyPDF(ctx, raw, s.keys)
		return err
	})
	return rep, err
}

// VerifyUpload verifies every signature in a PDF read from r, for example
// one uploaded on the verify page. Nothing is stored. Input over MaxSize is
// ErrTooLarge.
func (s *Service) VerifyUpload(ctx context.Context, r io.Reader) (*Report, error) {
	var rep *Report
	err := s.withSlot(ctx, func() error {
		raw, err := io.ReadAll(io.LimitReader(r, MaxSize+1))
		if err != nil {
			return fmt.Errorf("pdfsign: read upload: %w", err)
		}
		if len(raw) > MaxSize {
			return ErrTooLarge
		}
		rep, err = verifyPDF(ctx, raw, s.keys)
		return err
	})
	return rep, err
}

// load decrypts rec into memory. files.Download checks the HMAC over the
// whole object before writing any plaintext (D9), so a tampered stored file
// is crypto.ErrAuthentication here. The plaintext never touches the disk.
func (s *Service) load(ctx context.Context, rec *files.FileRecord) ([]byte, error) {
	if rec.Size > MaxSize {
		return nil, ErrTooLarge
	}
	buf := bytes.NewBuffer(make([]byte, 0, rec.Size))
	if err := s.files.Download(ctx, rec, readAlg, &limitedWriter{w: buf, n: MaxSize}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// store saves the signed copy as a new file in the original's slot, or as
// a plain document if it has none (or a slot this version doesn't know).
func (s *Service) store(ctx context.Context, ownerID bson.ObjectID, orig *files.FileRecord, name string, signed []byte) (*files.FileRecord, error) {
	if orig.Slot != "" {
		if slot, err := files.ParseSlot(string(orig.Slot)); err == nil {
			return s.files.UploadSlot(ctx, ownerID, slot, name, bytes.NewReader(signed))
		}
	}
	return s.files.Upload(ctx, ownerID, files.KindDocument, name, bytes.NewReader(signed))
}

// signedName turns "cv.pdf" into "cv-signed.pdf". The name was cleaned
// when it was uploaded; files cleans it again on upload.
func signedName(name string) string {
	base := name
	if strings.EqualFold(path.Ext(base), ".pdf") {
		base = base[:len(base)-len(".pdf")]
	}
	if base == "" {
		base = "document"
	}
	return base + signedSuffix
}

// withSlot runs fn once one of maxConcurrent slots is free, or gives up
// when ctx is done.
func (s *Service) withSlot(ctx context.Context, fn func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case s.slots <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-s.slots }()
	return fn()
}

// wipeKey sets the private values of priv to zero, so this key value can't
// be used again by mistake. It is best effort (D13, D44): big.Int doesn't
// promise to overwrite memory it has released, and crypto/rsa keeps its own
// internal copy of the key, which we can't reach.
func wipeKey(priv *rsa.PrivateKey) {
	if priv == nil {
		return
	}
	secret := append([]*big.Int{priv.D, priv.Precomputed.Dp, priv.Precomputed.Dq, priv.Precomputed.Qinv}, priv.Primes...)
	for _, b := range secret {
		if b != nil {
			b.SetInt64(0)
		}
	}
}

// limitedWriter fails once more than n bytes are written, so a stored
// object larger than its record claims can't exhaust memory.
type limitedWriter struct {
	w io.Writer
	n int64
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > l.n {
		return 0, ErrTooLarge
	}
	n, err := l.w.Write(p)
	l.n -= int64(n)
	return n, err
}
