package sharekey

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"
	"unicode"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
	"github.com/eggboixd/infosec-assignment1-group3/internal/files"
	"github.com/eggboixd/infosec-assignment1-group3/internal/keypair"
	"github.com/eggboixd/infosec-assignment1-group3/internal/profile"
	"github.com/eggboixd/infosec-assignment1-group3/internal/sharing"
)

// Import attempts allowed per requester per window. Each attempt is a
// password guess against the requester's private key (docs/keypairs.md).
const (
	importLimit  = 10
	importWindow = 15 * time.Minute
)

// MaxEncodedKey bounds the pasted share key. A 3072-bit RSA ciphertext is
// 384 bytes, 512 characters of base64; the rest allows line breaks.
const MaxEncodedKey = 1024

// materialStore is the storage the service needs. *Store implements it.
type materialStore interface {
	Insert(ctx context.Context, m *Material) error
	Exists(ctx context.Context, requestID bson.ObjectID) (bool, error)
	Find(ctx context.Context, requestID bson.ObjectID, actor string, actorID bson.ObjectID) (*Material, error)
	SetImported(ctx context.Context, requestID, requesterID bson.ObjectID, sealed []byte, at time.Time) error
	Delete(ctx context.Context, requestID bson.ObjectID) error
}

// keyService gives users' RSA keys. keypair.Service implements it.
type keyService interface {
	PublicKey(ctx context.Context, userID bson.ObjectID, p keypair.Purpose) (*rsa.PublicKey, error)
	Unlock(ctx context.Context, userID bson.ObjectID, password string, p keypair.Purpose) (*rsa.PrivateKey, error)
}

// profileSource reads stored profiles. profile.Store implements it.
type profileSource interface {
	FindByUserID(ctx context.Context, userID bson.ObjectID) (*profile.Profile, error)
}

// fileSource lists file records. files.Store implements it.
type fileSource interface {
	ListByOwner(ctx context.Context, ownerID bson.ObjectID) ([]files.FileRecord, error)
}

// objectSource reads ciphertext objects. files.ObjectStore implements it.
type objectSource interface {
	Get(ctx context.Context, key string) (io.ReadSeekCloser, error)
}

// Service implements sharing.Granter and the requester's import and open.
type Service struct {
	store    materialStore
	keys     keyService
	profiles profileSource
	files    fileSource
	objects  objectSource
	// master unwraps the owner's DEKs at grant time.
	master []byte
	// importKey wraps share keys after import: DeriveKey(master,
	// "share-key-import").
	importKey []byte
	limiter   *rateLimiter
	now       func() time.Time
}

var _ sharing.Granter = (*Service)(nil)

// NewService returns a Service. master is the MASTER_KEY.
func NewService(store materialStore, keys keyService, profiles profileSource, fileRecs fileSource, objects objectSource, master []byte) (*Service, error) {
	if len(master) != crypto.MasterKeySize {
		return nil, fmt.Errorf("sharekey: master key must be %d bytes", crypto.MasterKeySize)
	}
	importKey, err := crypto.DeriveKey(master, importKeyInfo)
	if err != nil {
		return nil, err
	}
	return &Service{
		store:     store,
		keys:      keys,
		profiles:  profiles,
		files:     fileRecs,
		objects:   objects,
		master:    bytes.Clone(master),
		importKey: importKey,
		limiter:   newRateLimiter(importLimit, importWindow),
		now:       time.Now,
	}, nil
}

// Grant implements sharing.Granter. It is create-if-absent per request ID.
func (s *Service) Grant(ctx context.Context, g sharing.Grant) error {
	exists, err := s.store.Exists(ctx, g.RequestID)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}

	pub, err := s.keys.PublicKey(ctx, g.RequesterID, keypair.Encryption)
	if err != nil {
		return fmt.Errorf("sharekey: requester key: %w", err)
	}
	fp, err := fingerprint(pub)
	if err != nil {
		return err
	}

	// 1. A fresh random share key for this request only.
	shareKey := make([]byte, ShareKeySize)
	if _, err := rand.Read(shareKey); err != nil {
		return fmt.Errorf("sharekey: random: %w", err)
	}
	defer clear(shareKey)

	// 2. Re-wrap the owner's DEKs and MAC keys under it.
	m := &Material{
		RequestID:            g.RequestID,
		OwnerID:              g.OwnerID,
		RequesterID:          g.RequesterID,
		RequesterFingerprint: fp,
		KeyCheck:             keyCheck(shareKey, g.RequestID),
		CreatedAt:            s.now().UTC(),
	}
	if m.Profile, err = s.shareProfile(ctx, shareKey, g.OwnerID); err != nil {
		return err
	}
	if m.Files, err = s.shareFiles(ctx, shareKey, g.OwnerID); err != nil {
		return err
	}

	// 3. Encrypt it to the requester's public encryption key.
	m.EncryptedKey, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, shareKey, oaepLabel(g.RequestID))
	if err != nil {
		return fmt.Errorf("sharekey: encrypt share key: %w", err)
	}

	// 4. Store. A concurrent Grant for the same request may have won: its
	// key stays, ours is dropped.
	if err := s.store.Insert(ctx, m); err != nil && !errors.Is(err, errExists) {
		return err
	}
	slog.Info("sharekey: granted", "request_id", g.RequestID.Hex(), "files", len(m.Files), "profile", m.Profile != nil)
	return nil
}

// Destroy implements sharing.Granter.
func (s *Service) Destroy(ctx context.Context, requestID bson.ObjectID) error {
	return s.store.Delete(ctx, requestID)
}

// shareProfile copies the owner's profile with its keys re-wrapped, or
// returns nil if the owner has none.
func (s *Service) shareProfile(ctx context.Context, shareKey []byte, ownerID bson.ObjectID) (*sharedProfile, error) {
	p, err := s.profiles.FindByUserID(ctx, ownerID)
	if errors.Is(err, profile.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	sp := &sharedProfile{}
	for _, f := range profileFields(p, sp, nil) {
		if *f.shared, err = s.shareSet(shareKey, *f.stored); err != nil {
			return nil, fmt.Errorf("sharekey: profile: %w", err)
		}
	}
	return sp, nil
}

// shareFiles re-wraps the keys of every file the owner has now.
func (s *Service) shareFiles(ctx context.Context, shareKey []byte, ownerID bson.ObjectID) ([]sharedFile, error) {
	recs, err := s.files.ListByOwner(ctx, ownerID)
	if err != nil {
		return nil, err
	}
	out := make([]sharedFile, 0, len(recs))
	for _, rec := range recs {
		name, err := s.shareSet(shareKey, rec.FileName)
		if err != nil {
			return nil, fmt.Errorf("sharekey: file %s name: %w", rec.ID.Hex(), err)
		}
		variants := make(map[crypto.Algorithm]sharedVariant, len(rec.Variants))
		for alg, v := range rec.Variants {
			k, err := rewrap(s.master, shareKey, v.Meta)
			if err != nil {
				return nil, fmt.Errorf("sharekey: file %s %s: %w", rec.ID.Hex(), alg, err)
			}
			variants[alg] = sharedVariant{ObjectKey: v.ObjectKey, Meta: v.Meta, Keys: k}
		}
		out = append(out, sharedFile{
			FileID: rec.ID, Kind: rec.Kind, Slot: rec.Slot, MIMEType: rec.MIMEType,
			Size: rec.Size, CreatedAt: rec.CreatedAt, FileName: name, Variants: variants,
		})
	}
	return out, nil
}

// shareSet copies a SealedSet with its keys re-wrapped.
func (s *Service) shareSet(shareKey []byte, set crypto.SealedSet) (sharedSet, error) {
	out := make(sharedSet, len(set))
	for alg, sealed := range set {
		k, err := rewrap(s.master, shareKey, sealed.Meta)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", alg, err)
		}
		out[alg] = sharedSealed{Sealed: sealed, Keys: k}
	}
	return out, nil
}

// EncryptedKey returns the encrypted share key of requestID for its owner.
func (s *Service) EncryptedKey(ctx context.Context, ownerID, requestID bson.ObjectID) (*KeyView, error) {
	m, err := s.store.Find(ctx, requestID, actorOwner, ownerID)
	if err != nil {
		return nil, err
	}
	return &KeyView{
		RequestID:   m.RequestID,
		Encoded:     base64.StdEncoding.EncodeToString(m.EncryptedKey),
		Fingerprint: m.RequesterFingerprint,
		Imported:    m.Imported(),
		CreatedAt:   m.CreatedAt,
	}, nil
}

// Status reports whether the requester of an active request has imported its
// share key. req must come from sharing.Service.Active in this HTTP request.
func (s *Service) Status(ctx context.Context, req *sharing.Request) (imported bool, err error) {
	m, err := s.store.Find(ctx, req.ID, actorRequester, req.RequesterID)
	if err != nil {
		return false, err
	}
	return m.Imported(), nil
}

// Import decrypts the pasted share key with the requester's private key and,
// if it is this request's key, stores it wrapped under the import subkey.
// req must come from sharing.Service.Active in this HTTP request.
func (s *Service) Import(ctx context.Context, req *sharing.Request, password, encoded string) error {
	if !s.limiter.allow(req.RequesterID.Hex()) {
		return ErrRateLimited
	}
	m, err := s.store.Find(ctx, req.ID, actorRequester, req.RequesterID)
	if err != nil {
		return err
	}
	ct, err := decodeKey(encoded)
	if err != nil {
		return ErrBadKey
	}

	priv, err := s.keys.Unlock(ctx, req.RequesterID, password, keypair.Encryption)
	if errors.Is(err, keypair.ErrUnlock) {
		return ErrWrongPassword
	}
	if err != nil {
		return fmt.Errorf("sharekey: unlock: %w", err)
	}
	shareKey, err := rsa.DecryptOAEP(sha256.New(), nil, priv, ct, oaepLabel(req.ID))
	if err != nil {
		return ErrBadKey
	}
	defer clear(shareKey)
	if len(shareKey) != ShareKeySize || !hmac.Equal(keyCheck(shareKey, req.ID), m.KeyCheck) {
		return ErrBadKey
	}

	sealed, err := sealShareKey(s.importKey, shareKey, req.ID)
	if err != nil {
		return err
	}
	if err := s.store.SetImported(ctx, req.ID, req.RequesterID, sealed, s.now().UTC()); err != nil {
		return err
	}
	slog.Info("sharekey: imported", "request_id", req.ID.Hex(), "requester_id", req.RequesterID.Hex())
	return nil
}

// decodeKey strips whitespace (WhatsApp may break the line) and decodes
// standard base64.
func decodeKey(encoded string) ([]byte, error) {
	if len(encoded) > MaxEncodedKey {
		return nil, ErrBadKey
	}
	clean := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, encoded)
	return base64.StdEncoding.DecodeString(clean)
}

// Shared is the owner's data as the requester sees it.
type Shared struct {
	// Profile is nil when the owner had no profile at approval time.
	Profile *profile.PrivateData
	Files   []FileView
}

// Open decrypts the shared profile and file names with alg's copies.
// req must come from sharing.Service.Active in this HTTP request.
func (s *Service) Open(ctx context.Context, req *sharing.Request, alg crypto.Algorithm) (*Shared, error) {
	if !alg.Valid() {
		return nil, fmt.Errorf("%w: %q", crypto.ErrUnknownAlgorithm, alg)
	}
	m, shareKey, err := s.unlocked(ctx, req)
	if err != nil {
		return nil, err
	}
	defer clear(shareKey)

	out := &Shared{}
	if m.Profile != nil {
		var d profile.PrivateData
		for _, f := range profileFields(nil, m.Profile, &d) {
			pt, err := openSealed(shareKey, *f.shared, alg)
			if err != nil {
				// Fail closed: never show the fields that did verify.
				return nil, err
			}
			*f.plain = string(pt)
		}
		out.Profile = &d
	}
	for _, f := range m.Files {
		v := FileView{ID: f.FileID, Kind: f.Kind, Size: f.Size, NameOK: true}
		if si, err := files.ParseSlot(string(f.Slot)); err == nil {
			v.SlotLabel = si.Label
		}
		name, err := openSealed(shareKey, f.FileName, alg)
		if err != nil {
			slog.Warn("sharekey: file name failed its check", "request_id", req.ID.Hex(), "file_id", f.FileID.Hex(), "alg", alg, "error", err)
			v.Name, v.NameOK = "(name failed its integrity check)", false
		} else {
			v.Name = string(name)
		}
		out.Files = append(out.Files, v)
	}
	return out, nil
}

// Download verifies and decrypts the alg copy of a shared file. start is
// called once the file is found, before any plaintext, and returns where the
// plaintext goes. The HMAC is checked over the whole object before the first
// byte is written (crypto.DecryptWithKeys), so on crypto.ErrAuthentication
// nothing was written. req must come from sharing.Service.Active in this HTTP
// request.
func (s *Service) Download(ctx context.Context, req *sharing.Request, fileID bson.ObjectID, alg crypto.Algorithm, start func(DownloadHeader) io.Writer) error {
	if !alg.Valid() {
		return fmt.Errorf("%w: %q", crypto.ErrUnknownAlgorithm, alg)
	}
	m, shareKey, err := s.unlocked(ctx, req)
	if err != nil {
		return err
	}
	defer clear(shareKey)

	var f *sharedFile
	for i := range m.Files {
		if m.Files[i].FileID == fileID {
			f = &m.Files[i]
			break
		}
	}
	if f == nil {
		return ErrNotFound
	}
	v, ok := f.Variants[alg]
	if !ok {
		return fmt.Errorf("%w: no %s copy of file %s", ErrCorrupt, alg, fileID.Hex())
	}
	name, err := openSealed(shareKey, f.FileName, alg)
	if err != nil {
		return err
	}
	dek, macKey, err := unwrapShared(shareKey, v.Keys)
	if err != nil {
		return err
	}
	defer clear(dek)
	defer clear(macKey)

	obj, err := s.objects.Get(ctx, v.ObjectKey)
	if err != nil {
		return err
	}
	defer obj.Close()
	w := start(DownloadHeader{Name: string(name), MIMEType: f.MIMEType, Size: f.Size})
	return crypto.DecryptWithKeys(ctx, alg, v.Meta, dek, macKey, w, obj)
}

// unlocked loads the requester's material and its imported share key. The
// caller clears the key.
func (s *Service) unlocked(ctx context.Context, req *sharing.Request) (*Material, []byte, error) {
	m, err := s.store.Find(ctx, req.ID, actorRequester, req.RequesterID)
	if err != nil {
		return nil, nil, err
	}
	if !m.Imported() {
		return nil, nil, ErrNotImported
	}
	shareKey, err := openShareKey(s.importKey, m.ImportedKey, req.ID)
	if err != nil {
		return nil, nil, err
	}
	return m, shareKey, nil
}

// openSealed verifies and decrypts the alg copy of a shared field.
func openSealed(shareKey []byte, set sharedSet, alg crypto.Algorithm) ([]byte, error) {
	sh, ok := set[alg]
	if !ok {
		return nil, fmt.Errorf("%w: no %s copy", ErrCorrupt, alg)
	}
	dek, macKey, err := unwrapShared(shareKey, sh.Keys)
	if err != nil {
		return nil, err
	}
	defer clear(dek)
	defer clear(macKey)
	var pt bytes.Buffer
	err = crypto.DecryptWithKeys(context.Background(), alg, sh.Sealed.Meta, dek, macKey, &pt, bytes.NewReader(sh.Sealed.Ciphertext))
	if err != nil {
		return nil, err
	}
	return pt.Bytes(), nil
}

// profileField ties a stored field, its shared copy and its plaintext.
type profileField struct {
	stored *crypto.SealedSet
	shared *sharedSet
	plain  *string
}

// profileFields lists the six profile fields. Any of the three arguments may
// be nil; its pointers then point into a throwaway value.
func profileFields(p *profile.Profile, sp *sharedProfile, d *profile.PrivateData) []profileField {
	if p == nil {
		p = &profile.Profile{}
	}
	if sp == nil {
		sp = &sharedProfile{}
	}
	if d == nil {
		d = &profile.PrivateData{}
	}
	return []profileField{
		{&p.FullName, &sp.FullName, &d.FullName},
		{&p.NIK, &sp.NIK, &d.NIK},
		{&p.DateOfBirth, &sp.DateOfBirth, &d.DateOfBirth},
		{&p.Address, &sp.Address, &d.Address},
		{&p.Phone, &sp.Phone, &d.Phone},
		{&p.Email, &sp.Email, &d.Email},
	}
}

// fingerprint formats SHA-256 of pub's PKIX DER, the same way keypair does.
func fingerprint(pub *rsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("sharekey: marshal public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return keypair.FormatFingerprint(sum[:]), nil
}
