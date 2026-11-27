package keypair

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// maxConcurrentKDF bounds how many Argon2id runs (64 MiB each) and RSA key
// generations this service does at once. auth has its own 4 slots, so the
// worst case for both is 6 × 64 MiB.
const maxConcurrentKDF = 2

// keyStore is the persistence the service needs. *Store satisfies it.
type keyStore interface {
	Insert(ctx context.Context, d *Document) error
	FindByUserID(ctx context.Context, userID bson.ObjectID) (*Document, error)
	ReplaceWrapped(ctx context.Context, userID bson.ObjectID, oldSalt []byte, kdf KDFParams, encWrapped, signWrapped []byte) error
}

// Service creates, stores and unlocks users' key pairs. It holds no
// decrypted private key between calls.
type Service struct {
	store  keyStore
	macKey []byte
	slots  chan struct{}
	genKey func() (*rsa.PrivateKey, error)
	now    func() time.Time
}

// NewService returns a Service. publicMACKey must be the 32-byte
// crypto.DeriveKey(MASTER_KEY, "keypair-public-mac").
func NewService(store keyStore, publicMACKey []byte) (*Service, error) {
	if len(publicMACKey) != PublicMACKeySize {
		return nil, fmt.Errorf("keypair: public MAC key must be %d bytes, got %d", PublicMACKeySize, len(publicMACKey))
	}
	return &Service{
		store:  store,
		macKey: append([]byte(nil), publicMACKey...),
		slots:  make(chan struct{}, maxConcurrentKDF),
		genKey: generateKey,
		now:    time.Now,
	}, nil
}

// generateKey makes one RSA-3072 key with e = 65537 from crypto/rand.
// Generating keys is the one place the assignment allows a library.
func generateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, KeyBits)
}

// EnsureKeys creates the user's two key pairs if they have none, with the
// private keys encrypted under a key derived from password. If the user
// already has key pairs it does nothing (it does not check the password),
// so it is safe to call on every login.
//
// It is called right after a successful register or login, the only
// moments the server has the plaintext password (D43). If two calls race,
// both generate keys but only the first insert is kept, so the user still
// ends up with exactly one set.
func (s *Service) EnsureKeys(ctx context.Context, userID bson.ObjectID, password string) error {
	if userID.IsZero() {
		return errors.New("keypair: ensure keys: empty user ID")
	}
	if password == "" {
		return errors.New("keypair: ensure keys: empty password")
	}
	switch _, err := s.store.FindByUserID(ctx, userID); {
	case err == nil:
		return nil
	case !errors.Is(err, ErrNoKeys):
		return err
	}

	var doc *Document
	err := s.withSlot(ctx, func() error {
		var err error
		doc, err = s.newDocument(userID, password)
		return err
	})
	if err != nil {
		return err
	}
	if err := s.store.Insert(ctx, doc); err != nil && !errors.Is(err, errExists) {
		return err
	}
	return nil
}

// newDocument generates both key pairs and wraps them under a fresh KEK.
func (s *Service) newDocument(userID bson.ObjectID, password string) (*Document, error) {
	kdf, err := newKDFParams()
	if err != nil {
		return nil, err
	}
	kek, err := deriveKEK(password, kdf)
	if err != nil {
		return nil, err
	}
	defer clear(kek)

	now := s.now()
	doc := &Document{UserID: userID, Version: documentVersion, KDF: kdf, CreatedAt: now.UTC().Truncate(time.Millisecond)}
	for _, p := range purposes {
		// One GenerateKey call per purpose: the two pairs share nothing (D39).
		priv, err := s.genKey()
		if err != nil {
			return nil, fmt.Errorf("keypair: generate %s key: %w", p, err)
		}
		sp, err := newStoredPair(kek, s.macKey, userID, p, priv, now)
		if err != nil {
			return nil, err
		}
		dst, _ := doc.pair(p) // p comes from purposes, so it is valid.
		*dst = sp
	}
	return doc, nil
}

// Unlock decrypts the user's private key for purpose p with password.
//
// It returns ErrUnlock for a wrong password (or a modified encrypted key),
// ErrNoKeys if the user has none, and ErrCorrupt if the stored public key
// or parameters fail their checks. The caller must use the key for the one
// action it was unlocked for and then drop it: never store it in a session,
// cookie, log or the database (D44).
func (s *Service) Unlock(ctx context.Context, userID bson.ObjectID, password string, p Purpose) (*rsa.PrivateKey, error) {
	doc, sp, pub, err := s.load(ctx, userID, p)
	if err != nil {
		return nil, err
	}
	// Checked before Argon2id runs, so planted parameters can't cost memory.
	if err := doc.KDF.validate(); err != nil {
		return nil, err
	}

	var pkcs8 []byte
	err = s.withSlot(ctx, func() error {
		kek, err := deriveKEK(password, doc.KDF)
		if err != nil {
			return err
		}
		defer clear(kek)
		pkcs8, err = unwrapPrivate(kek, sp.WrappedPrivate, wrapAAD(userID, p, sp.Fingerprint))
		return err
	})
	if err != nil {
		return nil, err
	}
	defer clear(pkcs8)

	key, err := x509.ParsePKCS8PrivateKey(pkcs8)
	if err != nil {
		return nil, fmt.Errorf("%w: %s private key: %v", ErrCorrupt, p, err)
	}
	priv, ok := key.(*rsa.PrivateKey)
	// The AAD already binds the private key to this fingerprint; comparing
	// the keys as well guarantees the caller gets the pair everyone else sees.
	if !ok || priv.N.BitLen() != KeyBits || !priv.PublicKey.Equal(pub) {
		return nil, fmt.Errorf("%w: %s private key does not match its public key", ErrCorrupt, p)
	}
	return priv, nil
}

// PublicKey returns the user's public key for purpose p, after checking its
// MAC. It needs no password: anyone may encrypt to or verify with a public
// key. ErrNoKeys means the user has no keys yet.
func (s *Service) PublicKey(ctx context.Context, userID bson.ObjectID, p Purpose) (*rsa.PublicKey, error) {
	_, _, pub, err := s.load(ctx, userID, p)
	return pub, err
}

// Info describes both of the user's key pairs (encryption first), for
// display. ErrNoKeys means the user has none yet.
func (s *Service) Info(ctx context.Context, userID bson.ObjectID) ([]Info, error) {
	doc, err := s.store.FindByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	infos := make([]Info, 0, len(purposes))
	for _, p := range purposes {
		sp, _ := doc.pair(p)
		if _, err := verifyPublic(s.macKey, userID, p, sp); err != nil {
			return nil, err
		}
		infos = append(infos, Info{
			Purpose:     p,
			Bits:        KeyBits,
			Fingerprint: FormatFingerprint(sp.Fingerprint),
			CreatedAt:   sp.CreatedAt,
		})
	}
	return infos, nil
}

// Rewrap re-encrypts both private keys under a KEK derived from
// newPassword, with a fresh salt. A change-password flow must call it
// before it stores the new password hash; otherwise the keys stay locked
// under the old password, which the user no longer knows. The key pairs
// themselves (and so every fingerprint and existing signature) are
// unchanged. A wrong oldPassword returns ErrUnlock and writes nothing.
func (s *Service) Rewrap(ctx context.Context, userID bson.ObjectID, oldPassword, newPassword string) error {
	if newPassword == "" {
		return errors.New("keypair: rewrap: empty new password")
	}
	doc, err := s.store.FindByUserID(ctx, userID)
	if err != nil {
		return err
	}
	for _, p := range purposes {
		sp, _ := doc.pair(p)
		if _, err := verifyPublic(s.macKey, userID, p, sp); err != nil {
			return err
		}
	}
	if err := doc.KDF.validate(); err != nil {
		return err
	}

	newKDF, err := newKDFParams()
	if err != nil {
		return err
	}
	rewrapped := make(map[Purpose][]byte, len(purposes))
	err = s.withSlot(ctx, func() error {
		oldKEK, err := deriveKEK(oldPassword, doc.KDF)
		if err != nil {
			return err
		}
		defer clear(oldKEK)
		newKEK, err := deriveKEK(newPassword, newKDF)
		if err != nil {
			return err
		}
		defer clear(newKEK)

		for _, p := range purposes {
			sp, _ := doc.pair(p)
			// Same AAD before and after: only the KEK changes.
			aad := wrapAAD(userID, p, sp.Fingerprint)
			pkcs8, err := unwrapPrivate(oldKEK, sp.WrappedPrivate, aad)
			if err != nil {
				return err
			}
			w, err := wrapPrivate(newKEK, pkcs8, aad)
			clear(pkcs8)
			if err != nil {
				return err
			}
			rewrapped[p] = w
		}
		return nil
	})
	if err != nil {
		return err
	}
	return s.store.ReplaceWrapped(ctx, userID, doc.KDF.Salt, newKDF, rewrapped[Encryption], rewrapped[Signing])
}

// load fetches the user's document and checks the public half of pair p.
func (s *Service) load(ctx context.Context, userID bson.ObjectID, p Purpose) (*Document, *StoredPair, *rsa.PublicKey, error) {
	if _, err := ParsePurpose(string(p)); err != nil {
		return nil, nil, nil, err
	}
	doc, err := s.store.FindByUserID(ctx, userID)
	if err != nil {
		return nil, nil, nil, err
	}
	sp, err := doc.pair(p)
	if err != nil {
		return nil, nil, nil, err
	}
	pub, err := verifyPublic(s.macKey, userID, p, sp)
	if err != nil {
		return nil, nil, nil, err
	}
	return doc, sp, pub, nil
}

// withSlot runs fn once a slot is free, or gives up when ctx is done (for
// example, the client disconnected while queued).
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
