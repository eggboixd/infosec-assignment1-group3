package sharekey

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
	"github.com/eggboixd/infosec-assignment1-group3/internal/sharing"
)

var ctx = context.Background()

// download runs Service.Download into a buffer.
func download(e *env, req *sharing.Request, fileID bson.ObjectID, alg crypto.Algorithm) (DownloadHeader, []byte, error) {
	var hdr DownloadHeader
	var out bytes.Buffer
	err := e.svc.Download(ctx, req, fileID, alg, func(h DownloadHeader) io.Writer {
		hdr = h
		return &out
	})
	return hdr, out.Bytes(), err
}

// The whole A2 flow: approve, send the key, import it, open everything with
// every algorithm.
func TestGrantImportOpen(t *testing.T) {
	e := newEnv(t)
	req := e.grant(t, e.alice)

	if _, err := e.svc.Open(ctx, req, crypto.AES); !errors.Is(err, ErrNotImported) {
		t.Fatalf("Open before import: err = %v, want ErrNotImported", err)
	}
	// WhatsApp may wrap the long line: whitespace must not matter.
	key := e.sentKey(t, req)
	wrapped := key[:100] + "\n" + key[100:300] + "  \r\n" + key[300:]
	if err := e.svc.Import(ctx, req, e.alice.password, wrapped); err != nil {
		t.Fatalf("Import: %v", err)
	}
	if imported, err := e.svc.Status(ctx, req); err != nil || !imported {
		t.Fatalf("Status = %v, %v; want true", imported, err)
	}

	for _, alg := range crypto.All() {
		t.Run(string(alg), func(t *testing.T) {
			sh, err := e.svc.Open(ctx, req, alg)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if sh.Profile == nil || *sh.Profile != e.data {
				t.Fatalf("profile = %+v, want %+v", sh.Profile, e.data)
			}
			if len(sh.Files) != 2 {
				t.Fatalf("%d files, want 2", len(sh.Files))
			}
			for _, f := range sh.Files {
				if !f.NameOK || f.Name != e.names[f.ID] {
					t.Errorf("file %s name = %q (ok %v), want %q", f.ID.Hex(), f.Name, f.NameOK, e.names[f.ID])
				}
				if f.SlotLabel == "" {
					t.Errorf("file %s has no slot label", f.ID.Hex())
				}
				hdr, got, err := download(e, req, f.ID, alg)
				if err != nil {
					t.Fatalf("Download: %v", err)
				}
				if !bytes.Equal(got, e.plain[f.ID]) || hdr.Name != e.names[f.ID] || hdr.Size != int64(len(got)) {
					t.Errorf("download of %s: %d bytes named %q, want the original", f.ID.Hex(), len(got), hdr.Name)
				}
			}
		})
	}
}

// What the server stores before import can't open the data: the keys are
// under the share key, and the share key is only RSA-encrypted.
func TestStoredMaterialHoldsNoUsableKey(t *testing.T) {
	e := newEnv(t)
	req := e.grant(t, e.alice)
	m := e.store.raw(req.ID)

	if len(m.EncryptedKey) != 256 { // 2048-bit test key
		t.Errorf("encrypted key is %d bytes, want 256", len(m.EncryptedKey))
	}
	if m.Imported() {
		t.Error("material is imported right after Grant")
	}
	sh := m.Profile.NIK[crypto.AES]
	if _, err := crypto.UnwrapKey(e.svc.master, sh.Keys.DEK); !errors.Is(err, crypto.ErrAuthentication) {
		t.Errorf("master key unwrapped a share-wrapped DEK: err = %v", err)
	}
	if bytes.Equal(sh.Keys.DEK, sh.Sealed.Meta.WrappedDEK) {
		t.Error("shared DEK is the master-wrapped DEK")
	}
}

func TestGrantIsCreateIfAbsent(t *testing.T) {
	e := newEnv(t)
	req := e.grant(t, e.alice)
	first := e.sentKey(t, req)
	err := e.svc.Grant(ctx, sharing.Grant{RequestID: req.ID, OwnerID: req.OwnerID, RequesterID: req.RequesterID})
	if err != nil {
		t.Fatalf("second Grant: %v", err)
	}
	if e.sentKey(t, req) != first {
		t.Fatal("second Grant replaced the share key the owner already sent")
	}
}

func TestGrantNeedsRequesterKey(t *testing.T) {
	e := newEnv(t)
	err := e.svc.Grant(ctx, sharing.Grant{RequestID: bson.NewObjectID(), OwnerID: e.owner.id, RequesterID: bson.NewObjectID()})
	if err == nil {
		t.Fatal("Grant succeeded for a requester without keys")
	}
}

func TestGrantWithoutProfile(t *testing.T) {
	e := newEnv(t)
	delete(e.profiles, e.owner.id)
	req := e.grant(t, e.alice)
	if err := e.svc.Import(ctx, req, e.alice.password, e.sentKey(t, req)); err != nil {
		t.Fatal(err)
	}
	sh, err := e.svc.Open(ctx, req, crypto.DES)
	if err != nil {
		t.Fatal(err)
	}
	if sh.Profile != nil || len(sh.Files) != 2 {
		t.Fatalf("got profile %v and %d files, want no profile and 2 files", sh.Profile != nil, len(sh.Files))
	}
}

// The share is a snapshot: the owner editing their profile afterwards
// doesn't break it.
func TestProfileEditAfterGrant(t *testing.T) {
	e := newEnv(t)
	req := e.grant(t, e.alice)
	changed := e.data
	changed.Address = "Jl. Baru 2"
	e.profiles[e.owner.id] = e.sealProfile(t, changed)

	if err := e.svc.Import(ctx, req, e.alice.password, e.sentKey(t, req)); err != nil {
		t.Fatal(err)
	}
	sh, err := e.svc.Open(ctx, req, crypto.RC4)
	if err != nil {
		t.Fatal(err)
	}
	if sh.Profile.Address != e.data.Address {
		t.Fatalf("address = %q, want the value at approval time", sh.Profile.Address)
	}
}

func TestImportRefusals(t *testing.T) {
	e := newEnv(t)
	req := e.grant(t, e.alice)
	other := e.grant(t, e.eve) // eve's request to the same owner
	good := e.sentKey(t, req)

	raw, _ := base64.StdEncoding.DecodeString(good)
	flipped := bytes.Clone(raw)
	flipped[10] ^= 1

	tests := []struct {
		name     string
		password string
		key      string
		want     error
	}{
		{"wrong password", "nope", good, ErrWrongPassword},
		{"not base64", e.alice.password, "this is not a key!", ErrBadKey},
		{"empty", e.alice.password, "", ErrBadKey},
		{"too long", e.alice.password, strings.Repeat("A", MaxEncodedKey+4), ErrBadKey},
		{"changed byte", e.alice.password, base64.StdEncoding.EncodeToString(flipped), ErrBadKey},
		// Eve's key is encrypted to eve: alice's private key can't open it.
		{"someone else's key", e.alice.password, e.sentKey(t, other), ErrBadKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := e.svc.Import(ctx, req, tt.password, tt.key); !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			if e.store.raw(req.ID).Imported() {
				t.Fatal("a refused import stored the key")
			}
		})
	}
}

// A key for one request can't be imported into another request of the same
// requester, even though their private key decrypts it: the OAEP label holds
// the request ID.
func TestImportKeyBoundToRequest(t *testing.T) {
	e := newEnv(t)
	first := e.grant(t, e.alice)
	second := e.grant(t, e.alice)
	err := e.svc.Import(ctx, second, e.alice.password, e.sentKey(t, first))
	if !errors.Is(err, ErrBadKey) {
		t.Fatalf("err = %v, want ErrBadKey", err)
	}
}

func TestImportRateLimited(t *testing.T) {
	e := newEnv(t)
	req := e.grant(t, e.alice)
	for range importLimit {
		if err := e.svc.Import(ctx, req, "wrong", e.sentKey(t, req)); !errors.Is(err, ErrWrongPassword) {
			t.Fatalf("err = %v, want ErrWrongPassword", err)
		}
	}
	if err := e.svc.Import(ctx, req, e.alice.password, e.sentKey(t, req)); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("err = %v, want ErrRateLimited", err)
	}
}

// Material is scoped to each side: nobody else's ID finds it.
func TestScopedToParties(t *testing.T) {
	e := newEnv(t)
	req := e.grant(t, e.alice)
	if _, err := e.svc.EncryptedKey(ctx, e.alice.id, req.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("requester read the owner's key page: err = %v", err)
	}
	asEve := *req
	asEve.RequesterID = e.eve.id
	if err := e.svc.Import(ctx, &asEve, e.eve.password, e.sentKey(t, req)); !errors.Is(err, ErrNotFound) {
		t.Errorf("eve imported alice's share: err = %v", err)
	}
	if _, err := e.svc.Open(ctx, &asEve, crypto.AES); !errors.Is(err, ErrNotFound) {
		t.Errorf("eve opened alice's share: err = %v", err)
	}
}

func TestDestroy(t *testing.T) {
	e := newEnv(t)
	req := e.grant(t, e.alice)
	if err := e.svc.Import(ctx, req, e.alice.password, e.sentKey(t, req)); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Destroy(ctx, req.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Open(ctx, req, crypto.AES); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Open after Destroy: err = %v, want ErrNotFound", err)
	}
	if err := e.svc.Destroy(ctx, req.ID); err != nil {
		t.Fatalf("second Destroy: %v", err)
	}
}

func TestTamperingDetected(t *testing.T) {
	e := newEnv(t)
	req := e.grant(t, e.alice)
	if err := e.svc.Import(ctx, req, e.alice.password, e.sentKey(t, req)); err != nil {
		t.Fatal(err)
	}
	m := e.store.raw(req.ID)

	t.Run("profile ciphertext", func(t *testing.T) {
		sh := m.Profile.Email[crypto.AES]
		sh.Sealed.Ciphertext = bytes.Clone(sh.Sealed.Ciphertext)
		sh.Sealed.Ciphertext[0] ^= 1
		m.Profile.Email[crypto.AES] = sh
		if _, err := e.svc.Open(ctx, req, crypto.AES); !errors.Is(err, crypto.ErrAuthentication) {
			t.Fatalf("err = %v, want ErrAuthentication", err)
		}
	})
	t.Run("file object", func(t *testing.T) {
		f := m.Files[0]
		key := f.Variants[crypto.DES].ObjectKey
		e.objects[key] = bytes.Clone(e.objects[key])
		e.objects[key][5] ^= 1
		_, got, err := download(e, req, f.FileID, crypto.DES)
		if !errors.Is(err, crypto.ErrAuthentication) {
			t.Fatalf("err = %v, want ErrAuthentication", err)
		}
		if len(got) != 0 {
			t.Fatalf("wrote %d plaintext bytes before failing", len(got))
		}
	})
	t.Run("imported key moved to another request", func(t *testing.T) {
		other := e.grant(t, e.alice)
		e.store.raw(other.ID).ImportedKey = m.ImportedKey
		if _, err := e.svc.Open(ctx, other, crypto.RC4); !errors.Is(err, crypto.ErrAuthentication) {
			t.Fatalf("err = %v, want ErrAuthentication", err)
		}
	})
}

func TestDownloadUnknownFile(t *testing.T) {
	e := newEnv(t)
	req := e.grant(t, e.alice)
	if err := e.svc.Import(ctx, req, e.alice.password, e.sentKey(t, req)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := download(e, req, bson.NewObjectID(), crypto.AES); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	// A file uploaded after approval isn't part of the share.
	e.addFile(t, "late.pdf", "document", "", []byte("%PDF late"))
	late := e.files[e.owner.id][2].ID
	if _, _, err := download(e, req, late, crypto.AES); !errors.Is(err, ErrNotFound) {
		t.Fatalf("late file: err = %v, want ErrNotFound", err)
	}
}
