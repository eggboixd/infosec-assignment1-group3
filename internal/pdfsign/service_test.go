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
	"strings"
	"sync"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
	"github.com/eggboixd/infosec-assignment1-group3/internal/files"
	"github.com/eggboixd/infosec-assignment1-group3/internal/keypair"
)

// fakeFiles is an in-memory, owner-scoped stand-in for files.Service.
type fakeFiles struct {
	mu        sync.Mutex
	recs      map[bson.ObjectID]*files.FileRecord
	names     map[bson.ObjectID]string
	data      map[bson.ObjectID][]byte
	downloads int
	uploads   []upload
	getErr    error
}

type upload struct {
	owner bson.ObjectID
	kind  files.Kind
	slot  files.Slot
	name  string
	data  []byte
	rec   *files.FileRecord
}

func newFakeFiles() *fakeFiles {
	return &fakeFiles{recs: map[bson.ObjectID]*files.FileRecord{}, names: map[bson.ObjectID]string{}, data: map[bson.ObjectID][]byte{}}
}

func (f *fakeFiles) add(owner bson.ObjectID, name, mime string, slot files.Slot, data []byte) bson.ObjectID {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := bson.NewObjectID()
	f.recs[id] = &files.FileRecord{ID: id, OwnerID: owner, Kind: files.KindDocument, Slot: slot, MIMEType: mime, Size: int64(len(data))}
	f.names[id] = name
	f.data[id] = data
	return id
}

func (f *fakeFiles) Get(_ context.Context, owner, id bson.ObjectID, alg crypto.Algorithm) (*files.FileRecord, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return nil, "", f.getErr
	}
	rec, ok := f.recs[id]
	if !ok || rec.OwnerID != owner || !alg.Valid() {
		return nil, "", files.ErrNotFound
	}
	return rec, f.names[id], nil
}

func (f *fakeFiles) Download(_ context.Context, rec *files.FileRecord, _ crypto.Algorithm, w io.Writer) error {
	f.mu.Lock()
	data := f.data[rec.ID]
	f.downloads++
	f.mu.Unlock()
	_, err := w.Write(data)
	return err
}

func (f *fakeFiles) Upload(_ context.Context, owner bson.ObjectID, kind files.Kind, name string, r io.Reader) (*files.FileRecord, error) {
	return f.store(owner, kind, "", name, r)
}

func (f *fakeFiles) UploadSlot(_ context.Context, owner bson.ObjectID, slot files.SlotInfo, name string, r io.Reader) (*files.FileRecord, error) {
	if !slot.AllowsExt(name) {
		return nil, files.ErrMIMENotAllowed
	}
	return f.store(owner, slot.Kind, slot.Slot, name, r)
}

func (f *fakeFiles) store(owner bson.ObjectID, kind files.Kind, slot files.Slot, name string, r io.Reader) (*files.FileRecord, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	id := f.add(owner, name, "application/pdf", slot, data)
	f.mu.Lock()
	defer f.mu.Unlock()
	rec := f.recs[id]
	f.uploads = append(f.uploads, upload{owner, kind, slot, name, data, rec})
	return rec, nil
}

// fakeVault stands in for keypair.Service: one password and key per user.
type fakeVault struct {
	mu      sync.Mutex
	keys    map[bson.ObjectID]*rsa.PrivateKey
	pw      map[bson.ObjectID]string
	unlocks int
}

func (v *fakeVault) Unlock(_ context.Context, id bson.ObjectID, password string, p keypair.Purpose) (*rsa.PrivateKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.unlocks++
	if p != keypair.Signing {
		return nil, fmt.Errorf("test: unlocked the %s key", p)
	}
	k, ok := v.keys[id]
	if !ok {
		return nil, keypair.ErrNoKeys
	}
	if password != v.pw[id] {
		return nil, keypair.ErrUnlock
	}
	// A deep copy, as Unlock decrypts a fresh key each time: the service
	// wipes it, and must not wipe the shared test key.
	return cloneKey(k), nil
}

func (v *fakeVault) PublicKey(_ context.Context, id bson.ObjectID, p keypair.Purpose) (*rsa.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if p != keypair.Signing {
		return nil, fmt.Errorf("test: asked for the %s key", p)
	}
	k, ok := v.keys[id]
	if !ok {
		return nil, keypair.ErrNoKeys
	}
	return &k.PublicKey, nil
}

type serviceEnv struct {
	svc   *Service
	files *fakeFiles
	vault *fakeVault
	ana   signer
	budi  signer
	clock *time.Time
}

func newServiceEnv(t *testing.T) *serviceEnv {
	t.Helper()
	ana, budi, _ := testSigners(t)
	vault := &fakeVault{
		keys: map[bson.ObjectID]*rsa.PrivateKey{ana.id.UserID: ana.priv, budi.id.UserID: budi.priv},
		pw:   map[bson.ObjectID]string{ana.id.UserID: "ana-password", budi.id.UserID: "budi-password"},
	}
	fs := newFakeFiles()
	svc := NewService(fs, vault)
	now := signTime
	svc.now = func() time.Time { return now }
	svc.limiter.now = func() time.Time { return now }
	return &serviceEnv{svc: svc, files: fs, vault: vault, ana: ana, budi: budi, clock: &now}
}

func TestSignFileStoresSignedCopyInSameSlot(t *testing.T) {
	e := newServiceEnv(t)
	ctx := context.Background()
	orig := simplePDF()
	id := e.files.add(e.ana.id.UserID, "cv.pdf", "application/pdf", files.SlotCV, orig)

	rec, err := e.svc.SignFile(ctx, e.ana.id, id, "ana-password")
	if err != nil {
		t.Fatal(err)
	}
	if len(e.files.uploads) != 1 {
		t.Fatalf("%d uploads", len(e.files.uploads))
	}
	up := e.files.uploads[0]
	if up.rec != rec || up.owner != e.ana.id.UserID || up.slot != files.SlotCV || up.name != "cv-signed.pdf" {
		t.Fatalf("upload %+v", up)
	}
	if !bytes.HasPrefix(up.data, orig) {
		t.Fatal("signed copy doesn't start with the original")
	}
	// The original is untouched and still there.
	if _, _, err := e.files.Get(ctx, e.ana.id.UserID, id, crypto.AES); err != nil || !bytes.Equal(e.files.data[id], orig) {
		t.Fatalf("original changed or gone: %v", err)
	}

	rep, err := e.svc.VerifyFile(ctx, e.ana.id.UserID, rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Status != StatusValid || len(rep.Signatures) != 1 || rep.Signatures[0].SignerID != e.ana.id.UserID {
		t.Fatalf("report %+v", rep)
	}

	// Budi can't sign Ana's file, and the signed copy can be signed again by
	// its owner.
	if _, err := e.svc.SignFile(ctx, e.budi.id, rec.ID, "budi-password"); !errors.Is(err, files.ErrNotFound) {
		t.Fatalf("other user's file: %v", err)
	}
	rec2, err := e.svc.SignFile(ctx, e.ana.id, rec.ID, "ana-password")
	if err != nil {
		t.Fatal(err)
	}
	if e.files.names[rec2.ID] != "cv-signed-signed.pdf" {
		t.Fatalf("second name %q", e.files.names[rec2.ID])
	}
	if rep, _ := e.svc.VerifyFile(ctx, e.ana.id.UserID, rec2.ID); rep.Status != StatusValid || len(rep.Signatures) != 2 {
		t.Fatalf("signed twice: %+v", rep)
	}
}

func TestSignFileWithoutSlot(t *testing.T) {
	e := newServiceEnv(t)
	id := e.files.add(e.ana.id.UserID, "Letter.PDF", "application/pdf", "", formPDF())
	if _, err := e.svc.SignFile(context.Background(), e.ana.id, id, "ana-password"); err != nil {
		t.Fatal(err)
	}
	up := e.files.uploads[0]
	if up.slot != "" || up.kind != files.KindDocument || up.name != "Letter-signed.pdf" {
		t.Fatalf("upload %+v", up)
	}
}

func TestSignFileRejects(t *testing.T) {
	e := newServiceEnv(t)
	ctx := context.Background()
	ana := e.ana.id.UserID
	pdfID := e.files.add(ana, "cv.pdf", "application/pdf", files.SlotCV, simplePDF())
	docID := e.files.add(ana, "letter.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", files.SlotRecommendation, []byte("PK\x03\x04"))
	lying := e.files.add(ana, "fake.pdf", "application/pdf", "", []byte("not really a PDF"))

	// A PDF whose signature was broken after signing (made with Budi's key
	// in another app instance; here: a flipped byte).
	signed := mustSign(t, simplePDF(), e.budi)
	hello := bytes.Index(signed, []byte("Hello"))
	broken := e.files.add(ana, "broken.pdf", "application/pdf", "", flipAt(signed, int64(hello), 'J'))

	cases := map[string]struct {
		id   bson.ObjectID
		pw   string
		want error
	}{
		"unknown file":        {bson.NewObjectID(), "ana-password", files.ErrNotFound},
		"not a PDF (MIME)":    {docID, "ana-password", ErrNotPDF},
		"not a PDF (content)": {lying, "ana-password", ErrNotPDF},
		"invalid signature":   {broken, "ana-password", ErrExistingSignatureInvalid},
		"wrong password":      {pdfID, "wrong", keypair.ErrUnlock},
	}
	for name, tc := range cases {
		e.vault.unlocks = 0
		_, err := e.svc.SignFile(ctx, e.ana.id, tc.id, tc.pw)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", name, err, tc.want)
		}
		// The password is only tried once the document is known to be signable.
		if tc.want != keypair.ErrUnlock && e.vault.unlocks != 0 {
			t.Errorf("%s: Unlock called %d times", name, e.vault.unlocks)
		}
	}
	if len(e.files.uploads) != 0 {
		t.Fatalf("%d uploads after failures", len(e.files.uploads))
	}

	// A user without keys.
	stranger := Identity{UserID: bson.NewObjectID(), Username: "new"}
	sid := e.files.add(stranger.UserID, "x.pdf", "application/pdf", "", simplePDF())
	if _, err := e.svc.SignFile(ctx, stranger, sid, "pw"); !errors.Is(err, keypair.ErrNoKeys) {
		t.Errorf("no keys: %v", err)
	}
	if _, err := e.svc.SignFile(ctx, Identity{}, pdfID, "ana-password"); err == nil {
		t.Error("empty signer accepted")
	}
}

func TestSignFileRateLimit(t *testing.T) {
	e := newServiceEnv(t)
	ctx := context.Background()
	id := e.files.add(e.ana.id.UserID, "cv.pdf", "application/pdf", "", simplePDF())

	for i := range maxUnlockFailures {
		if _, err := e.svc.SignFile(ctx, e.ana.id, id, "guess"); !errors.Is(err, keypair.ErrUnlock) {
			t.Fatalf("attempt %d: %v", i+1, err)
		}
	}
	// Now blocked, even with the right password, and without decrypting.
	e.files.downloads, e.vault.unlocks = 0, 0
	_, err := e.svc.SignFile(ctx, e.ana.id, id, "ana-password")
	var rl *RateLimitError
	if !errors.Is(err, ErrRateLimited) || !errors.As(err, &rl) || rl.RetryAfter <= 0 || rl.RetryAfter > unlockWindow {
		t.Fatalf("blocked: err = %v", err)
	}
	if e.files.downloads != 0 || e.vault.unlocks != 0 {
		t.Fatalf("blocked request still downloaded (%d) or unlocked (%d)", e.files.downloads, e.vault.unlocks)
	}
	// Other users are not affected.
	bid := e.files.add(e.budi.id.UserID, "b.pdf", "application/pdf", "", simplePDF())
	if _, err := e.svc.SignFile(ctx, e.budi.id, bid, "budi-password"); err != nil {
		t.Fatalf("other user: %v", err)
	}
	// After the window, Ana can sign again.
	*e.clock = e.clock.Add(unlockWindow)
	if _, err := e.svc.SignFile(ctx, e.ana.id, id, "ana-password"); err != nil {
		t.Fatalf("after window: %v", err)
	}
}

// Successful signatures don't count towards the limit.
func TestSignFileManySuccessesNotLimited(t *testing.T) {
	e := newServiceEnv(t)
	id := e.files.add(e.ana.id.UserID, "cv.pdf", "application/pdf", "", simplePDF())
	for i := range maxUnlockFailures + 2 {
		if _, err := e.svc.SignFile(context.Background(), e.ana.id, id, "ana-password"); err != nil {
			t.Fatalf("signature %d: %v", i+1, err)
		}
	}
}

func TestVerifyFileAndUpload(t *testing.T) {
	e := newServiceEnv(t)
	ctx := context.Background()
	signed := mustSign(t, formPDF(), e.budi)
	id := e.files.add(e.ana.id.UserID, "from-budi.pdf", "application/pdf", "", signed)

	rep, err := e.svc.VerifyFile(ctx, e.ana.id.UserID, id)
	if err != nil || rep.Status != StatusValid || rep.Signatures[0].SignerID != e.budi.id.UserID {
		t.Fatalf("VerifyFile: %+v, %v", rep, err)
	}
	if _, err := e.svc.VerifyFile(ctx, e.budi.id.UserID, id); !errors.Is(err, files.ErrNotFound) {
		t.Fatalf("other user's file: %v", err)
	}
	docID := e.files.add(e.ana.id.UserID, "a.xlsx", "application/vnd.ms-excel", "", []byte("x"))
	if _, err := e.svc.VerifyFile(ctx, e.ana.id.UserID, docID); !errors.Is(err, ErrNotPDF) {
		t.Fatalf("non-PDF: %v", err)
	}

	rep, err = e.svc.VerifyUpload(ctx, bytes.NewReader(append(bytes.Clone(signed), "junk"...)))
	if err != nil || rep.Status != StatusModified || rep.AppendedBytes != 4 {
		t.Fatalf("VerifyUpload modified: %+v, %v", rep, err)
	}
	if rep, err := e.svc.VerifyUpload(ctx, bytes.NewReader(simplePDF())); err != nil || rep.Status != StatusUnsigned {
		t.Fatalf("VerifyUpload unsigned: %+v, %v", rep, err)
	}
	for name, tc := range map[string]struct {
		r    io.Reader
		want error
	}{
		"empty":      {bytes.NewReader(nil), ErrNotPDF},
		"not PDF":    {strings.NewReader("hello"), ErrNotPDF},
		"too large":  {io.MultiReader(strings.NewReader("%PDF-1.7\n"), io.LimitReader(zeroReader{}, MaxSize)), ErrTooLarge},
		"read error": {io.MultiReader(strings.NewReader("%PDF-"), errReader{}), errBoom},
	} {
		if _, err := e.svc.VerifyUpload(ctx, tc.r); !errors.Is(err, tc.want) {
			t.Errorf("VerifyUpload %s: %v, want %v", name, err, tc.want)
		}
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

var errBoom = errors.New("boom")

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errBoom }

func TestServiceHonoursCancel(t *testing.T) {
	e := newServiceEnv(t)
	id := e.files.add(e.ana.id.UserID, "cv.pdf", "application/pdf", "", simplePDF())
	// Fill both slots so the call has to wait, then cancel it.
	for range maxConcurrent {
		e.svc.slots <- struct{}{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := e.svc.SignFile(ctx, e.ana.id, id, "ana-password"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("SignFile: %v", err)
	}
	if _, err := e.svc.VerifyUpload(ctx, bytes.NewReader(simplePDF())); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("VerifyUpload: %v", err)
	}
}

// Nothing the service logs may contain the password or document content.
func TestServiceLogsNoSecrets(t *testing.T) {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(old)

	e := newServiceEnv(t)
	id := e.files.add(e.ana.id.UserID, "secret-name.pdf", "application/pdf", "", simplePDF())
	_, _ = e.svc.SignFile(context.Background(), e.ana.id, id, "wrong-password-xyz")
	if _, err := e.svc.SignFile(context.Background(), e.ana.id, id, "ana-password"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if out == "" {
		t.Fatal("expected some log lines")
	}
	for _, secret := range []string{"wrong-password-xyz", "ana-password", "Hello", "secret-name"} {
		if strings.Contains(out, secret) {
			t.Errorf("log contains %q:\n%s", secret, out)
		}
	}
}

func TestSignedName(t *testing.T) {
	for in, want := range map[string]string{
		"cv.pdf":        "cv-signed.pdf",
		"CV.PDF":        "CV-signed.pdf",
		"a.b.pdf":       "a.b-signed.pdf",
		".pdf":          "document-signed.pdf",
		"noext":         "noext-signed.pdf",
		"cv-signed.pdf": "cv-signed-signed.pdf",
	} {
		if got := signedName(in); got != want {
			t.Errorf("%q → %q, want %q", in, got, want)
		}
	}
}

func cloneKey(k *rsa.PrivateKey) *rsa.PrivateKey {
	c := *k
	cp := func(b *big.Int) *big.Int {
		if b == nil {
			return nil
		}
		return new(big.Int).Set(b)
	}
	c.D = cp(k.D)
	c.Primes = make([]*big.Int, len(k.Primes))
	for i, p := range k.Primes {
		c.Primes[i] = cp(p)
	}
	c.Precomputed.Dp, c.Precomputed.Dq, c.Precomputed.Qinv = cp(k.Precomputed.Dp), cp(k.Precomputed.Dq), cp(k.Precomputed.Qinv)
	c.Precomputed.CRTValues = nil
	return &c
}

func TestWipeKey(t *testing.T) {
	_, _, c := testKeys(t)
	k := cloneKey(c)
	wipeKey(k)
	if k.D.Sign() != 0 || k.Primes[0].Sign() != 0 || k.Primes[1].Sign() != 0 || k.Precomputed.Dp.Sign() != 0 || k.Precomputed.Qinv.Sign() != 0 {
		t.Fatal("private values not cleared")
	}
	if c.D.Sign() == 0 || c.Primes[0].Sign() == 0 || c.Precomputed.Dp.Sign() == 0 {
		t.Fatal("wiped the shared test key")
	}
	wipeKey(nil) // no panic
}

func TestFailureLimiterSweep(t *testing.T) {
	l := newFailureLimiter(1, time.Minute)
	now := signTime
	l.now = func() time.Time { return now }
	for i := range maxTrackedUsers {
		l.fail(fmt.Sprint(i))
	}
	if b, _ := l.blocked("0"); !b {
		t.Fatal("key 0 should be blocked")
	}
	now = now.Add(time.Minute)
	l.fail("new") // triggers a sweep of the expired windows
	if len(l.hits) != 1 {
		t.Fatalf("%d keys tracked after sweep", len(l.hits))
	}
}
