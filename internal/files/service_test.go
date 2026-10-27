package files

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/eggboixd/infosec-assignment1-group3/internal/benchmark"
	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
)

var owner = bson.NewObjectID()

func TestUploadDownloadRoundTrip(t *testing.T) {
	tests := []struct {
		file string
		kind Kind
		mime string
	}{
		{"ktp-fake.jpg", KindIDCard, "image/jpeg"},
		{"ktp-fake.png", KindIDCard, "image/png"},
		{"sample.pdf", KindDocument, "application/pdf"},
		{"sample.docx", KindDocument, mimeDOCX},
		{"sample.xlsx", KindDocument, mimeXLSX},
		{"sample.mp4", KindVideo, "video/mp4"},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			rig := newTestRig(t)
			plain := sample(t, tt.file)

			rec, err := rig.svc.Upload(context.Background(), owner, tt.kind, tt.file, bytes.NewReader(plain))
			if err != nil {
				t.Fatalf("Upload: %v", err)
			}
			if rec.MIMEType != tt.mime || rec.Size != int64(len(plain)) || rec.Kind != tt.kind || rec.OwnerID != owner {
				t.Errorf("record = %s %d %s, want %s %d %s", rec.MIMEType, rec.Size, rec.Kind, tt.mime, len(plain), tt.kind)
			}
			if rig.objects.Len() != 3 || rig.meta.Len() != 1 {
				t.Fatalf("stored %d objects and %d records, want 3 and 1", rig.objects.Len(), rig.meta.Len())
			}

			for _, alg := range crypto.All() {
				v := rec.Variants[alg]
				if strings.Contains(v.ObjectKey, tt.file) || v.ObjectKey != objectKey(owner, rec.ID, alg) {
					t.Errorf("%s: object key %q", alg, v.ObjectKey)
				}
				stored := rig.objects.objs[v.ObjectKey]
				if bytes.Equal(stored, plain) || v.CiphertextSize != int64(len(plain)) || int64(len(stored)) != v.CiphertextSize {
					t.Errorf("%s: stored object is plaintext or has the wrong size", alg)
				}

				got, name, err := rig.svc.Get(context.Background(), owner, rec.ID, alg)
				if err != nil || name != tt.file || got.ID != rec.ID {
					t.Fatalf("%s: Get = %q, %v", alg, name, err)
				}
				var out bytes.Buffer
				if err := rig.svc.Download(context.Background(), got, alg, &out); err != nil {
					t.Fatalf("%s: Download: %v", alg, err)
				}
				if !bytes.Equal(out.Bytes(), plain) {
					t.Errorf("%s: downloaded bytes differ from the upload", alg)
				}
			}
		})
	}
}

// The three copies are independent: different keys and IVs give different
// ciphertexts of the same plaintext.
func TestVariantsDiffer(t *testing.T) {
	rig := newTestRig(t)
	rec, err := rig.svc.Upload(context.Background(), owner, KindDocument, "a.pdf", bytes.NewReader(sample(t, "sample.pdf")))
	if err != nil {
		t.Fatal(err)
	}
	aes, des, rc4 := rig.objects.objs[rec.Variants[crypto.AES].ObjectKey], rig.objects.objs[rec.Variants[crypto.DES].ObjectKey], rig.objects.objs[rec.Variants[crypto.RC4].ObjectKey]
	if bytes.Equal(aes, des) || bytes.Equal(des, rc4) || bytes.Equal(aes, rc4) {
		t.Error("two variants have identical ciphertext")
	}
}

// A multi-megabyte upload streams through the pipes (run with -race).
func TestUploadLargeVideo(t *testing.T) {
	rig := newTestRig(t)
	plain := append(sample(t, "sample.mp4"), make([]byte, 8<<20)...)
	if _, err := rand.Read(plain[28024:]); err != nil {
		t.Fatal(err)
	}
	rec, err := rig.svc.Upload(context.Background(), owner, KindVideo, "clip.mp4", bytes.NewReader(plain))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := rig.svc.Download(context.Background(), rec, crypto.DES, &out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), plain) {
		t.Error("8 MiB round trip differs")
	}
}

func TestUploadRejectsWrongTypes(t *testing.T) {
	pdf, png := sample(t, "sample.pdf"), sample(t, "ktp-fake.png")
	tests := []struct {
		name string
		kind Kind
		file string
		data []byte
	}{
		{"PDF as an ID card", KindIDCard, "card.pdf", pdf},
		{"PDF renamed to .png", KindIDCard, "card.png", pdf},
		{"PNG renamed to .pdf", KindDocument, "doc.pdf", png},
		{"text renamed to .docx", KindDocument, "doc.docx", []byte("just text, not a zip archive")},
		{"HTML renamed to .jpg", KindIDCard, "x.jpg", []byte("<html><script>alert(1)</script></html>")},
		{"no extension", KindDocument, "README", pdf},
		{"executable", KindDocument, "setup.exe", []byte("MZ\x90\x00")},
		{"image as video", KindVideo, "clip.mp4", png},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rig := newTestRig(t)
			_, err := rig.svc.Upload(context.Background(), owner, tt.kind, tt.file, bytes.NewReader(tt.data))
			if !errors.Is(err, ErrMIMENotAllowed) {
				t.Errorf("err = %v, want ErrMIMENotAllowed", err)
			}
			if rig.objects.Len() != 0 || rig.meta.Len() != 0 {
				t.Error("a rejected upload left data behind")
			}
		})
	}
}

func TestUploadEmpty(t *testing.T) {
	rig := newTestRig(t)
	if _, err := rig.svc.Upload(context.Background(), owner, KindDocument, "a.pdf", bytes.NewReader(nil)); !errors.Is(err, ErrEmptyFile) {
		t.Errorf("err = %v, want ErrEmptyFile", err)
	}
}

func TestUploadSizeLimit(t *testing.T) {
	png := sample(t, "ktp-fake.png")
	setMaxSize(t, KindIDCard, int64(len(png)))

	rig := newTestRig(t)
	if _, err := rig.svc.Upload(context.Background(), owner, KindIDCard, "at-limit.png", bytes.NewReader(png)); err != nil {
		t.Fatalf("file exactly at the limit: %v", err)
	}
	rig = newTestRig(t)
	_, err := rig.svc.Upload(context.Background(), owner, KindIDCard, "over.png", bytes.NewReader(append(png, 0)))
	if !errors.Is(err, ErrTooLarge) {
		t.Errorf("one byte over: err = %v, want ErrTooLarge", err)
	}
	if rig.objects.Len() != 0 || rig.meta.Len() != 0 {
		t.Errorf("an oversized upload left %d objects and %d records", rig.objects.Len(), rig.meta.Len())
	}
}

// If one variant can't be stored, the others are deleted and nothing is
// recorded.
func TestUploadCleansUpWhenAVariantFails(t *testing.T) {
	for _, alg := range crypto.All() {
		t.Run(string(alg), func(t *testing.T) {
			rig := newTestRig(t)
			boom := errors.New("disk full")
			rig.objects.failPut = func(key string) error {
				if strings.HasSuffix(key, "/"+string(alg)) {
					return boom
				}
				return nil
			}
			plain := append(sample(t, "sample.mp4"), make([]byte, 1<<20)...)
			_, err := rig.svc.Upload(context.Background(), owner, KindVideo, "clip.mp4", bytes.NewReader(plain))
			if !errors.Is(err, boom) {
				t.Errorf("err = %v, want it to wrap %v", err, boom)
			}
			if rig.objects.Len() != 0 || rig.meta.Len() != 0 || len(rig.bench.Records()) != 0 {
				t.Errorf("left %d objects, %d records, %d benchmarks; want none", rig.objects.Len(), rig.meta.Len(), len(rig.bench.Records()))
			}
		})
	}
}

func TestUploadCleansUpWhenMetadataFails(t *testing.T) {
	rig := newTestRig(t)
	rig.meta.failInsert = errors.New("mongo down")
	if _, err := rig.svc.Upload(context.Background(), owner, KindDocument, "a.pdf", bytes.NewReader(sample(t, "sample.pdf"))); err == nil {
		t.Fatal("Upload succeeded with a failing metadata store")
	}
	if rig.objects.Len() != 0 {
		t.Errorf("%d objects left after the metadata insert failed", rig.objects.Len())
	}
}

// failingReader returns data, then an error, like a client that disconnects
// halfway through an upload.
// failingReader returns data and then err. onErr, if set, runs first, the
// way net/http cancels the request context when reading the body fails.
type failingReader struct {
	data  []byte
	err   error
	onErr func()
}

func (f *failingReader) Read(p []byte) (int, error) {
	if len(f.data) == 0 {
		if f.onErr != nil {
			f.onErr()
		}
		return 0, f.err
	}
	n := copy(p, f.data)
	f.data = f.data[n:]
	return n, nil
}

func TestUploadCleansUpWhenClientDisconnects(t *testing.T) {
	rig := newTestRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	src := &failingReader{data: append(sample(t, "sample.mp4"), make([]byte, 1<<20)...), err: io.ErrUnexpectedEOF, onErr: cancel}
	if _, err := rig.svc.Upload(ctx, owner, KindVideo, "clip.mp4", src); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("err = %v, want %v", err, io.ErrUnexpectedEOF)
	}
	if rig.objects.Len() != 0 || rig.meta.Len() != 0 {
		t.Error("an interrupted upload left data behind")
	}
	if n := rig.objects.Leaked(); n != 0 {
		t.Errorf("%d multipart uploads could not be aborted: Put used the cancelled request context", n)
	}
}

// cancelAfter cancels a context once n bytes have been written through it,
// like a client that closes the connection as soon as it has the body.
type cancelAfter struct {
	n      int
	cancel context.CancelFunc
}

func (c *cancelAfter) Write(p []byte) (int, error) {
	c.n -= len(p)
	if c.n <= 0 {
		c.cancel()
	}
	return len(p), nil
}

func TestDownloadRecordSurvivesClientClose(t *testing.T) {
	rig := newTestRig(t)
	pdf := sample(t, "sample.pdf")
	rec, err := rig.svc.Upload(context.Background(), owner, KindDocument, "a.pdf", bytes.NewReader(pdf))
	if err != nil {
		t.Fatal(err)
	}
	before := len(rig.bench.Records())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := rig.svc.Download(ctx, rec, crypto.AES, &cancelAfter{n: len(pdf), cancel: cancel}); err != nil {
		t.Fatal(err)
	}
	if got := len(rig.bench.Records()) - before; got != 1 {
		t.Errorf("%d decrypt records saved, want 1", got)
	}
}

func TestDownloadTamperedWritesNothing(t *testing.T) {
	for _, alg := range crypto.All() {
		t.Run(string(alg), func(t *testing.T) {
			rig := newTestRig(t)
			rec, err := rig.svc.Upload(context.Background(), owner, KindDocument, "a.pdf", bytes.NewReader(sample(t, "sample.pdf")))
			if err != nil {
				t.Fatal(err)
			}
			rig.objects.Tamper(rec.Variants[alg].ObjectKey)

			var out bytes.Buffer
			if err := rig.svc.Download(context.Background(), rec, alg, &out); !errors.Is(err, crypto.ErrAuthentication) {
				t.Errorf("err = %v, want ErrAuthentication", err)
			}
			if out.Len() != 0 {
				t.Errorf("%d bytes written before the tamper was detected", out.Len())
			}
			// The other copies are untouched and still download.
			for _, other := range crypto.All() {
				if other == alg {
					continue
				}
				if err := rig.svc.Download(context.Background(), rec, other, io.Discard); err != nil {
					t.Errorf("%s copy: %v", other, err)
				}
			}
		})
	}
}

func TestOtherUsersFilesAreInvisible(t *testing.T) {
	rig := newTestRig(t)
	rec, err := rig.svc.Upload(context.Background(), owner, KindDocument, "a.pdf", bytes.NewReader(sample(t, "sample.pdf")))
	if err != nil {
		t.Fatal(err)
	}
	stranger := bson.NewObjectID()
	if _, _, err := rig.svc.Get(context.Background(), stranger, rec.ID, crypto.AES); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get by another user: err = %v, want ErrNotFound", err)
	}
	if err := rig.svc.Delete(context.Background(), stranger, rec.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("Delete by another user: err = %v, want ErrNotFound", err)
	}
	if list, _ := rig.svc.List(context.Background(), stranger); len(list) != 0 {
		t.Errorf("another user lists %d files, want 0", len(list))
	}
	if rig.objects.Len() != 3 {
		t.Error("another user's delete removed objects")
	}
}

func TestDeleteRemovesEverything(t *testing.T) {
	rig := newTestRig(t)
	rec, err := rig.svc.Upload(context.Background(), owner, KindDocument, "a.pdf", bytes.NewReader(sample(t, "sample.pdf")))
	if err != nil {
		t.Fatal(err)
	}
	if err := rig.svc.Delete(context.Background(), owner, rec.ID); err != nil {
		t.Fatal(err)
	}
	if rig.objects.Len() != 0 || rig.meta.Len() != 0 {
		t.Errorf("left %d objects and %d records", rig.objects.Len(), rig.meta.Len())
	}
	if err := rig.svc.Delete(context.Background(), owner, rec.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("second Delete: err = %v, want ErrNotFound", err)
	}
}

func TestListNewestFirstWithNames(t *testing.T) {
	rig := newTestRig(t)
	for _, name := range []string{"first.pdf", "second.pdf", "third.pdf"} {
		if _, err := rig.svc.Upload(context.Background(), owner, KindDocument, name, bytes.NewReader(sample(t, "sample.pdf"))); err != nil {
			t.Fatal(err)
		}
	}
	list, err := rig.svc.List(context.Background(), owner)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range list {
		names = append(names, f.Name)
	}
	if strings.Join(names, ",") != "third.pdf,second.pdf,first.pdf" {
		t.Errorf("names = %v, want newest first", names)
	}
}

// A stored filename that fails its check is shown as a placeholder, not
// trusted, and the rest of the list still loads.
func TestListTamperedFilename(t *testing.T) {
	rig := newTestRig(t)
	rec, err := rig.svc.Upload(context.Background(), owner, KindDocument, "secret.pdf", bytes.NewReader(sample(t, "sample.pdf")))
	if err != nil {
		t.Fatal(err)
	}
	stored := rig.meta.recs[rec.ID]
	stored.FileName[crypto.AES].Ciphertext[0] ^= 1
	list, err := rig.svc.List(context.Background(), owner)
	if err != nil || len(list) != 1 || list[0].NameOK || list[0].Name != nameUnavailable {
		t.Errorf("List = %+v, %v; want one row with the placeholder name", list, err)
	}
	if _, _, err := rig.svc.Get(context.Background(), owner, rec.ID, crypto.AES); !errors.Is(err, crypto.ErrAuthentication) {
		t.Errorf("Get with a tampered AES name: err = %v, want ErrAuthentication", err)
	}
}

func TestBenchmarkRecords(t *testing.T) {
	rig := newTestRig(t)
	plain := sample(t, "ktp-fake.jpg")
	rec, err := rig.svc.Upload(context.Background(), owner, KindIDCard, "card.jpg", bytes.NewReader(plain))
	if err != nil {
		t.Fatal(err)
	}
	if err := rig.svc.Download(context.Background(), rec, crypto.RC4, io.Discard); err != nil {
		t.Fatal(err)
	}
	recs := rig.bench.Records()
	if len(recs) != 4 {
		t.Fatalf("%d benchmark records, want 3 encrypt + 1 decrypt", len(recs))
	}
	seen := map[crypto.Algorithm]bool{}
	for _, r := range recs[:3] {
		seen[r.Algorithm] = true
		if r.Operation != benchmark.OpEncrypt || r.Bytes != int64(len(plain)) || r.FileKind != "idcard" ||
			r.CryptoDuration < 0 || r.TotalDuration < r.CryptoDuration {
			t.Errorf("encrypt record = %+v", r)
		}
	}
	if len(seen) != 3 {
		t.Errorf("encrypt records cover %d algorithms, want 3", len(seen))
	}
	if d := recs[3]; d.Operation != benchmark.OpDecrypt || d.Algorithm != crypto.RC4 || d.Bytes != int64(len(plain)) || d.FileKind != "idcard" {
		t.Errorf("decrypt record = %+v", d)
	}
}
