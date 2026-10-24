package files

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/eggboixd/infosec-assignment1-group3/internal/benchmark"
	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
)

// Upload errors the handler maps to user-facing messages.
var (
	// ErrMIMENotAllowed is returned when an upload's type is not allowed for
	// its kind, or its content does not match its extension.
	ErrMIMENotAllowed = errors.New("files: file type not allowed for this kind")
	// ErrEmptyFile is returned for a zero-byte upload.
	ErrEmptyFile = errors.New("files: file is empty")
	// ErrTooLarge is returned when an upload exceeds its kind's MaxSize.
	ErrTooLarge = errors.New("files: file too large")
)

// nameUnavailable replaces a filename that fails its integrity check.
const nameUnavailable = "(name failed integrity check)"

// cleanupTimeout bounds deleting partial uploads, which runs on a fresh
// context because the request's may already be cancelled.
const cleanupTimeout = 30 * time.Second

// saveTimeout bounds saving benchmark records. They are saved on a context
// detached from the request: a client that closes the connection as soon
// as it has the last byte cancels the request context, and the record of a
// completed operation would be lost.
const saveTimeout = 5 * time.Second

// metadataStore is the persistence the service needs. *Store satisfies it.
type metadataStore interface {
	Insert(ctx context.Context, rec *FileRecord) error
	Get(ctx context.Context, ownerID, id bson.ObjectID) (*FileRecord, error)
	ListByOwner(ctx context.Context, ownerID bson.ObjectID) ([]FileRecord, error)
	Delete(ctx context.Context, ownerID, id bson.ObjectID) error
}

// benchmarkSink receives one record per measured operation.
// *benchmark.Store satisfies it.
type benchmarkSink interface {
	Save(ctx context.Context, r benchmark.Record) error
}

// Service implements the streaming upload and download pipeline on plain
// Go types.
type Service struct {
	meta    metadataStore
	objects ObjectStore
	enc     crypto.Encryptor
	// bench may be nil, which disables benchmark records.
	bench benchmarkSink
	now   func() time.Time
}

// NewService returns a Service.
func NewService(meta metadataStore, objects ObjectStore, enc crypto.Encryptor, bench benchmarkSink) *Service {
	return &Service{meta: meta, objects: objects, enc: enc, bench: bench, now: time.Now}
}

// objectKey names one variant in object storage. It holds only IDs, never
// the filename, so the bucket listing reveals nothing about the content.
func objectKey(ownerID, fileID bson.ObjectID, alg crypto.Algorithm) string {
	return ownerID.Hex() + "/" + fileID.Hex() + "/" + string(alg)
}

// Upload checks r's type, then encrypts it once per algorithm and stores
// each ciphertext. The plaintext is read exactly once and never buffered
// whole: it is fanned out to three pipes, one per algorithm, and each
// encrypted stream goes straight to object storage (docs/decisions.md D32).
//
// If anything fails, the objects already written are deleted and no
// metadata is inserted. The browser-supplied Content-Type is not used.
func (s *Service) Upload(ctx context.Context, ownerID bson.ObjectID, kind Kind, filename string, r io.Reader) (*FileRecord, error) {
	filename = cleanFilename(filename)
	br := bufio.NewReaderSize(r, sniffLen)
	head, err := br.Peek(sniffLen)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("files: read upload: %w", err)
	}
	if len(head) == 0 {
		return nil, ErrEmptyFile
	}
	mimeType, err := detectMIME(kind, filename, head)
	if err != nil {
		return nil, err
	}

	rec := &FileRecord{
		ID:        bson.NewObjectID(),
		OwnerID:   ownerID,
		Kind:      kind,
		MIMEType:  mimeType,
		Variants:  map[crypto.Algorithm]Variant{},
		CreatedAt: s.now().UTC(),
	}
	size, variants, records, err := s.encryptAll(ctx, rec, br)
	if err != nil {
		s.deleteObjects(rec)
		return nil, err
	}
	rec.Size = size
	rec.Variants = variants

	rec.FileName = crypto.SealedSet{}
	for _, alg := range crypto.All() {
		ct, meta, err := s.enc.EncryptField(alg, []byte(filename))
		if err != nil {
			s.deleteObjects(rec)
			return nil, fmt.Errorf("files: seal filename: %w", err)
		}
		rec.FileName[alg] = crypto.Sealed{Ciphertext: ct, Meta: meta}
	}
	if err := s.meta.Insert(ctx, rec); err != nil {
		s.deleteObjects(rec)
		return nil, err
	}
	for i := range records {
		records[i].FileKind = string(kind)
	}
	s.saveRecords(ctx, records...)
	return rec, nil
}

// variantResult is what one algorithm's goroutines report.
type variantResult struct {
	alg     crypto.Algorithm
	variant Variant
	record  benchmark.Record
	err     error
}

// encryptAll copies src once into one pipe per algorithm. For each
// algorithm, one goroutine encrypts from its pipe into a second pipe and
// another streams that ciphertext into object storage.
//
// A failure anywhere closes the pipes with that error, so every other
// goroutine and the copy loop stop instead of blocking. Put runs on a
// context detached from the request, and the context is not cancelled on
// failure: minio-go aborts a failed multipart upload using Put's context,
// and a cancelled one (the client disconnecting cancels the request's)
// would leave the incomplete upload behind. Put still ends promptly,
// because its pipe is closed with the error.
func (s *Service) encryptAll(ctx context.Context, rec *FileRecord, src io.Reader) (int64, map[crypto.Algorithm]Variant, []benchmark.Record, error) {
	putCtx := context.WithoutCancel(ctx)
	algs := crypto.All()
	plainWriters := make([]*io.PipeWriter, len(algs))
	results := make(chan variantResult, len(algs))
	var wg sync.WaitGroup

	for i, alg := range algs {
		plainR, plainW := io.Pipe()
		plainWriters[i] = plainW
		key := objectKey(rec.OwnerID, rec.ID, alg)

		wg.Go(func() {
			cipherR, cipherW := io.Pipe()
			putErr := make(chan error, 1)
			go func() {
				err := s.objects.Put(putCtx, key, cipherR, -1, "application/octet-stream")
				// Unblock Encrypt if Put stopped reading early.
				_ = cipherR.CloseWithError(errOr(err, io.ErrClosedPipe))
				putErr <- err
			}()

			counted := &countingWriter{w: cipherW}
			var meta crypto.Meta
			record, encErr := benchmark.Measure(ctx, alg, benchmark.OpEncrypt, func(ctx context.Context) (int64, error) {
				var err error
				meta, err = s.enc.Encrypt(ctx, alg, counted, plainR)
				return counted.n, err
			})
			// nil gives Put a clean EOF; an error makes Put abort.
			_ = cipherW.CloseWithError(encErr)
			err := errors.Join(encErr, <-putErr)
			if err != nil {
				// Stop the copy loop feeding this pipe.
				_ = plainR.CloseWithError(err)
			}
			results <- variantResult{
				alg:     alg,
				variant: Variant{ObjectKey: key, Meta: meta, CiphertextSize: counted.n},
				record:  record,
				err:     err,
			}
		})
	}

	limit := rec.Kind.MaxSize()
	writers := make([]io.Writer, len(plainWriters))
	for i, w := range plainWriters {
		writers[i] = w
	}
	// Read one byte past the limit to tell "exactly at" from "over".
	n, copyErr := io.Copy(io.MultiWriter(writers...), io.LimitReader(src, limit+1))
	if copyErr == nil && n > limit {
		copyErr = ErrTooLarge
	}
	for _, w := range plainWriters {
		_ = w.CloseWithError(copyErr) // nil closes with EOF
	}
	wg.Wait()
	close(results)

	variants := map[crypto.Algorithm]Variant{}
	var records []benchmark.Record
	var errs []error
	for res := range results {
		if res.err != nil {
			errs = append(errs, fmt.Errorf("files: %s variant: %w", res.alg, res.err))
			continue
		}
		res.record.Bytes = n
		variants[res.alg] = res.variant
		records = append(records, res.record)
	}
	// The copy error is the root cause (client gone, body or size limit);
	// the variant errors are its consequences.
	if copyErr != nil {
		return 0, nil, nil, copyErr
	}
	if len(errs) > 0 {
		return 0, nil, nil, errors.Join(errs...)
	}
	return n, variants, records, nil
}

// deleteObjects removes every possible variant of rec. Deleting a key that
// was never written is not an error, so this is safe after any failure.
func (s *Service) deleteObjects(rec *FileRecord) {
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	for _, alg := range crypto.All() {
		key := objectKey(rec.OwnerID, rec.ID, alg)
		if err := s.objects.Delete(ctx, key); err != nil {
			slog.Error("files: delete partial upload", "file_id", rec.ID.Hex(), "alg", alg, "error", err)
		}
	}
}

// Get returns ownerID's file id and its filename decrypted with alg.
// Another user's file is ErrNotFound. A filename that fails its integrity
// check returns crypto.ErrAuthentication.
func (s *Service) Get(ctx context.Context, ownerID, id bson.ObjectID, alg crypto.Algorithm) (*FileRecord, string, error) {
	rec, err := s.meta.Get(ctx, ownerID, id)
	if err != nil {
		return nil, "", err
	}
	name, err := s.openName(rec, alg)
	if err != nil {
		return nil, "", err
	}
	return rec, name, nil
}

// Download verifies and decrypts the alg variant of rec into w.
//
// Envelope.Decrypt checks the HMAC over the whole object before writing any
// plaintext (D9), so on crypto.ErrAuthentication nothing has been written
// and the handler can still send an error status.
func (s *Service) Download(ctx context.Context, rec *FileRecord, alg crypto.Algorithm, w io.Writer) error {
	v, ok := rec.Variants[alg]
	if !ok {
		return fmt.Errorf("files: %s variant: %w", alg, ErrCorrupt)
	}
	obj, err := s.objects.Get(ctx, v.ObjectKey)
	if err != nil {
		return err
	}
	defer obj.Close()

	record, err := benchmark.Measure(ctx, alg, benchmark.OpDecrypt, func(ctx context.Context) (int64, error) {
		counted := &countingWriter{w: w}
		err := s.enc.Decrypt(ctx, alg, v.Meta, counted, obj)
		return counted.n, err
	})
	if err != nil {
		return err
	}
	record.FileKind = string(rec.Kind)
	s.saveRecords(ctx, record)
	return nil
}

// ErrCorrupt is returned when a record lacks the requested variant.
var ErrCorrupt = errors.New("files: record is incomplete")

// List returns ownerID's files, newest first, with filenames decrypted
// from the AES copy.
func (s *Service) List(ctx context.Context, ownerID bson.ObjectID) ([]FileView, error) {
	recs, err := s.meta.ListByOwner(ctx, ownerID)
	if err != nil {
		return nil, err
	}
	out := make([]FileView, 0, len(recs))
	for i := range recs {
		rec := &recs[i]
		name, err := s.openName(rec, crypto.AES)
		ok := err == nil
		if !ok {
			slog.Warn("files: filename integrity check failed", "file_id", rec.ID.Hex(), "error", err)
			name = nameUnavailable
		}
		out = append(out, FileView{
			ID: rec.ID, Name: name, NameOK: ok, Kind: rec.Kind, Size: rec.Size, CreatedAt: rec.CreatedAt,
		})
	}
	return out, nil
}

// Delete removes every variant and then the metadata of file id. If an
// object can't be deleted the record is kept, so the user can retry.
func (s *Service) Delete(ctx context.Context, ownerID, id bson.ObjectID) error {
	rec, err := s.meta.Get(ctx, ownerID, id)
	if err != nil {
		return err
	}
	for alg, v := range rec.Variants {
		if err := s.objects.Delete(ctx, v.ObjectKey); err != nil {
			return fmt.Errorf("files: delete %s variant: %w", alg, err)
		}
	}
	return s.meta.Delete(ctx, ownerID, id)
}

// openName decrypts rec's filename with alg.
func (s *Service) openName(rec *FileRecord, alg crypto.Algorithm) (string, error) {
	sealed, ok := rec.FileName[alg]
	if !ok {
		return "", fmt.Errorf("files: %s filename: %w", alg, ErrCorrupt)
	}
	name, err := s.enc.DecryptField(alg, sealed.Meta, sealed.Ciphertext)
	if err != nil {
		return "", err
	}
	return string(name), nil
}

// saveRecords stores benchmark records. A failure is logged and otherwise
// ignored: it must not fail the user's request.
func (s *Service) saveRecords(ctx context.Context, records ...benchmark.Record) {
	if s.bench == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), saveTimeout)
	defer cancel()
	for _, r := range records {
		if err := s.bench.Save(ctx, r); err != nil {
			slog.Warn("files: save benchmark record", "alg", r.Algorithm, "op", r.Operation, "error", err)
		}
	}
}

// The io.Pipe CloseWithError calls above discard their result: it is
// documented to always be nil.

// countingWriter counts the bytes written through it.
type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// errOr returns err, or fallback when err is nil.
func errOr(err, fallback error) error {
	if err != nil {
		return err
	}
	return fallback
}
