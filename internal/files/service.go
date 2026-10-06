package files

import (
	"context"
	"errors"
	"io"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/eggboixd/infosec-assignment1-group3/internal/benchmark"
	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
)

// ErrNotImplemented marks service functions that are still stubs.
var ErrNotImplemented = errors.New("files: not implemented")

// ErrMIMENotAllowed is returned when an upload's type is not allowed for its kind.
var ErrMIMENotAllowed = errors.New("files: file type not allowed for this kind")

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
	bench   benchmarkSink
}

// NewService returns a Service.
func NewService(meta metadataStore, objects ObjectStore, enc crypto.Encryptor, bench benchmarkSink) *Service {
	return &Service{meta: meta, objects: objects, enc: enc, bench: bench}
}

// Upload encrypts r once per algorithm and stores each ciphertext.
//
// TODO(feature/file-storage): read the plaintext exactly once and fan it
// out to one goroutine per algorithm: io.MultiWriter over three io.Pipe
// writers; each goroutine runs enc.Encrypt into a second io.Pipe whose
// reader goes to objects.Put(ctx, key, pr, -1, "application/octet-stream").
// Wrap each Encrypt in benchmark.Measure(OpEncrypt) and save the Record.
// Use random object keys (owner/<file id>/<alg>), never the filename. If any
// variant fails, close all pipes with the error, delete the variants already
// written, and insert no metadata. Seal filename with EncryptField.
func (s *Service) Upload(ctx context.Context, ownerID bson.ObjectID, kind Kind, filename, mimeType string, r io.Reader) (*FileRecord, error) {
	return nil, ErrNotImplemented
}

// Download verifies and decrypts the alg variant of file id into w.
//
// TODO(feature/file-storage): load the record (owner-scoped), open the
// object with objects.Get, and call enc.Decrypt, which verifies the HMAC
// over the whole object before writing any plaintext. Measure with
// benchmark.Measure(OpDecrypt). Because nothing is written before
// verification, the handler can still send an error status on tamper.
func (s *Service) Download(ctx context.Context, ownerID, id bson.ObjectID, alg crypto.Algorithm, w io.Writer) (*FileRecord, error) {
	return nil, ErrNotImplemented
}

// List returns ownerID's files.
//
// TODO(feature/file-storage): call meta.ListByOwner and decrypt filenames
// for display.
func (s *Service) List(ctx context.Context, ownerID bson.ObjectID) ([]FileRecord, error) {
	return nil, ErrNotImplemented
}

// Delete removes every variant and the metadata of file id.
//
// TODO(feature/file-storage): delete each variant's object, then the record.
func (s *Service) Delete(ctx context.Context, ownerID, id bson.ObjectID) error {
	return ErrNotImplemented
}
