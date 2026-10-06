// Package files stores uploaded files (ID card images, documents, videos)
// encrypted once per algorithm, and streams them back decrypted.
package files

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
)

// Kind is the category of an uploaded file. It selects the MIME allowlist.
type Kind string

// Supported kinds. The string values come from the upload form's kind field.
const (
	KindIDCard   Kind = "idcard"
	KindDocument Kind = "document"
	KindVideo    Kind = "video"
)

// ErrUnknownKind is returned for a kind outside the constants above.
var ErrUnknownKind = errors.New("files: unknown kind")

// allowedMIME lists the accepted MIME types per kind.
var allowedMIME = map[Kind][]string{
	KindIDCard: {
		"image/jpeg",
		"image/png",
	},
	KindDocument: {
		"application/pdf",
		"application/msword", // .doc
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document", // .docx
		"application/vnd.ms-excel", // .xls
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", // .xlsx
	},
	KindVideo: {
		"video/mp4",
		"video/webm",
	},
}

// ParseKind converts form input into a Kind.
func ParseKind(s string) (Kind, error) {
	k := Kind(s)
	if _, ok := allowedMIME[k]; !ok {
		return "", fmt.Errorf("%w: %q", ErrUnknownKind, s)
	}
	return k, nil
}

// Allows reports whether mimeType is accepted for k. mimeType must already
// be normalised (lowercase, no parameters).
//
// TODO(feature/file-storage): decide how the MIME type is established.
// http.DetectContentType reports DOCX/XLSX as application/zip and DOC/XLS as
// application/octet-stream, so sniffing alone cannot tell them apart; a
// combination of sniffed magic bytes and the file extension is needed.
func (k Kind) Allows(mimeType string) bool {
	return slices.Contains(allowedMIME[k], mimeType)
}

// AllowedMIMETypes returns a copy of the allowlist for k.
func (k Kind) AllowedMIMETypes() []string {
	return slices.Clone(allowedMIME[k])
}

// Variant is one encrypted copy of a file.
type Variant struct {
	// ObjectKey locates the ciphertext in object storage.
	ObjectKey string      `bson:"object_key"`
	Meta      crypto.Meta `bson:"meta"`
	// CiphertextSize is the stored object size in bytes.
	CiphertextSize int64 `bson:"ciphertext_size"`
}

// FileRecord is the metadata document for one upload in the files collection.
type FileRecord struct {
	ID      bson.ObjectID `bson:"_id,omitempty"`
	OwnerID bson.ObjectID `bson:"owner_id"`
	Kind    Kind          `bson:"kind"`
	// FileName is the original filename, encrypted with each algorithm.
	FileName crypto.SealedSet `bson:"file_name"`
	MIMEType string           `bson:"mime_type"`
	// Size is the plaintext size in bytes.
	Size      int64                        `bson:"size"`
	Variants  map[crypto.Algorithm]Variant `bson:"variants"`
	CreatedAt time.Time                    `bson:"created_at"`
}
