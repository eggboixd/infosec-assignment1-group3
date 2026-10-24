// Package files stores uploaded files (ID card images, documents, videos)
// encrypted once per algorithm, and streams them back decrypted.
package files

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"path"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

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

// MIME types that http.DetectContentType cannot name on its own.
const (
	mimeDOC  = "application/msword"
	mimeDOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	mimeXLS  = "application/vnd.ms-excel"
	mimeXLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
)

// allowedMIME lists the accepted MIME types per kind.
var allowedMIME = map[Kind][]string{
	KindIDCard: {
		"image/jpeg",
		"image/png",
	},
	KindDocument: {
		"application/pdf",
		mimeDOC,
		mimeDOCX,
		mimeXLS,
		mimeXLSX,
	},
	KindVideo: {
		"video/mp4",
		"video/webm",
	},
}

// maxSize is the largest plaintext accepted per kind (docs/decisions.md
// D33). The request body limit (MAX_BODY_BYTES) applies on top.
var maxSize = map[Kind]int64{
	KindIDCard:   10 << 20,
	KindDocument: 50 << 20,
	KindVideo:    2 << 30,
}

// MaxSize returns the largest accepted plaintext size for k.
func (k Kind) MaxSize() int64 {
	return maxSize[k]
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
func (k Kind) Allows(mimeType string) bool {
	return slices.Contains(allowedMIME[k], mimeType)
}

// AllowedMIMETypes returns a copy of the allowlist for k.
func (k Kind) AllowedMIMETypes() []string {
	return slices.Clone(allowedMIME[k])
}

// sniffLen is how many leading bytes detectMIME needs.
// http.DetectContentType reads at most 512.
const sniffLen = 512

// fileTypes maps each accepted extension to its MIME type and a check on the
// file's leading bytes. Both must agree: the extension alone is chosen by
// the uploader, and sniffing alone cannot tell DOCX from XLSX (both are ZIP)
// or DOC from XLS (both are OLE2). The browser's Content-Type is ignored.
var fileTypes = map[string]struct {
	mime  string
	magic func(head []byte) bool
}{
	".jpg":  {"image/jpeg", sniffs("image/jpeg")},
	".jpeg": {"image/jpeg", sniffs("image/jpeg")},
	".png":  {"image/png", sniffs("image/png")},
	".pdf":  {"application/pdf", sniffs("application/pdf")},
	".doc":  {mimeDOC, hasPrefix(oleMagic)},
	".xls":  {mimeXLS, hasPrefix(oleMagic)},
	".docx": {mimeDOCX, hasPrefix(zipMagic)},
	".xlsx": {mimeXLSX, hasPrefix(zipMagic)},
	".mp4":  {"video/mp4", sniffs("video/mp4")},
	".webm": {"video/webm", sniffs("video/webm")},
}

var (
	// oleMagic starts every OLE2 compound file (.doc, .xls).
	oleMagic = []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}
	// zipMagic starts a ZIP local file header (.docx, .xlsx).
	zipMagic = []byte("PK\x03\x04")
)

func sniffs(want string) func([]byte) bool {
	return func(head []byte) bool {
		got, _, _ := strings.Cut(http.DetectContentType(head), ";")
		return got == want
	}
}

func hasPrefix(magic []byte) func([]byte) bool {
	return func(head []byte) bool { return bytes.HasPrefix(head, magic) }
}

// detectMIME returns the MIME type of an upload named filename whose first
// bytes are head, or ErrMIMENotAllowed if the extension is not accepted for
// kind or the content does not match the extension.
func detectMIME(kind Kind, filename string, head []byte) (string, error) {
	ext := strings.ToLower(path.Ext(filename))
	t, ok := fileTypes[ext]
	if !ok || !kind.Allows(t.mime) || !t.magic(head) {
		return "", ErrMIMENotAllowed
	}
	return t.mime, nil
}

// maxNameLen bounds a stored filename, in bytes.
const maxNameLen = 255

// cleanFilename keeps the last path element of the client-supplied name
// (browsers on Windows may send a full path), drops control characters,
// and truncates it to maxNameLen bytes on a UTF-8 boundary.
func cleanFilename(name string) string {
	name = strings.ReplaceAll(name, `\`, "/")
	name = path.Base(name)
	name = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == utf8.RuneError {
			return -1
		}
		return r
	}, name)
	name = strings.TrimSpace(name)
	for len(name) > maxNameLen {
		_, size := utf8.DecodeLastRuneInString(name)
		name = name[:len(name)-size]
	}
	if name == "" || name == "." || name == ".." || name == "/" {
		return "file"
	}
	return name
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

// FileView is one row of the file list, with the filename decrypted.
type FileView struct {
	ID   bson.ObjectID
	Name string
	// NameOK is false when the stored filename failed its integrity check;
	// Name then holds a placeholder.
	NameOK    bool
	Kind      Kind
	Size      int64
	CreatedAt time.Time
}
