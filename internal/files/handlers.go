package files

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Handler serves the file routes.
type Handler struct {
	svc *Service
}

// NewHandler returns a Handler for svc.
func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// TODO(feature/file-storage): call h.svc.List and render files.html
// (TODO(feature/frontend) for the template).
func (h *Handler) list(c *gin.Context) {
	c.String(http.StatusNotImplemented, "not implemented")
}

// upload accepts a multipart form with a "kind" field followed by a "file"
// part.
//
// Never use c.FormFile() or c.MultipartForm(): they buffer the whole file
// in memory or in a temporary file on disk, so plaintext would touch disk.
// Stream the part instead:
//
//	mr, err := c.Request.MultipartReader()
//	if err != nil { /* 400 */ }
//	// The "kind" part must come first so it can be validated before the file.
//	part, err := mr.NextPart()        // expect FormName() == "kind"
//	kindValue, err := io.ReadAll(io.LimitReader(part, 32))
//	kind, err := ParseKind(string(kindValue))
//	part, err = mr.NextPart()         // expect FormName() == "file"
//	rec, err := h.svc.Upload(c.Request.Context(), user.ID, kind,
//		part.FileName(), part.Header.Get("Content-Type"), part)
//
// TODO(feature/file-storage): implement as above.
func (h *Handler) upload(c *gin.Context) {
	c.String(http.StatusNotImplemented, "not implemented")
}

// TODO(feature/file-storage): parse :id with bson.ObjectIDFromHex and ?alg
// with crypto.ParseAlgorithm (400 on error), set Content-Type and
// Content-Disposition (with a sanitised filename), then call h.svc.Download
// with c.Writer. Map ErrNotFound to 404 and crypto.ErrAuthentication to 422.
// Wrap the whole handler in benchmark.Measure(OpDownload).
func (h *Handler) download(c *gin.Context) {
	c.String(http.StatusNotImplemented, "not implemented")
}

// TODO(feature/file-storage): parse :id, call h.svc.Delete, return 200 with
// an empty body so htmx removes the row.
func (h *Handler) remove(c *gin.Context) {
	c.String(http.StatusNotImplemented, "not implemented")
}
