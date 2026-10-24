package files

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/eggboixd/infosec-assignment1-group3/internal/auth"
	"github.com/eggboixd/infosec-assignment1-group3/internal/benchmark"
	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
)

// User-facing messages. They never include file contents or names.
const (
	msgBadForm      = "The upload form was incomplete. Choose a kind and a file, then try again."
	msgUnknownKind  = "Unknown file kind. Choose ID card, document or video."
	msgTypeMismatch = "That file type isn't allowed for this kind, or its content doesn't match its extension."
	msgEmpty        = "That file is empty."
	msgUploadFailed = "The file could not be stored. Please try again."
	msgLoadFailed   = "Your files could not be loaded. Please try again."
	msgNotFound     = "We couldn't find that file."
	msgBadAlg       = "Unknown algorithm. Choose AES-256, DES or RC4."
	msgIntegrity    = "This copy of the file failed its integrity check, so it was not sent. It may have been tampered with."
	msgDownload     = "The file could not be downloaded. Please try again."
	msgDeleteFailed = "The file could not be deleted. Please try again."
)

// maxKindLen bounds the "kind" form field.
const maxKindLen = 32

// Handler serves the file routes.
type Handler struct {
	svc *Service
}

// NewHandler returns a Handler for svc.
func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// list handles GET /files.
func (h *Handler) list(c *gin.Context) {
	user, ok := auth.CurrentUser(c)
	if !ok {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	files, err := h.svc.List(c.Request.Context(), user.ID)
	if err != nil {
		slog.Error("files: list", "user_id", user.ID.Hex(), "error", err)
		h.render(c, http.StatusInternalServerError, nil, msgLoadFailed)
		return
	}
	h.render(c, http.StatusOK, files, "")
}

// upload handles POST /files: a multipart form with a "kind" part followed
// by a "file" part. On success it redirects back to /files
// (Post/Redirect/Get).
//
// Never use c.FormFile() or c.MultipartForm(): they buffer the whole file
// in memory or in a temporary file on disk, so plaintext would touch disk.
// The part is streamed straight into Service.Upload instead.
func (h *Handler) upload(c *gin.Context) {
	user, ok := auth.CurrentUser(c)
	if !ok {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	mr, err := c.Request.MultipartReader()
	if err != nil {
		h.renderList(c, user, http.StatusBadRequest, msgBadForm)
		return
	}

	// The "kind" part must come first so it is validated before the file.
	part, err := mr.NextPart()
	if err != nil || part.FormName() != "kind" {
		h.uploadError(c, user, err)
		return
	}
	kindValue, err := io.ReadAll(io.LimitReader(part, maxKindLen))
	if err != nil {
		h.uploadError(c, user, err)
		return
	}
	kind, err := ParseKind(strings.TrimSpace(string(kindValue)))
	if err != nil {
		h.renderList(c, user, http.StatusBadRequest, msgUnknownKind)
		return
	}

	part, err = mr.NextPart()
	if err != nil || part.FormName() != "file" || part.FileName() == "" {
		h.uploadError(c, user, err)
		return
	}
	defer part.Close()

	rec, err := h.svc.Upload(c.Request.Context(), user.ID, kind, part.FileName(), part)
	if err != nil {
		h.uploadError(c, user, err)
		return
	}
	slog.Info("files: uploaded", "user_id", user.ID.Hex(), "file_id", rec.ID.Hex(), "kind", kind, "bytes", rec.Size)
	c.Redirect(http.StatusSeeOther, "/files")
}

// uploadError maps an upload failure to a status and message.
func (h *Handler) uploadError(c *gin.Context, user *auth.User, err error) {
	var maxErr *http.MaxBytesError
	switch {
	case c.Request.Context().Err() != nil, errors.Is(err, context.Canceled):
		// The client went away. net/http cancels the request context when
		// reading the body fails, but the error itself is usually
		// io.ErrUnexpectedEOF. Nobody is left to read a response.
		slog.Info("files: upload cancelled", "user_id", user.ID.Hex())
		c.Abort()
	case err == nil, errors.Is(err, io.EOF):
		// A part was missing or in the wrong order.
		h.renderList(c, user, http.StatusBadRequest, msgBadForm)
	case errors.Is(err, ErrMIMENotAllowed):
		h.renderList(c, user, http.StatusUnsupportedMediaType, msgTypeMismatch)
	case errors.Is(err, ErrEmptyFile):
		h.renderList(c, user, http.StatusBadRequest, msgEmpty)
	case errors.Is(err, ErrTooLarge), errors.As(err, &maxErr):
		h.renderList(c, user, http.StatusRequestEntityTooLarge, tooLargeMessage())
	default:
		slog.Error("files: upload", "user_id", user.ID.Hex(), "error", err)
		h.renderList(c, user, http.StatusInternalServerError, msgUploadFailed)
	}
}

func tooLargeMessage() string {
	return "That file is too large. Limits: ID card " + humanLimit(KindIDCard) +
		", document " + humanLimit(KindDocument) + ", video " + humanLimit(KindVideo) + "."
}

func humanLimit(k Kind) string {
	n := k.MaxSize()
	if n >= 1<<30 {
		return strconv.FormatInt(n>>30, 10) + " GiB"
	}
	return strconv.FormatInt(n>>20, 10) + " MiB"
}

// download handles GET /files/:id/download?alg=aes|des|rc4.
//
// The response headers are set before Download runs but are only sent with
// the first plaintext byte, which Envelope.Decrypt writes after the HMAC
// has verified. On a failed check nothing has been sent, so the headers are
// replaced and an error page is shown instead.
func (h *Handler) download(c *gin.Context) {
	user, ok := auth.CurrentUser(c)
	if !ok {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	id, err := bson.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		renderError(c, user, http.StatusNotFound, msgNotFound)
		return
	}
	alg, err := crypto.ParseAlgorithm(c.Query("alg"))
	if err != nil {
		renderError(c, user, http.StatusBadRequest, msgBadAlg)
		return
	}

	var rec *FileRecord
	record, err := benchmark.Measure(c.Request.Context(), alg, benchmark.OpDownload, func(ctx context.Context) (int64, error) {
		var name string
		var err error
		rec, name, err = h.svc.Get(ctx, user.ID, id, alg)
		if err != nil {
			return 0, err
		}
		hdr := c.Writer.Header()
		hdr.Set("Content-Type", rec.MIMEType)
		hdr.Set("Content-Length", strconv.FormatInt(rec.Size, 10))
		hdr.Set("Content-Disposition", contentDisposition(name))
		hdr.Set("Cache-Control", "no-store")
		counted := &countingWriter{w: c.Writer}
		err = h.svc.Download(ctx, rec, alg, counted)
		return counted.n, err
	})

	switch {
	case err == nil:
		record.FileKind = string(rec.Kind)
		h.svc.saveRecords(c.Request.Context(), record)
	case c.Writer.Written():
		// Plaintext was already streaming (for example the object changed
		// between the verify and decrypt passes, D9). The status is sent;
		// all we can do is stop, which truncates the response.
		slog.Error("files: download aborted mid-stream", "user_id", user.ID.Hex(), "file_id", id.Hex(), "alg", alg, "error", err)
		c.Abort()
	case errors.Is(err, ErrNotFound):
		renderError(c, user, http.StatusNotFound, msgNotFound)
	case errors.Is(err, crypto.ErrAuthentication), errors.Is(err, ErrCorrupt):
		slog.Warn("files: integrity check failed", "user_id", user.ID.Hex(), "file_id", id.Hex(), "alg", alg, "error", err)
		renderError(c, user, http.StatusUnprocessableEntity, msgIntegrity)
	default:
		slog.Error("files: download", "user_id", user.ID.Hex(), "file_id", id.Hex(), "alg", alg, "error", err)
		renderError(c, user, http.StatusInternalServerError, msgDownload)
	}
}

// contentDisposition always marks the response as an attachment, so the
// browser saves the file instead of rendering it (an uploaded PDF or HTML
// polyglot can't run in the app's origin). mime.FormatMediaType quotes the
// name and switches to RFC 2231 encoding for non-ASCII names.
func contentDisposition(name string) string {
	if v := mime.FormatMediaType("attachment", map[string]string{"filename": name}); v != "" {
		return v
	}
	return mime.FormatMediaType("attachment", map[string]string{"filename": "download" + path.Ext(name)})
}

// remove handles DELETE /files/:id. It returns 200 with an empty body so
// htmx replaces the table row with nothing.
func (h *Handler) remove(c *gin.Context) {
	user, ok := auth.CurrentUser(c)
	if !ok {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	id, err := bson.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.String(http.StatusNotFound, msgNotFound)
		return
	}
	switch err := h.svc.Delete(c.Request.Context(), user.ID, id); {
	case err == nil:
		slog.Info("files: deleted", "user_id", user.ID.Hex(), "file_id", id.Hex())
		c.Status(http.StatusOK)
	case errors.Is(err, ErrNotFound):
		c.String(http.StatusNotFound, msgNotFound)
	default:
		slog.Error("files: delete", "user_id", user.ID.Hex(), "file_id", id.Hex(), "error", err)
		c.String(http.StatusInternalServerError, msgDeleteFailed)
	}
}

// renderList shows the file list with an error message, after a failed
// upload. The list itself is reloaded so the page stays complete.
func (h *Handler) renderList(c *gin.Context, user *auth.User, status int, msg string) {
	files, err := h.svc.List(c.Request.Context(), user.ID)
	if err != nil {
		slog.Error("files: list", "user_id", user.ID.Hex(), "error", err)
	}
	h.render(c, status, files, msg)
}

// render passes exactly the data files.html and layout.html document.
func (h *Handler) render(c *gin.Context, status int, files []FileView, errMsg string) {
	user, _ := auth.CurrentUser(c)
	flash := auth.TakeFlash(c)
	if errMsg != "" {
		flash = &auth.Flash{Kind: "error", Message: errMsg}
	}
	c.HTML(status, "files.html", gin.H{
		"Title":        "Files",
		"User":         user,
		"Files":        files,
		"JustLoggedIn": auth.JustLoggedIn(c),
		"Flash":        flash,
	})
}

// renderError shows error.html with a fixed, user-facing message.
func renderError(c *gin.Context, user *auth.User, status int, msg string) {
	hdr := c.Writer.Header()
	for _, k := range []string{"Content-Disposition", "Content-Length", "Content-Type"} {
		hdr.Del(k)
	}
	c.HTML(status, "error.html", gin.H{
		"Title":   "Error",
		"User":    user,
		"Status":  status,
		"Message": msg,
	})
}
