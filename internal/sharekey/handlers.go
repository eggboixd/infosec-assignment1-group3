package sharekey

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"path"
	"strconv"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/eggboixd/infosec-assignment1-group3/internal/auth"
	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
	"github.com/eggboixd/infosec-assignment1-group3/internal/keypair"
	"github.com/eggboixd/infosec-assignment1-group3/internal/sharing"
)

const (
	keyTemplate    = "sharekey.html"
	sharedTemplate = "shared.html"
	msgNotFound    = "We couldn't find that shared data."
	msgNoKey       = "There is no share key for that request. It's made when you approve a request and deleted when access ends."
	msgExpired     = "This access has expired."
	msgNotActive   = "This access isn't active: it hasn't been approved, or it was revoked."
	msgBadAlg      = "Unknown algorithm. Choose AES-256, DES or RC4."
	msgIntegrity   = "The shared data failed its integrity check, so it wasn't shown."
	msgServer      = "Something went wrong on our side. Please try again."
	msgCheckForm   = "Paste the share key and type your password."
	msgBadKey      = "That key doesn't open this request. Paste the whole key the owner sent you for this request."
	msgWrongPass   = "Wrong password."
	msgRateLimited = "Too many attempts. Try again in 15 minutes."
	msgNoKeys      = "You have no key pair yet. Log out and in again to create it."
)

// accessChecker says whether a requester may open a request's data right
// now. sharing.Service implements it.
type accessChecker interface {
	Active(ctx context.Context, requestID, requesterID bson.ObjectID) (*sharing.Request, error)
}

// Handler serves the owner's share-key page and the requester's import and
// open pages.
type Handler struct {
	svc    *Service
	access accessChecker
}

// NewHandler returns a Handler. access is the share-request service.
func NewHandler(svc *Service, access accessChecker) *Handler {
	return &Handler{svc: svc, access: access}
}

type importForm struct {
	Key      string `form:"key" binding:"required,max=1024"`
	Password string `form:"password" binding:"required,max=128"`
}

// showKey handles GET /shares/requests/:id/key: the owner copies the
// encrypted share key from here into WhatsApp or email.
func (h *Handler) showKey(c *gin.Context) {
	user := mustUser(c)
	id, ok := h.requestID(c, user)
	if !ok {
		return
	}
	kv, err := h.svc.EncryptedKey(c.Request.Context(), user.ID, id)
	switch {
	case errors.Is(err, ErrNotFound):
		renderError(c, user, http.StatusNotFound, msgNoKey)
		return
	case err != nil:
		slog.Error("sharekey: load key", "user_id", user.ID.Hex(), "request_id", id.Hex(), "error", err)
		renderError(c, user, http.StatusInternalServerError, msgServer)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.HTML(http.StatusOK, keyTemplate, gin.H{
		"Title":        "Share key",
		"User":         user,
		"JustLoggedIn": auth.JustLoggedIn(c),
		"Key":          kv,
	})
}

// showData handles GET /shares/requests/:id/data?alg=aes|des|rc4: the import
// form until the key is imported, then the owner's data.
func (h *Handler) showData(c *gin.Context) {
	user := mustUser(c)
	req, ok := h.active(c, user)
	if !ok {
		return
	}
	alg := crypto.AES
	if q := c.Query("alg"); q != "" {
		a, err := crypto.ParseAlgorithm(q)
		if err != nil {
			renderError(c, user, http.StatusBadRequest, msgBadAlg)
			return
		}
		alg = a
	}
	ctx := c.Request.Context()
	shared, err := h.svc.Open(ctx, req, alg)
	switch {
	case errors.Is(err, ErrNotImported):
		h.renderShared(c, user, http.StatusOK, req, nil, alg, nil)
	case err == nil:
		h.renderShared(c, user, http.StatusOK, req, shared, alg, nil)
	default:
		h.fail(c, user, req, err)
	}
}

// importKey handles POST /shares/requests/:id/import. Never log the form.
func (h *Handler) importKey(c *gin.Context) {
	user := mustUser(c)
	req, ok := h.active(c, user)
	if !ok {
		return
	}
	var f importForm
	if err := c.ShouldBind(&f); err != nil {
		h.renderShared(c, user, http.StatusBadRequest, req, nil, crypto.AES, errFlash(msgCheckForm))
		return
	}
	err := h.svc.Import(c.Request.Context(), req, f.Password, f.Key)
	if err == nil {
		c.Redirect(http.StatusSeeOther, "/shares/requests/"+req.ID.Hex()+"/data")
		return
	}
	for _, r := range []struct {
		err    error
		status int
		msg    string
	}{
		{ErrBadKey, http.StatusUnprocessableEntity, msgBadKey},
		{ErrWrongPassword, http.StatusUnauthorized, msgWrongPass},
		{ErrRateLimited, http.StatusTooManyRequests, msgRateLimited},
		{keypair.ErrNoKeys, http.StatusConflict, msgNoKeys},
	} {
		if errors.Is(err, r.err) {
			slog.Warn("sharekey: import refused", "request_id", req.ID.Hex(), "requester_id", user.ID.Hex(), "error", err)
			h.renderShared(c, user, r.status, req, nil, crypto.AES, errFlash(r.msg))
			return
		}
	}
	h.fail(c, user, req, err)
}

// download handles GET /shares/requests/:id/files/:file?alg=aes|des|rc4.
// Headers are set in start but only sent with the first plaintext byte, which
// is written after the HMAC has verified.
func (h *Handler) download(c *gin.Context) {
	user := mustUser(c)
	req, ok := h.active(c, user)
	if !ok {
		return
	}
	fileID, err := bson.ObjectIDFromHex(c.Param("file"))
	if err != nil {
		renderError(c, user, http.StatusNotFound, msgNotFound)
		return
	}
	alg, err := crypto.ParseAlgorithm(c.Query("alg"))
	if err != nil {
		renderError(c, user, http.StatusBadRequest, msgBadAlg)
		return
	}
	err = h.svc.Download(c.Request.Context(), req, fileID, alg, func(d DownloadHeader) io.Writer {
		hdr := c.Writer.Header()
		hdr.Set("Content-Type", d.MIMEType)
		hdr.Set("Content-Length", strconv.FormatInt(d.Size, 10))
		hdr.Set("Content-Disposition", contentDisposition(d.Name))
		hdr.Set("Cache-Control", "no-store")
		return c.Writer
	})
	switch {
	case err == nil:
	case c.Writer.Written():
		slog.Error("sharekey: download aborted mid-stream", "request_id", req.ID.Hex(), "file_id", fileID.Hex(), "alg", alg, "error", err)
		c.Abort()
	case errors.Is(err, ErrNotImported):
		c.Redirect(http.StatusSeeOther, "/shares/requests/"+req.ID.Hex()+"/data")
	default:
		h.fail(c, user, req, err)
	}
}

// active parses :id and checks with sharing that the logged-in user may open
// it right now. Every handler that opens shared data starts here.
func (h *Handler) active(c *gin.Context, user *auth.User) (*sharing.Request, bool) {
	id, ok := h.requestID(c, user)
	if !ok {
		return nil, false
	}
	req, err := h.access.Active(c.Request.Context(), id, user.ID)
	switch {
	case err == nil:
		return req, true
	case errors.Is(err, sharing.ErrNotFound):
		renderError(c, user, http.StatusNotFound, msgNotFound)
	case errors.Is(err, sharing.ErrExpired):
		renderError(c, user, http.StatusForbidden, msgExpired)
	case errors.Is(err, sharing.ErrNotApproved):
		renderError(c, user, http.StatusForbidden, msgNotActive)
	default:
		slog.Error("sharekey: check access", "user_id", user.ID.Hex(), "request_id", id.Hex(), "error", err)
		renderError(c, user, http.StatusInternalServerError, msgServer)
	}
	return nil, false
}

// fail renders the error page for a service error.
func (h *Handler) fail(c *gin.Context, user *auth.User, req *sharing.Request, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		renderError(c, user, http.StatusNotFound, msgNotFound)
	case errors.Is(err, crypto.ErrAuthentication), errors.Is(err, ErrCorrupt):
		slog.Warn("sharekey: integrity check failed", "request_id", req.ID.Hex(), "requester_id", user.ID.Hex(), "error", err)
		renderError(c, user, http.StatusUnprocessableEntity, msgIntegrity)
	default:
		slog.Error("sharekey: open shared data", "request_id", req.ID.Hex(), "requester_id", user.ID.Hex(), "error", err)
		renderError(c, user, http.StatusInternalServerError, msgServer)
	}
}

// requestID parses :id. An invalid ID is the same 404 as an unknown one.
func (h *Handler) requestID(c *gin.Context, user *auth.User) (bson.ObjectID, bool) {
	id, err := bson.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		renderError(c, user, http.StatusNotFound, msgNotFound)
		return bson.ObjectID{}, false
	}
	return id, true
}

// renderShared shows shared.html: the import form when shared is nil.
func (h *Handler) renderShared(c *gin.Context, user *auth.User, status int, req *sharing.Request, shared *Shared, alg crypto.Algorithm, flash *auth.Flash) {
	c.Header("Cache-Control", "no-store")
	c.HTML(status, sharedTemplate, gin.H{
		"Title":        "Shared data",
		"User":         user,
		"JustLoggedIn": auth.JustLoggedIn(c),
		"Flash":        flash,
		"Request":      req,
		"Shared":       shared,
		"Alg":          string(alg),
	})
}

// renderError shows error.html with a fixed message, dropping any download
// headers already set.
func renderError(c *gin.Context, user *auth.User, status int, msg string) {
	hdr := c.Writer.Header()
	for _, k := range []string{"Content-Disposition", "Content-Length", "Content-Type"} {
		hdr.Del(k)
	}
	c.HTML(status, "error.html", gin.H{"Title": "Error", "User": user, "Status": status, "Message": msg})
}

// contentDisposition marks the response as an attachment, the same way
// files does, so an uploaded HTML or PDF can't run in the app's origin.
func contentDisposition(name string) string {
	if v := mime.FormatMediaType("attachment", map[string]string{"filename": name}); v != "" {
		return v
	}
	return mime.FormatMediaType("attachment", map[string]string{"filename": "download" + path.Ext(name)})
}

func errFlash(msg string) *auth.Flash { return &auth.Flash{Kind: "error", Message: msg} }

// mustUser returns the logged-in user. RequireAuth guards every route here.
func mustUser(c *gin.Context) *auth.User {
	if u, ok := auth.CurrentUser(c); ok {
		return u
	}
	return &auth.User{}
}
