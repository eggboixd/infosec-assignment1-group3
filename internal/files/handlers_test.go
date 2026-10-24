package files

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/eggboixd/infosec-assignment1-group3/internal/auth"
	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
	"github.com/eggboixd/infosec-assignment1-group3/internal/web"
)

// httpRig is a testRig behind the real engine, logged in as user.
type httpRig struct {
	*testRig
	engine *gin.Engine
	user   *auth.User
}

func newHTTPRig(t *testing.T) *httpRig {
	t.Helper()
	r := &httpRig{testRig: newTestRig(t), user: &auth.User{ID: owner, Username: "budi"}}
	engine, err := web.NewEngine(web.Options{
		Mode:         gin.TestMode,
		MaxBodyBytes: 64 << 20,
		Features:     []web.RouteRegistrar{NewHandler(r.svc)},
		RequireAuth:  func(c *gin.Context) { auth.SetCurrentUser(c, r.user) },
	})
	if err != nil {
		t.Fatal(err)
	}
	r.engine = engine
	return r
}

func (r *httpRig) do(req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	r.engine.ServeHTTP(rec, req)
	return rec
}

// part is one multipart field, sent in order.
type part struct {
	name, filename string
	data           []byte
}

func multipartRequest(t *testing.T, parts ...part) *http.Request {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for _, p := range parts {
		h := textproto.MIMEHeader{}
		if p.filename != "" {
			// Escaped the way browsers and multipart.CreateFormFile do.
			fn := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(p.filename)
			h.Set("Content-Disposition", `form-data; name="`+p.name+`"; filename="`+fn+`"`)
			// A lying browser type must not matter.
			h.Set("Content-Type", "text/html")
		} else {
			h.Set("Content-Disposition", `form-data; name="`+p.name+`"`)
		}
		w, err := mw.CreatePart(h)
		if err != nil {
			t.Fatal(err)
		}
		w.Write(p.data)
	}
	mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/files", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return req
}

func (r *httpRig) upload(t *testing.T, kind, filename string, data []byte) *httptest.ResponseRecorder {
	t.Helper()
	return r.do(multipartRequest(t, part{name: "kind", data: []byte(kind)}, part{name: "file", filename: filename, data: data}))
}

func (r *httpRig) onlyFile(t *testing.T) FileRecord {
	t.Helper()
	if r.meta.Len() != 1 {
		t.Fatalf("%d records stored, want 1", r.meta.Len())
	}
	for _, rec := range r.meta.recs {
		return rec
	}
	panic("unreachable")
}

func TestHTTPUploadListDownloadDelete(t *testing.T) {
	r := newHTTPRig(t)
	pdf := sample(t, "sample.pdf")

	empty := r.do(httptest.NewRequest(http.MethodGet, "/files", nil))
	if empty.Code != http.StatusOK || !strings.Contains(empty.Body.String(), "Nothing stored yet") {
		t.Fatalf("empty list: %d", empty.Code)
	}

	up := r.upload(t, "document", "Laporan Akhir.pdf", pdf)
	if up.Code != http.StatusSeeOther || up.Header().Get("Location") != "/files" {
		t.Fatalf("upload: %d %q, want 303 /files", up.Code, up.Header().Get("Location"))
	}
	rec := r.onlyFile(t)
	if rec.MIMEType != "application/pdf" {
		t.Errorf("MIME = %q; the browser's text/html must be ignored", rec.MIMEType)
	}

	list := r.do(httptest.NewRequest(http.MethodGet, "/files", nil)).Body.String()
	for _, want := range []string{"Laporan Akhir.pdf", "Hi, budi!", "/files/" + rec.ID.Hex() + "/download?alg=des", `hx-delete="/files/` + rec.ID.Hex()} {
		if !strings.Contains(list, want) {
			t.Errorf("list page is missing %q", want)
		}
	}

	for _, alg := range crypto.All() {
		dl := r.do(httptest.NewRequest(http.MethodGet, "/files/"+rec.ID.Hex()+"/download?alg="+string(alg), nil))
		if dl.Code != http.StatusOK || !bytes.Equal(dl.Body.Bytes(), pdf) {
			t.Fatalf("%s download: %d, %d bytes", alg, dl.Code, dl.Body.Len())
		}
		h := dl.Header()
		if h.Get("Content-Type") != "application/pdf" || h.Get("Content-Disposition") != `attachment; filename="Laporan Akhir.pdf"` ||
			h.Get("Content-Length") != "701" || h.Get("Cache-Control") != "no-store" || h.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s download headers: %v", alg, h)
		}
	}

	del := r.do(httptest.NewRequest(http.MethodDelete, "/files/"+rec.ID.Hex(), nil))
	if del.Code != http.StatusOK || del.Body.Len() != 0 {
		t.Errorf("delete: %d with %d bytes, want 200 empty", del.Code, del.Body.Len())
	}
	if r.objects.Len() != 0 || r.meta.Len() != 0 {
		t.Error("delete left data behind")
	}
	if again := r.do(httptest.NewRequest(http.MethodDelete, "/files/"+rec.ID.Hex(), nil)); again.Code != http.StatusNotFound {
		t.Errorf("second delete: %d, want 404", again.Code)
	}
}

func TestHTTPUploadErrors(t *testing.T) {
	pdf := sample(t, "sample.pdf")
	tests := []struct {
		name  string
		parts []part
		want  int
		msg   string
	}{
		{"unknown kind", []part{{name: "kind", data: []byte("audio")}, {name: "file", filename: "a.pdf", data: pdf}}, http.StatusBadRequest, "Unknown file kind"},
		{"file before kind", []part{{name: "file", filename: "a.pdf", data: pdf}, {name: "kind", data: []byte("document")}}, http.StatusBadRequest, "form was incomplete"},
		{"no file", []part{{name: "kind", data: []byte("document")}}, http.StatusBadRequest, "form was incomplete"},
		{"file part without filename", []part{{name: "kind", data: []byte("document")}, {name: "file", data: pdf}}, http.StatusBadRequest, "form was incomplete"},
		{"wrong type for kind", []part{{name: "kind", data: []byte("idcard")}, {name: "file", filename: "a.pdf", data: pdf}}, http.StatusUnsupportedMediaType, "isn&#39;t allowed"},
		{"empty file", []part{{name: "kind", data: []byte("document")}, {name: "file", filename: "a.pdf"}}, http.StatusBadRequest, "That file is empty"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newHTTPRig(t)
			rec := r.do(multipartRequest(t, tt.parts...))
			if rec.Code != tt.want || !strings.Contains(rec.Body.String(), tt.msg) {
				t.Errorf("got %d, want %d with %q", rec.Code, tt.want, tt.msg)
			}
			if !strings.Contains(rec.Body.String(), "flash--error") {
				t.Error("the error is not shown as a flash message")
			}
			if r.objects.Len() != 0 || r.meta.Len() != 0 {
				t.Error("a failed upload left data behind")
			}
		})
	}

	t.Run("not multipart", func(t *testing.T) {
		r := newHTTPRig(t)
		req := httptest.NewRequest(http.MethodPost, "/files", strings.NewReader("kind=document"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if rec := r.do(req); rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", rec.Code)
		}
	})
}

func TestHTTPUploadTooLarge(t *testing.T) {
	png := sample(t, "ktp-fake.png")
	setMaxSize(t, KindIDCard, int64(len(png)-1))
	r := newHTTPRig(t)
	rec := r.upload(t, "idcard", "card.png", png)
	if rec.Code != http.StatusRequestEntityTooLarge || !strings.Contains(rec.Body.String(), "too large") {
		t.Errorf("got %d, want 413 'too large'", rec.Code)
	}
	if r.objects.Len() != 0 || r.meta.Len() != 0 {
		t.Error("an oversized upload left data behind")
	}
}

func TestHTTPUploadClientDisconnects(t *testing.T) {
	r := newHTTPRig(t)
	full := multipartRequest(t, part{name: "kind", data: []byte("video")}, part{name: "file", filename: "clip.mp4", data: append(sample(t, "sample.mp4"), make([]byte, 1<<20)...)})
	body, err := io.ReadAll(full.Body)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// The connection drops halfway through the body.
	req := full.WithContext(ctx)
	req.Body = io.NopCloser(&failingReader{data: body[:len(body)/2], err: io.ErrUnexpectedEOF, onErr: cancel})

	rec := r.do(req)
	if rec.Body.Len() != 0 {
		t.Errorf("rendered %d bytes for a client that is gone", rec.Body.Len())
	}
	if r.objects.Len() != 0 || r.meta.Len() != 0 || r.objects.Leaked() != 0 {
		t.Error("an interrupted upload left data behind")
	}
}

func TestHTTPDownloadErrors(t *testing.T) {
	r := newHTTPRig(t)
	r.upload(t, "document", "a.pdf", sample(t, "sample.pdf"))
	rec := r.onlyFile(t)
	base := "/files/" + rec.ID.Hex() + "/download"

	tests := []struct {
		name, target string
		want         int
	}{
		{"missing alg", base, http.StatusBadRequest},
		{"unknown alg", base + "?alg=rot13", http.StatusBadRequest},
		{"bad id", "/files/not-an-id/download?alg=aes", http.StatusNotFound},
		{"unknown id", "/files/" + bson.NewObjectID().Hex() + "/download?alg=aes", http.StatusNotFound},
	}
	for _, tt := range tests {
		if got := r.do(httptest.NewRequest(http.MethodGet, tt.target, nil)); got.Code != tt.want {
			t.Errorf("%s: status = %d, want %d", tt.name, got.Code, tt.want)
		}
	}

	// Another user gets 404, the same as for a file that doesn't exist.
	r.user = &auth.User{ID: bson.NewObjectID(), Username: "eve"}
	if got := r.do(httptest.NewRequest(http.MethodGet, base+"?alg=aes", nil)); got.Code != http.StatusNotFound {
		t.Errorf("another user's file: status = %d, want 404", got.Code)
	}
	if got := r.do(httptest.NewRequest(http.MethodDelete, "/files/"+rec.ID.Hex(), nil)); got.Code != http.StatusNotFound {
		t.Errorf("deleting another user's file: status = %d, want 404", got.Code)
	}
}

// A tampered copy is refused before any plaintext or file headers go out.
func TestHTTPDownloadTampered(t *testing.T) {
	r := newHTTPRig(t)
	r.upload(t, "document", "a.pdf", sample(t, "sample.pdf"))
	rec := r.onlyFile(t)
	r.objects.Tamper(rec.Variants[crypto.DES].ObjectKey)

	got := r.do(httptest.NewRequest(http.MethodGet, "/files/"+rec.ID.Hex()+"/download?alg=des", nil))
	if got.Code != http.StatusUnprocessableEntity || !strings.Contains(got.Body.String(), "failed its integrity check") {
		t.Errorf("status = %d, want 422 with the integrity message", got.Code)
	}
	if cd := got.Header().Get("Content-Disposition"); cd != "" {
		t.Errorf("Content-Disposition = %q, want none", cd)
	}
	if ct := got.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want the HTML error page", ct)
	}
	if strings.Contains(got.Body.String(), "%PDF") {
		t.Error("plaintext was sent")
	}
	if ok := r.do(httptest.NewRequest(http.MethodGet, "/files/"+rec.ID.Hex()+"/download?alg=aes", nil)); ok.Code != http.StatusOK {
		t.Errorf("untouched AES copy: status = %d, want 200", ok.Code)
	}
}

// Filenames come from the uploader, so they are escaped in the page and
// can't inject headers in the download.
func TestHTTPHostileFilename(t *testing.T) {
	r := newHTTPRig(t)
	r.upload(t, "document", `<img src=x onerror=alert(1)>".pdf`, sample(t, "sample.pdf"))
	rec := r.onlyFile(t)

	list := r.do(httptest.NewRequest(http.MethodGet, "/files", nil)).Body.String()
	if strings.Contains(list, "<img src=x") || !strings.Contains(list, "&lt;img src=x") {
		t.Error("the filename is not HTML-escaped in the list")
	}
	dl := r.do(httptest.NewRequest(http.MethodGet, "/files/"+rec.ID.Hex()+"/download?alg=aes", nil))
	if cd := dl.Header().Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment;") || strings.ContainsAny(cd, "\r\n") {
		t.Errorf("Content-Disposition = %q", cd)
	}
}

func TestHTTPDownloadRecordsBenchmark(t *testing.T) {
	r := newHTTPRig(t)
	r.upload(t, "document", "a.pdf", sample(t, "sample.pdf"))
	rec := r.onlyFile(t)
	r.do(httptest.NewRequest(http.MethodGet, "/files/"+rec.ID.Hex()+"/download?alg=aes", nil))

	var ops []string
	for _, b := range r.bench.Records() {
		ops = append(ops, string(b.Algorithm)+":"+string(b.Operation))
	}
	if got := strings.Join(ops[3:], ","); got != "aes:decrypt,aes:download" {
		t.Errorf("records after the upload = %s, want aes:decrypt,aes:download", got)
	}
}
