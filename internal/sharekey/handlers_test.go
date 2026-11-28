package sharekey

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/eggboixd/infosec-assignment1-group3/internal/auth"
	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
	"github.com/eggboixd/infosec-assignment1-group3/internal/sharing"
	"github.com/eggboixd/infosec-assignment1-group3/internal/web"
)

// fakeAccess answers Active from a fixed request and error.
type fakeAccess struct {
	req *sharing.Request
	err error
}

func (a *fakeAccess) Active(_ context.Context, id, requesterID bson.ObjectID) (*sharing.Request, error) {
	if a.err != nil {
		return nil, a.err
	}
	if id != a.req.ID || requesterID != a.req.RequesterID {
		return nil, sharing.ErrNotFound
	}
	return a.req, nil
}

type handlerEnv struct {
	*env
	engine *gin.Engine
	access *fakeAccess
	req    *sharing.Request
	as     *auth.User
}

func newHandlerEnv(t *testing.T) *handlerEnv {
	t.Helper()
	h := &handlerEnv{env: newEnv(t)}
	h.req = h.grant(t, h.alice)
	h.req.OwnerName = "budi"
	h.access = &fakeAccess{req: h.req}
	h.as = &auth.User{ID: h.alice.id, Username: "alice"}
	engine, err := web.NewEngine(web.Options{
		Mode:         gin.TestMode,
		MaxBodyBytes: 1 << 20,
		Features:     []web.RouteRegistrar{NewHandler(h.svc, h.access)},
		RequireAuth:  func(c *gin.Context) { auth.SetCurrentUser(c, h.as) },
	})
	if err != nil {
		t.Fatal(err)
	}
	h.engine = engine
	return h
}

func (h *handlerEnv) do(method, target string, form url.Values) *httptest.ResponseRecorder {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	r := httptest.NewRequest(method, target, body)
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	rec := httptest.NewRecorder()
	h.engine.ServeHTTP(rec, r)
	return rec
}

func check(t *testing.T, rec *httptest.ResponseRecorder, status int, want ...string) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status = %d, want %d; body: %.300s", rec.Code, status, rec.Body.String())
	}
	for _, w := range want {
		if !strings.Contains(rec.Body.String(), w) {
			t.Errorf("body lacks %q", w)
		}
	}
}

func TestOwnerKeyPage(t *testing.T) {
	h := newHandlerEnv(t)
	base := "/shares/requests/" + h.req.ID.Hex()
	key := h.sentKey(t, h.req)

	h.as = &auth.User{ID: h.owner.id, Username: "budi"}
	rec := h.do("GET", base+"/key", nil)
	check(t, rec, 200, htmlText(key), h.store.raw(h.req.ID).RequesterFingerprint, "hasn't imported it yet")
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("key page is cacheable")
	}

	h.as = &auth.User{ID: h.alice.id, Username: "alice"}
	check(t, h.do("GET", base+"/key", nil), 404)
	check(t, h.do("GET", "/shares/requests/nope/key", nil), 404)
}

func TestRequesterFlow(t *testing.T) {
	h := newHandlerEnv(t)
	base := "/shares/requests/" + h.req.ID.Hex()
	key := h.sentKey(t, h.req)

	check(t, h.do("GET", base+"/data", nil), 200, `action="`+base+`/import"`, `name="password"`)
	check(t, h.do("POST", base+"/import", url.Values{"key": {key}, "password": {"wrong"}}), 401, "Wrong password.")
	check(t, h.do("POST", base+"/import", url.Values{"key": {"AAAA"}, "password": {h.alice.password}}), 422, "doesn&#39;t open this request")
	check(t, h.do("POST", base+"/import", url.Values{"password": {h.alice.password}}), 400)

	rec := h.do("POST", base+"/import", url.Values{"key": {key}, "password": {h.alice.password}})
	if rec.Code != 303 || rec.Header().Get("Location") != base+"/data" {
		t.Fatalf("import: %d to %q, want 303 to the data page", rec.Code, rec.Header().Get("Location"))
	}

	check(t, h.do("GET", base+"/data?alg=des", nil), 200, h.data.FullName, h.data.NIK, "ktp.png", "?alg=des")
	check(t, h.do("GET", base+"/data?alg=xyz", nil), 400)

	f := h.files[h.owner.id][0]
	rec = h.do("GET", base+"/files/"+f.ID.Hex()+"?alg=rc4", nil)
	check(t, rec, 200)
	if rec.Body.String() != string(h.plain[f.ID]) {
		t.Error("downloaded file differs from the original")
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment") || !strings.Contains(cd, "ktp.png") {
		t.Errorf("Content-Disposition = %q", cd)
	}
	check(t, h.do("GET", base+"/files/"+bson.NewObjectID().Hex()+"?alg=aes", nil), 404)

	// A changed object fails before any plaintext is sent.
	key0 := f.Variants[crypto.AES].ObjectKey
	h.objects[key0] = append([]byte{h.objects[key0][0] ^ 1}, h.objects[key0][1:]...)
	check(t, h.do("GET", base+"/files/"+f.ID.Hex()+"?alg=aes", nil), 422, "integrity check")
}

// Every route that opens shared data asks sharing first.
func TestAccessChecked(t *testing.T) {
	h := newHandlerEnv(t)
	base := "/shares/requests/" + h.req.ID.Hex()
	if err := h.svc.Import(context.Background(), h.req, h.alice.password, h.sentKey(t, h.req)); err != nil {
		t.Fatal(err)
	}
	file := base + "/files/" + h.files[h.owner.id][0].ID.Hex() + "?alg=aes"

	for _, tt := range []struct {
		err    error
		status int
		msg    string
	}{
		{sharing.ErrExpired, 403, "This access has expired."},
		{sharing.ErrNotApproved, 403, "isn&#39;t active"},
		{sharing.ErrNotFound, 404, "couldn&#39;t find"},
	} {
		h.access.err = tt.err
		check(t, h.do("GET", base+"/data", nil), tt.status, tt.msg)
		check(t, h.do("GET", file, nil), tt.status, tt.msg)
		check(t, h.do("POST", base+"/import", url.Values{"key": {"x"}, "password": {"y"}}), tt.status, tt.msg)
	}

	// Another user is not the requester.
	h.access.err = nil
	h.as = &auth.User{ID: h.eve.id, Username: "eve"}
	rec := h.do("GET", base+"/data", nil)
	check(t, rec, http.StatusNotFound)
	if strings.Contains(rec.Body.String(), h.data.NIK) {
		t.Fatal("another user saw the shared NIK")
	}
}

// htmlText is s as html/template writes it in element text.
func htmlText(s string) string {
	return strings.ReplaceAll(s, "+", "&#43;")
}
