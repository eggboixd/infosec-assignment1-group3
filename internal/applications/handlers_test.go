package applications

// These tests drive the real Gin engine and the embedded templates from
// internal/web, with the in-memory fakes of service_test.go. web does not
// import this package outside its tests, so there is no import cycle.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/eggboixd/infosec-assignment1-group3/internal/auth"
	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
	"github.com/eggboixd/infosec-assignment1-group3/internal/web"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// engine serves f's handler. With user nil every request is logged out.
func (f fixture) engine(t *testing.T, user *auth.User) *gin.Engine {
	t.Helper()
	var session gin.HandlerFunc
	if user != nil {
		session = func(c *gin.Context) { auth.SetCurrentUser(c, user) }
	}
	r, err := web.NewEngine(web.Options{
		MaxBodyBytes: 1 << 20,
		Session:      session,
		Features:     []web.RouteRegistrar{NewHandler(f.svc)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func serve(r *gin.Engine, method, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(method, path, nil))
	return w
}

func expect(t *testing.T, w *httptest.ResponseRecorder, code int, body ...string) {
	t.Helper()
	if w.Code != code {
		t.Errorf("status %d, want %d", w.Code, code)
	}
	for _, s := range body {
		if !strings.Contains(w.Body.String(), s) {
			t.Errorf("body is missing %q", s)
		}
	}
}

func TestHomePage(t *testing.T) {
	f := newFixture(t)
	w := serve(f.engine(t, nil), http.MethodGet, "/")
	expect(t, w, http.StatusOK, "Beasiswa Prestasi Nusantara", "Beasiswa Bakti Keluarga", `href="/register"`)
	if strings.Contains(w.Body.String(), "badge--") {
		t.Error("a visitor sees a status badge")
	}

	id := f.ready()
	if err := f.svc.Submit(context.Background(), id, "bakti-keluarga"); err != nil {
		t.Fatal(err)
	}
	w = serve(f.engine(t, &auth.User{ID: id, Username: "alice"}), http.MethodGet, "/")
	expect(t, w, http.StatusOK, "badge--submitted", "Ready to submit", "alice")
}

func TestDetailPage(t *testing.T) {
	f := newFixture(t)
	r := f.engine(t, nil)
	expect(t, serve(r, http.MethodGet, "/scholarships/bakti-keluarga"), http.StatusOK, "Beasiswa Bakti Keluarga", "Log in to apply")
	expect(t, serve(r, http.MethodGet, "/scholarships/lpdp"), http.StatusNotFound, "find that scholarship")
}

func TestApplyRequiresLogin(t *testing.T) {
	f := newFixture(t)
	w := serve(f.engine(t, nil), http.MethodPost, "/scholarships/bakti-keluarga/apply")
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
		t.Errorf("got %d Location=%q, want 303 /login", w.Code, w.Header().Get("Location"))
	}
	if len(f.store.docs) != 0 {
		t.Error("an application was stored without login")
	}
}

func TestApply(t *testing.T) {
	f := newFixture(t)
	id := f.ready()
	r := f.engine(t, &auth.User{ID: id, Username: "alice"})

	w := serve(r, http.MethodPost, "/scholarships/bakti-keluarga/apply")
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/scholarships/bakti-keluarga" {
		t.Fatalf("got %d Location=%q, want 303 to the detail page", w.Code, w.Header().Get("Location"))
	}
	expect(t, serve(r, http.MethodGet, "/scholarships/bakti-keluarga"), http.StatusOK, "badge--submitted", "application was received")
	expect(t, serve(r, http.MethodPost, "/scholarships/bakti-keluarga/apply"), http.StatusConflict, "already applied")
	expect(t, serve(r, http.MethodPost, "/scholarships/nope/apply"), http.StatusNotFound)
	if n := len(f.store.docs); n != 1 {
		t.Errorf("%d applications stored, want 1", n)
	}
}

func TestApplyNotReady(t *testing.T) {
	f := newFixture(t)
	id := bson.NewObjectID()
	f.docs[id] = allDocuments()
	r := f.engine(t, &auth.User{ID: id, Username: "bob"})
	expect(t, serve(r, http.MethodPost, "/scholarships/prestasi-nusantara/apply"), http.StatusUnprocessableEntity, "not complete yet", "btn--locked")
	if len(f.store.docs) != 0 {
		t.Error("an incomplete application was stored")
	}
}

func TestTamperedApplicationShowsIntegrityError(t *testing.T) {
	f := newFixture(t)
	id := f.ready()
	if err := f.svc.Submit(context.Background(), id, "bakti-keluarga"); err != nil {
		t.Fatal(err)
	}
	f.store.edit(t, 0, func(a *Application) {
		s := a.Scholarship[crypto.AES]
		s.Ciphertext[len(s.Ciphertext)-1] ^= 0x80
		a.Scholarship[crypto.AES] = s
	})
	r := f.engine(t, &auth.User{ID: id, Username: "alice"})
	for _, path := range []string{"/", "/scholarships/bakti-keluarga"} {
		w := serve(r, http.MethodGet, path)
		expect(t, w, http.StatusUnprocessableEntity, "integrity check")
		if strings.Contains(w.Body.String(), "badge--submitted") {
			t.Errorf("%s still shows the tampered application as submitted", path)
		}
	}
}
