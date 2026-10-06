package web

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/eggboixd/infosec-assignment1-group3/internal/auth"
	"github.com/eggboixd/infosec-assignment1-group3/internal/benchmark"
	"github.com/eggboixd/infosec-assignment1-group3/internal/files"
	"github.com/eggboixd/infosec-assignment1-group3/internal/profile"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// authProbe wraps auth.RequireAuth and records the requests it handled and
// whether a user was available to the handlers.
type authProbe struct {
	hits     int
	sawUser  bool
	original gin.HandlerFunc
}

func (p *authProbe) middleware(c *gin.Context) {
	p.hits++
	p.original(c)
	_, p.sawUser = auth.CurrentUser(c)
}

// newTestEngine builds the real engine with stub handlers. The stubs never
// touch their services, so nil services are safe.
func newTestEngine(t *testing.T, maxBody int64) (*gin.Engine, *authProbe) {
	t.Helper()
	probe := &authProbe{original: auth.RequireAuth()}
	r, err := NewEngine(Options{
		MaxBodyBytes: maxBody,
		HealthChecks: []HealthCheck{{Name: "fake", Pinger: fakePinger{}}},
		Features: []RouteRegistrar{
			auth.NewHandler(nil),
			profile.NewHandler(nil),
			files.NewHandler(nil),
			benchmark.NewHandler(nil),
		},
		RequireAuth: probe.middleware,
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return r, probe
}

func TestStubRoutesReturnNotImplemented(t *testing.T) {
	tests := []struct {
		method    string
		path      string
		protected bool
	}{
		{http.MethodGet, "/register", false},
		{http.MethodPost, "/register", false},
		{http.MethodGet, "/login", false},
		{http.MethodPost, "/login", false},
		{http.MethodPost, "/logout", true},
		{http.MethodGet, "/profile", true},
		{http.MethodPost, "/profile", true},
		{http.MethodGet, "/files", true},
		{http.MethodPost, "/files", true},
		{http.MethodGet, "/files/0123456789abcdef01234567/download?alg=aes", true},
		{http.MethodDelete, "/files/0123456789abcdef01234567", true},
		{http.MethodGet, "/benchmarks", true},
		{http.MethodGet, "/benchmarks/export.csv", true},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			r, probe := newTestEngine(t, 1<<20)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(tt.method, tt.path, nil))

			if w.Code != http.StatusNotImplemented {
				t.Errorf("status = %d, want %d", w.Code, http.StatusNotImplemented)
			}
			wantHits := 0
			if tt.protected {
				wantHits = 1
			}
			if probe.hits != wantHits {
				t.Errorf("RequireAuth ran %d times, want %d", probe.hits, wantHits)
			}
			if tt.protected && !probe.sawUser {
				t.Error("RequireAuth did not provide a current user")
			}
		})
	}
}

func TestRootRedirectsToFiles(t *testing.T) {
	r, probe := newTestEngine(t, 1<<20)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/files" {
		t.Errorf("got %d Location=%q, want 303 /files", w.Code, w.Header().Get("Location"))
	}
	if probe.hits != 1 {
		t.Errorf("RequireAuth ran %d times, want 1", probe.hits)
	}
}

func TestDefaultRequireAuthIsUsed(t *testing.T) {
	r, err := NewEngine(Options{MaxBodyBytes: 1024, Features: []RouteRegistrar{files.NewHandler(nil)}})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/files", nil))
	if w.Code != http.StatusNotImplemented {
		t.Errorf("status = %d, want 501", w.Code)
	}
}

func TestMaxBodySize(t *testing.T) {
	r, _ := newTestEngine(t, 16)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(make([]byte, 17))))
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized declared body: status = %d, want 413", w.Code)
	}

	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(make([]byte, 16))))
	if w.Code != http.StatusNotImplemented {
		t.Errorf("body at limit: status = %d, want 501", w.Code)
	}
}

func TestMaxBodySizeCapsUndeclaredLength(t *testing.T) {
	var readErr error
	r := gin.New()
	r.Use(maxBodySize(8))
	r.POST("/", func(c *gin.Context) {
		_, readErr = c.Request.Body.Read(make([]byte, 64))
		c.Status(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("x", 64)))
	req.ContentLength = -1 // as for a chunked upload
	r.ServeHTTP(httptest.NewRecorder(), req)

	var maxErr *http.MaxBytesError
	if !errors.As(readErr, &maxErr) {
		t.Errorf("read error = %v, want *http.MaxBytesError", readErr)
	}
}

func TestSecurityHeaders(t *testing.T) {
	r, _ := newTestEngine(t, 1024)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/login", nil))
	for _, h := range []string{"Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy"} {
		if w.Header().Get(h) == "" {
			t.Errorf("missing header %s", h)
		}
	}
}

func TestTemplatesRender(t *testing.T) {
	tmpl, err := loadTemplates()
	if err != nil {
		t.Fatalf("loadTemplates: %v", err)
	}
	data := map[string]any{"Title": "Test", "User": &auth.User{Username: "u"}}
	for _, name := range []string{"login.html", "register.html", "profile.html", "files.html", "benchmarks.html"} {
		var buf bytes.Buffer
		if err := tmpl.ExecuteTemplate(&buf, name, data); err != nil {
			t.Errorf("execute %s: %v", name, err)
			continue
		}
		if !strings.Contains(buf.String(), "htmx.min.js") || !strings.Contains(buf.String(), "</html>") {
			t.Errorf("%s is missing the layout", name)
		}
	}
}

func TestStaticAssetsServed(t *testing.T) {
	r, _ := newTestEngine(t, 1024)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/static/style.css", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}
