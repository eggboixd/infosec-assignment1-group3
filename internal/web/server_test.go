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
	"github.com/eggboixd/infosec-assignment1-group3/internal/profile"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// authProbe replaces auth.RequireAuth: it logs every request in as a test
// user and records the requests it handled and whether a user was available
// to the handlers.
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
// touch their services, so nil services are safe. Implemented routes (such as
// /profile, tested in internal/profile) are not requested here.
func newTestEngine(t *testing.T, maxBody int64) (*gin.Engine, *authProbe) {
	t.Helper()
	probe := &authProbe{original: func(c *gin.Context) {
		auth.SetCurrentUser(c, &auth.User{Username: "tester"})
	}}
	r, err := NewEngine(Options{
		MaxBodyBytes: maxBody,
		HealthChecks: []HealthCheck{{Name: "fake", Pinger: fakePinger{}}},
		Features: []RouteRegistrar{
			auth.NewHandler(nil, nil),
			profile.NewHandler(nil),
			stubFiles{},
			stubBenchmarks{},
		},
		RequireAuth: probe.middleware,
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return r, probe
}

// stubFiles and stubBenchmarks mount the feature routes with handlers that
// only answer 501. These tests exercise the engine's middleware (auth, body
// limits, CSRF), not the features, which are tested in their own packages.
type stubFiles struct{}

func (stubFiles) RegisterRoutes(_, protected *gin.RouterGroup) {
	stub := func(c *gin.Context) { c.Status(http.StatusNotImplemented) }
	protected.GET("/files", stub)
	protected.POST("/files", stub)
	protected.GET("/files/:id/download", stub)
	protected.DELETE("/files/:id", stub)
}

type stubBenchmarks struct{}

func (stubBenchmarks) RegisterRoutes(_, protected *gin.RouterGroup) {
	stub := func(c *gin.Context) { c.Status(http.StatusNotImplemented) }
	protected.GET("/benchmarks", stub)
	protected.GET("/benchmarks/export.csv", stub)
}

func TestStubRoutesReturnNotImplemented(t *testing.T) {
	tests := []struct {
		method    string
		path      string
		protected bool
	}{
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

func TestAuthPagesRender(t *testing.T) {
	tests := []struct {
		path   string
		action string
	}{
		{"/login", `action="/login"`},
		{"/register", `action="/register"`},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			r, probe := newTestEngine(t, 1<<20)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, tt.path, nil))

			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", w.Code)
			}
			if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
				t.Errorf("Content-Type = %q, want text/html", ct)
			}
			body := w.Body.String()
			for _, want := range []string{tt.action, "mascot--suspicious", "data-gembi-cover"} {
				if !strings.Contains(body, want) {
					t.Errorf("body is missing %q", want)
				}
			}
			if probe.hits != 0 {
				t.Errorf("RequireAuth ran %d times on a public page, want 0", probe.hits)
			}
		})
	}
}

// "/" is public: a visitor without a session sees the landing page.
func TestRootRendersLandingPage(t *testing.T) {
	r, probe := newTestEngine(t, 1<<20)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	if w.Header().Get("Content-Security-Policy") == "" {
		t.Error("missing Content-Security-Policy header")
	}
	body := w.Body.String()
	for _, want := range []string{"mascot--hello", `href="/login"`, `href="/register"`} {
		if !strings.Contains(body, want) {
			t.Errorf("body is missing %q", want)
		}
	}
	if probe.hits != 0 {
		t.Errorf("RequireAuth ran %d times on a public page, want 0", probe.hits)
	}
}

// A logged-in user skips the landing page. Options.Session stands in for
// auth.LoadSession, which main.go installs on every request.
func TestRootRedirectsLoggedInUser(t *testing.T) {
	r, err := NewEngine(Options{
		MaxBodyBytes: 1024,
		Session:      func(c *gin.Context) { auth.SetCurrentUser(c, &auth.User{Username: "tester"}) },
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/files" {
		t.Errorf("got %d Location=%q, want 303 /files", w.Code, w.Header().Get("Location"))
	}
}

// Without RequireAuth in Options the real guard is used, and with no
// session loaded it sends the browser to the login page.
func TestDefaultRequireAuthIsUsed(t *testing.T) {
	r, err := NewEngine(Options{MaxBodyBytes: 1024, Features: []RouteRegistrar{stubFiles{}}})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/files", nil))
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
		t.Errorf("got %d Location=%q, want 303 /login", w.Code, w.Header().Get("Location"))
	}
}

func TestMaxBodySize(t *testing.T) {
	r, _ := newTestEngine(t, 16)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/files", bytes.NewReader(make([]byte, 17))))
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized declared body: status = %d, want 413", w.Code)
	}

	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/files", bytes.NewReader(make([]byte, 16))))
	if w.Code != http.StatusNotImplemented {
		t.Errorf("body at limit: status = %d, want 501", w.Code)
	}
}

// Only the upload route gets the large limit; forms are capped at
// formBodyBytes so a big multipart body can't be sent to them.
func TestFormBodyLimit(t *testing.T) {
	r, _ := newTestEngine(t, 1<<30)
	tests := []struct {
		path string
		size int
		want int
	}{
		{"/login", formBodyBytes + 1, http.StatusRequestEntityTooLarge},
		{"/files/0123456789abcdef01234567", formBodyBytes + 1, http.StatusRequestEntityTooLarge},
		{"/files", formBodyBytes + 1, http.StatusNotImplemented},
	}
	for _, tt := range tests {
		method := http.MethodPost
		if tt.path != "/login" && tt.path != "/files" {
			method = http.MethodDelete
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(method, tt.path, bytes.NewReader(make([]byte, tt.size))))
		if w.Code != tt.want {
			t.Errorf("%s %s with %d bytes: status = %d, want %d", method, tt.path, tt.size, w.Code, tt.want)
		}
	}
}

func TestCrossOriginProtection(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		headers map[string]string
		want    int
	}{
		{"cross-site fetch metadata", http.MethodPost, map[string]string{"Sec-Fetch-Site": "cross-site"}, http.StatusForbidden},
		{"foreign Origin", http.MethodPost, map[string]string{"Origin": "https://evil.example"}, http.StatusForbidden},
		{"foreign Origin on DELETE", http.MethodDelete, map[string]string{"Origin": "https://evil.example"}, http.StatusForbidden},
		{"same-origin fetch metadata", http.MethodPost, map[string]string{"Sec-Fetch-Site": "same-origin"}, http.StatusNotImplemented},
		{"matching Origin", http.MethodPost, map[string]string{"Origin": "http://example.com"}, http.StatusNotImplemented},
		{"no browser headers", http.MethodPost, nil, http.StatusNotImplemented},
		{"cross-site GET is allowed", http.MethodGet, map[string]string{"Sec-Fetch-Site": "cross-site"}, http.StatusNotImplemented},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := newTestEngine(t, 1<<20)
			target := "/files"
			if tt.method == http.MethodDelete {
				target = "/files/0123456789abcdef01234567"
			}
			// httptest requests have Host example.com.
			req := httptest.NewRequest(tt.method, target, nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != tt.want {
				t.Errorf("status = %d, want %d", w.Code, tt.want)
			}
		})
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
	for _, name := range []string{"home.html", "login.html", "register.html", "profile.html", "files.html", "benchmarks.html", "error.html"} {
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

func TestNoRouteRendersConfusedPage(t *testing.T) {
	for _, path := range []string{"/nope", "/files/x/y/z", "/static/missing.css"} {
		t.Run(path, func(t *testing.T) {
			r, _ := newTestEngine(t, 1024)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))

			if w.Code != http.StatusNotFound {
				t.Errorf("status = %d, want 404", w.Code)
			}
			body := w.Body.String()
			if got := stageMood(t, body); got != "confused" {
				t.Errorf("Gembi's mood = %q, want confused", got)
			}
			if !strings.Contains(body, "Error 404") {
				t.Error("body is missing the status code")
			}
		})
	}
}

func TestStaticAssetsServed(t *testing.T) {
	tests := []struct {
		path        string
		contentType string
	}{
		{"/static/style.css", "text/css"},
		{"/static/mascot.css", "text/css"},
		{"/static/app.js", "javascript"},
		{"/static/mascot.js", "javascript"},
		{"/static/fonts/nunito-latin-wght-normal.woff2", "font/woff2"},
		{"/static/fonts/OFL.txt", "text/plain"},
		{"/static/favicon.svg", "image/svg+xml"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			r, _ := newTestEngine(t, 1024)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, tt.path, nil))
			if w.Code != http.StatusOK {
				t.Errorf("status = %d, want 200", w.Code)
			}
			if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, tt.contentType) {
				t.Errorf("Content-Type = %q, want it to contain %q", ct, tt.contentType)
			}
		})
	}
}
