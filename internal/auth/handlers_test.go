package auth_test

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/eggboixd/infosec-assignment1-group3/internal/auth"
	"github.com/eggboixd/infosec-assignment1-group3/internal/web"
)

const password = "correct-horse-battery"

// whoami is a protected test route that reports what the auth middleware
// handed to it.
type whoami struct{}

func (whoami) RegisterRoutes(_, protected *gin.RouterGroup) {
	protected.GET("/whoami", func(c *gin.Context) {
		u, _ := auth.CurrentUser(c)
		c.JSON(http.StatusOK, gin.H{"username": u.Username, "just_logged_in": auth.JustLoggedIn(c)})
	})
}

type fixture struct {
	t      *testing.T
	engine *gin.Engine
	users  interface {
		Get(string) (auth.User, bool)
	}
	sessions interface{ Len() int }
	cookies  map[string]*http.Cookie // a tiny browser cookie jar
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	auth.UseFastHashes(t)
	users, sessions := auth.NewMemUsers(), auth.NewMemSessions()
	mgr := auth.NewSessionManager(sessions, []byte("0123456789abcdef0123456789abcdef"), false)
	engine, err := web.NewEngine(web.Options{
		Mode:         gin.TestMode,
		MaxBodyBytes: 1 << 20,
		Session:      auth.LoadSession(mgr),
		Features:     []web.RouteRegistrar{auth.NewHandler(auth.NewService(users), mgr), whoami{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{t: t, engine: engine, users: users, sessions: sessions, cookies: map[string]*http.Cookie{}}
}

// do sends a request with the jar's cookies and stores any it gets back,
// like a browser that does not follow redirects.
func (f *fixture) do(method, target string, form url.Values, headers ...string) *httptest.ResponseRecorder {
	f.t.Helper()
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	req := httptest.NewRequest(method, target, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	for _, c := range f.cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	f.engine.ServeHTTP(rec, req)
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(f.cookies, c.Name)
		} else {
			f.cookies[c.Name] = c
		}
	}
	return rec
}

func (f *fixture) register(username, pw, confirm string) *httptest.ResponseRecorder {
	return f.do(http.MethodPost, "/register", url.Values{"username": {username}, "password": {pw}, "confirm": {confirm}})
}

func (f *fixture) login(username, pw string) *httptest.ResponseRecorder {
	return f.do(http.MethodPost, "/login", url.Values{"username": {username}, "password": {pw}})
}

func expectRedirect(t *testing.T, rec *httptest.ResponseRecorder, to string) {
	t.Helper()
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != to {
		t.Fatalf("got %d Location=%q, want 303 %s", rec.Code, rec.Header().Get("Location"), to)
	}
}

func TestRegisterThenLoginThenLogout(t *testing.T) {
	f := newFixture(t)

	expectRedirect(t, f.register("Budi", password, password), "/login")
	u, ok := f.users.Get("budi")
	if !ok || !strings.HasPrefix(u.PasswordHash, "$argon2id$") {
		t.Fatalf("stored user = %+v, %v; want budi with an Argon2id hash", u, ok)
	}

	page := f.do(http.MethodGet, "/login", nil)
	if !strings.Contains(page.Body.String(), "Account created") {
		t.Error("login page does not show the one-time registration message")
	}
	if again := f.do(http.MethodGet, "/login", nil); strings.Contains(again.Body.String(), "Account created") {
		t.Error("registration message shown twice")
	}

	expectRedirect(t, f.login("BUDI", password), "/files")
	c := f.cookies[auth.SessionCookieName]
	if c == nil || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie = %+v; want HttpOnly, SameSite=Strict", c)
	}

	who := f.do(http.MethodGet, "/whoami", nil)
	if who.Code != http.StatusOK || !strings.Contains(who.Body.String(), `"username":"budi"`) ||
		!strings.Contains(who.Body.String(), `"just_logged_in":true`) {
		t.Errorf("first /whoami = %d %s; want budi, just_logged_in", who.Code, who.Body)
	}
	if who := f.do(http.MethodGet, "/whoami", nil); !strings.Contains(who.Body.String(), `"just_logged_in":false`) {
		t.Errorf("second /whoami = %s; want just_logged_in false", who.Body)
	}

	// A logged-in user visiting the auth pages goes to their files.
	expectRedirect(t, f.do(http.MethodGet, "/login", nil), "/files")
	expectRedirect(t, f.do(http.MethodGet, "/register", nil), "/files")

	stolen := *c
	expectRedirect(t, f.do(http.MethodPost, "/logout", nil), "/login")
	if f.sessions.Len() != 0 {
		t.Errorf("%d sessions left after logout, want 0", f.sessions.Len())
	}
	if !strings.Contains(f.do(http.MethodGet, "/login", nil).Body.String(), "logged out") {
		t.Error("login page does not show the logout message")
	}

	// The old cookie is useless once the session is deleted server-side.
	f.cookies[auth.SessionCookieName] = &stolen
	expectRedirect(t, f.do(http.MethodGet, "/whoami", nil), "/login")
	if !strings.Contains(f.do(http.MethodGet, "/login", nil).Body.String(), "session has ended") {
		t.Error("login page does not explain the ended session")
	}
}

func TestProtectedRoutesNeedASession(t *testing.T) {
	f := newFixture(t)
	expectRedirect(t, f.do(http.MethodGet, "/whoami", nil), "/login")
	expectRedirect(t, f.do(http.MethodPost, "/logout", nil), "/login")

	// htmx would swap a redirect target into the page, so it gets a header.
	rec := f.do(http.MethodGet, "/whoami", nil, "HX-Request", "true")
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("HX-Redirect") != "/login" {
		t.Errorf("htmx: got %d HX-Redirect=%q, want 401 /login", rec.Code, rec.Header().Get("HX-Redirect"))
	}
}

// Every login gets a fresh token; the previous session stops working.
func TestLoginRotatesSession(t *testing.T) {
	f := newFixture(t)
	f.register("budi", password, password)
	f.login("budi", password)
	first := *f.cookies[auth.SessionCookieName]

	rec := f.login("budi", password)
	if n := strings.Count(strings.Join(rec.Header().Values("Set-Cookie"), "\n"), auth.SessionCookieName+"="); n != 1 {
		t.Errorf("login sent %d session cookies, want 1", n)
	}
	second := f.cookies[auth.SessionCookieName]
	if second.Value == first.Value {
		t.Fatal("second login reused the session token")
	}
	if f.sessions.Len() != 1 {
		t.Errorf("%d sessions stored, want 1 (the old one deleted)", f.sessions.Len())
	}
	f.cookies[auth.SessionCookieName] = &first
	expectRedirect(t, f.do(http.MethodGet, "/whoami", nil), "/login")
}

func TestLoginFailuresLookTheSame(t *testing.T) {
	f := newFixture(t)
	f.register("budi", password, password)

	wrong := f.login("budi", "wrong-password-here")
	unknown := f.login("nobody", password)
	empty := f.login("", "")
	for name, rec := range map[string]*httptest.ResponseRecorder{"wrong password": wrong, "unknown user": unknown, "empty form": empty} {
		if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "Wrong username or password.") {
			t.Errorf("%s: got %d, want 401 with the generic message", name, rec.Code)
		}
		if _, ok := f.cookies[auth.SessionCookieName]; ok {
			t.Errorf("%s: a session cookie was set", name)
		}
		if strings.Contains(rec.Body.String(), password) || strings.Contains(rec.Body.String(), "wrong-password-here") {
			t.Errorf("%s: the password is echoed in the page", name)
		}
	}
	if !strings.Contains(wrong.Body.String(), `value="budi"`) {
		t.Error("the username is not refilled after a failed login")
	}
}

func TestRegisterValidation(t *testing.T) {
	tests := []struct {
		name, username, password, confirm string
		want                              []string
	}{
		{"short username", "ab", password, password, []string{"Username must be 3–32 letters or digits."}},
		{"symbols in username", "budi!", password, password, []string{"Username must be 3–32 letters or digits."}},
		{"short password", "budi", "short", "short", []string{"at least 12 characters"}},
		{"mismatch", "budi", password, password + "x", []string{"don&#39;t match"}},
		{"everything", "", "", "x", []string{"Username must", "at least 12", "don&#39;t match"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			rec := f.register(tt.username, tt.password, tt.confirm)
			if rec.Code != http.StatusUnprocessableEntity {
				t.Errorf("status = %d, want 422", rec.Code)
			}
			for _, w := range tt.want {
				if !strings.Contains(rec.Body.String(), w) {
					t.Errorf("page is missing %q", w)
				}
			}
			if tt.password != "" && strings.Contains(rec.Body.String(), tt.password) {
				t.Error("the password is echoed in the page")
			}
		})
	}
}

func TestRegisterDuplicate(t *testing.T) {
	f := newFixture(t)
	f.register("budi", password, password)
	rec := f.register("BUDI", password, password)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "already taken") {
		t.Errorf("got %d, want 409 'already taken'", rec.Code)
	}
}

func TestLoginIsRateLimited(t *testing.T) {
	f := newFixture(t)
	for i := range 10 {
		if rec := f.login("budi", "wrong-password-here"); rec.Code == http.StatusTooManyRequests {
			t.Fatalf("attempt %d was rate limited, want 10 allowed", i+1)
		}
	}
	rec := f.login("budi", "wrong-password-here")
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" ||
		!strings.Contains(rec.Body.String(), "Too many attempts") {
		t.Errorf("11th attempt: got %d Retry-After=%q, want 429 with Retry-After", rec.Code, rec.Header().Get("Retry-After"))
	}
}

func TestRegisterIsRateLimited(t *testing.T) {
	f := newFixture(t)
	for range 5 {
		f.register("ab", "x", "y")
	}
	if rec := f.register("ab", "x", "y"); rec.Code != http.StatusTooManyRequests {
		t.Errorf("6th attempt: status = %d, want 429", rec.Code)
	}
}

// A login form posted from another site is refused before it is handled.
func TestCrossSiteLoginIsRefused(t *testing.T) {
	f := newFixture(t)
	f.register("budi", password, password)
	rec := f.do(http.MethodPost, "/login", url.Values{"username": {"budi"}, "password": {password}},
		"Origin", "https://evil.example")
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	if _, ok := f.cookies[auth.SessionCookieName]; ok {
		t.Error("a cross-site login created a session")
	}
}

// Logs carry user IDs and outcomes, never passwords, hashes or tokens.
func TestNothingSecretInLogs(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	f := newFixture(t)
	f.register("budi", password, password)
	f.login("budi", "wrong-password-here")
	f.login("budi", password)
	token := f.cookies[auth.SessionCookieName].Value
	u, _ := f.users.Get("budi")

	logs := buf.String()
	if !strings.Contains(logs, "auth: logged in") {
		t.Fatalf("expected login events in the logs, got %q", logs)
	}
	for _, secret := range []string{password, "wrong-password-here", token, u.PasswordHash} {
		if strings.Contains(logs, secret) {
			t.Errorf("logs contain a secret: %q", secret)
		}
	}
}
