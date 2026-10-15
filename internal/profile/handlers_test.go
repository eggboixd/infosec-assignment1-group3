// External test package: these tests drive the real Gin engine and the
// embedded templates from internal/web. Being outside package profile keeps
// any future web -> profile import from becoming an import cycle.
package profile_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
	"github.com/eggboixd/infosec-assignment1-group3/internal/profile"
	"github.com/eggboixd/infosec-assignment1-group3/internal/web"
)

// devUserID is the user the auth.RequireAuth stub injects until
// feature/auth lands.
var devUserID = bson.ObjectID{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}

// store is a minimal in-memory profile store enforcing the NIK unique index.
type store struct {
	mu       sync.Mutex
	profiles map[bson.ObjectID]profile.Profile
}

func (s *store) Upsert(_ context.Context, p *profile.Profile) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for uid, other := range s.profiles {
		if uid != p.UserID && bytes.Equal(other.NIKIndex, p.NIKIndex) {
			return profile.ErrNIKTaken
		}
	}
	s.profiles[p.UserID] = *p
	return nil
}

func (s *store) FindByUserID(_ context.Context, id bson.ObjectID) (*profile.Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.profiles[id]
	if !ok {
		return nil, profile.ErrNotFound
	}
	return &p, nil
}

type fixture struct {
	svc    *profile.Service
	store  *store
	engine *gin.Engine
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	key := func() []byte {
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			t.Fatal(err)
		}
		return k
	}
	enc, err := crypto.NewEnvelope(key())
	if err != nil {
		t.Fatal(err)
	}
	st := &store{profiles: map[bson.ObjectID]profile.Profile{}}
	svc := profile.NewService(st, enc, key(), nil)
	engine, err := web.NewEngine(web.Options{
		Mode:         gin.TestMode,
		MaxBodyBytes: 1 << 20,
		Features:     []web.RouteRegistrar{profile.NewHandler(svc)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{svc: svc, store: st, engine: engine}
}

func (f *fixture) do(method, target string, form url.Values) *httptest.ResponseRecorder {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, target, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	rec := httptest.NewRecorder()
	f.engine.ServeHTTP(rec, req)
	return rec
}

// Obviously fake test data.
func validForm() url.Values {
	return url.Values{
		"full_name":     {"Siti Rahayu"},
		"nik":           {"3578015505010003"},
		"date_of_birth": {"2001-05-15"},
		"address":       {"Jl. Arief Rahman Hakim 1, Surabaya"},
		"phone":         {"082233445566"},
		"email":         {"siti@example.com"},
	}
}

// Both profile routes must sit behind RequireAuth. A guard that rejects
// everyone must stop them before the handler runs.
func TestProfileRoutesRequireLogin(t *testing.T) {
	f := newFixture(t)
	guarded, err := web.NewEngine(web.Options{
		Mode:         gin.TestMode,
		MaxBodyBytes: 1 << 20,
		Features:     []web.RouteRegistrar{profile.NewHandler(f.svc)},
		RequireAuth:  func(c *gin.Context) { c.AbortWithStatus(http.StatusUnauthorized) },
	})
	if err != nil {
		t.Fatal(err)
	}
	f.engine = guarded
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		if rec := f.do(method, "/profile", validForm()); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s /profile without login: status = %d, want 401", method, rec.Code)
		}
	}
	if _, err := f.store.FindByUserID(context.Background(), devUserID); !errors.Is(err, profile.ErrNotFound) {
		t.Error("unauthenticated POST stored a profile")
	}
}

func TestShowWithoutProfile(t *testing.T) {
	f := newFixture(t)
	rec := f.do(http.MethodGet, "/profile", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Nothing stored yet") {
		t.Error("empty-state text missing")
	}
}

func TestSaveRedirectsThenShowsEachAlgorithm(t *testing.T) {
	f := newFixture(t)
	rec := f.do(http.MethodPost, "/profile", validForm())
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST status = %d, want 303; body: %s", rec.Code, rec.Body)
	}
	if loc := rec.Header().Get("Location"); loc != "/profile?alg=aes" {
		t.Errorf("Location = %q", loc)
	}

	for _, alg := range []string{"aes", "des", "rc4"} {
		t.Run(alg, func(t *testing.T) {
			rec := f.do(http.MethodGet, "/profile?alg="+alg, nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d", rec.Code)
			}
			body := rec.Body.String()
			for _, v := range validForm() {
				if !strings.Contains(body, v[0]) {
					t.Errorf("decrypted value %q not shown", v[0])
				}
			}
			if !strings.Contains(body, `<option value="`+alg+`" selected>`) {
				t.Errorf("%s is not the selected algorithm", alg)
			}
		})
	}
}

func TestShowUnknownAlgorithm(t *testing.T) {
	f := newFixture(t)
	for _, alg := range []string{"ecb", "AES", "3des", "%00"} {
		rec := f.do(http.MethodGet, "/profile?alg="+alg, nil)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("alg=%q: status = %d, want 400", alg, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "Unknown algorithm") {
			t.Errorf("alg=%q: message missing", alg)
		}
	}
}

func TestSaveInvalidKeepsInputAndShowsFriendlyErrors(t *testing.T) {
	f := newFixture(t)
	form := validForm()
	form.Set("nik", "12345")
	form.Set("phone", "08-12")
	rec := f.do(http.MethodPost, "/profile", form)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"NIK must be exactly 16 digits.", "Phone number must be 9 to 15 digits", `value="Siti Rahayu"`} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
	if strings.Contains(body, "Key: ") || strings.Contains(body, "PrivateData.") {
		t.Error("raw validator error leaked to the page")
	}
	if _, err := f.store.FindByUserID(context.Background(), devUserID); !errors.Is(err, profile.ErrNotFound) {
		t.Error("invalid form was stored")
	}
}

// Passes the binding tags but fails the service's extra rules.
func TestSaveFutureDateOfBirth(t *testing.T) {
	f := newFixture(t)
	form := validForm()
	form.Set("date_of_birth", "2999-01-01")
	rec := f.do(http.MethodPost, "/profile", form)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "cannot be in the future") {
		t.Error("message missing")
	}
}

func TestSaveDuplicateNIK(t *testing.T) {
	f := newFixture(t)
	other := profile.PrivateData{
		FullName: "Other Person", NIK: validForm().Get("nik"), DateOfBirth: "1990-01-01",
		Address: "Jl. Lain 2", Phone: "081111111111", Email: "other@example.com",
	}
	if err := f.svc.Save(context.Background(), bson.NewObjectID(), other); err != nil {
		t.Fatal(err)
	}
	rec := f.do(http.MethodPost, "/profile", validForm())
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "already registered") {
		t.Error("message missing")
	}
	if strings.Contains(body, "Other Person") {
		t.Error("page reveals the other account")
	}
}

func TestShowTamperedProfile(t *testing.T) {
	f := newFixture(t)
	if rec := f.do(http.MethodPost, "/profile", validForm()); rec.Code != http.StatusSeeOther {
		t.Fatalf("POST status = %d", rec.Code)
	}
	p := f.store.profiles[devUserID]
	s := p.Address[crypto.DES]
	s.Ciphertext[3] ^= 0x10
	p.Address[crypto.DES] = s

	rec := f.do(http.MethodGet, "/profile?alg=des", nil)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "integrity check") {
		t.Error("message missing")
	}
	// Fail closed: not even the untouched fields are shown.
	if strings.Contains(body, "Siti Rahayu") {
		t.Error("data shown despite failed integrity check")
	}
	// The other copies are unaffected.
	if rec := f.do(http.MethodGet, "/profile?alg=aes", nil); rec.Code != http.StatusOK {
		t.Errorf("aes copy: status = %d", rec.Code)
	}
}

// Every path, including failures that log, must keep personal data out of
// the application log and Gin's request log.
func TestNothingSensitiveInLogs(t *testing.T) {
	var logs bytes.Buffer
	prevLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	prevWriter := gin.DefaultWriter
	gin.DefaultWriter = &logs
	t.Cleanup(func() {
		slog.SetDefault(prevLogger)
		gin.DefaultWriter = prevWriter
	})

	f := newFixture(t) // built after swapping gin.DefaultWriter, so its logger writes to logs
	form := validForm()

	f.do(http.MethodPost, "/profile", form)
	for _, alg := range []string{"aes", "des", "rc4"} {
		f.do(http.MethodGet, "/profile?alg="+alg, nil)
	}
	bad := validForm()
	bad.Set("email", "nope")
	f.do(http.MethodPost, "/profile", bad)

	p := f.store.profiles[devUserID]
	s := p.NIK[crypto.RC4]
	s.Ciphertext[0] ^= 1
	p.NIK[crypto.RC4] = s
	f.do(http.MethodGet, "/profile?alg=rc4", nil) // logs a warning

	out := logs.String()
	if !strings.Contains(out, "integrity check failed") {
		t.Fatalf("expected the integrity warning to be logged; log was:\n%s", out)
	}
	for field, v := range form {
		if strings.Contains(out, v[0]) || strings.Contains(out, url.QueryEscape(v[0])) {
			t.Errorf("log contains %s", field)
		}
	}
	if strings.Contains(out, "Surabaya") || strings.Contains(out, "nope") {
		t.Error("log contains form input")
	}
}
