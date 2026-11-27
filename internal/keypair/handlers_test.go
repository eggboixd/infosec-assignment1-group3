// External test package: these tests drive the real Gin engine and the
// embedded templates from internal/web, as the profile tests do.
package keypair_test

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/eggboixd/infosec-assignment1-group3/internal/auth"
	"github.com/eggboixd/infosec-assignment1-group3/internal/keypair"
	"github.com/eggboixd/infosec-assignment1-group3/internal/web"
)

var (
	alice = &auth.User{ID: bson.ObjectID{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, Username: "alice"}
	bob   = &auth.User{ID: bson.ObjectID{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}, Username: "bob"}
)

// engine serves the key routes with every request logged in as user, or
// with requireAuth replaced when guard is set.
func engine(t *testing.T, svc *keypair.Service, user *auth.User, guard gin.HandlerFunc) *gin.Engine {
	t.Helper()
	if guard == nil {
		guard = func(c *gin.Context) { auth.SetCurrentUser(c, user) }
	}
	e, err := web.NewEngine(web.Options{
		Mode:         gin.TestMode,
		MaxBodyBytes: 1 << 20,
		Features:     []web.RouteRegistrar{keypair.NewHandler(svc)},
		RequireAuth:  guard,
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func get(e *gin.Engine, target string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return rec
}

func TestDownloadPublicKeyPEM(t *testing.T) {
	svc := keypair.NewTestService(t)
	ctx := context.Background()
	for _, u := range []*auth.User{alice, bob} {
		if err := svc.EnsureKeys(ctx, u.ID, "a long enough password "+u.Username); err != nil {
			t.Fatal(err)
		}
	}
	e := engine(t, svc, alice, nil)

	var seen []*rsa.PublicKey
	for _, p := range []keypair.Purpose{keypair.Encryption, keypair.Signing} {
		rec := get(e, "/keys/"+string(p)+"/public.pem")
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", p, rec.Code)
		}
		hdr := rec.Header()
		if hdr.Get("Content-Type") != "application/x-pem-file" || hdr.Get("Cache-Control") != "no-store" ||
			hdr.Get("Content-Disposition") != `attachment; filename=securestore-alice-`+string(p)+`-public.pem` {
			t.Errorf("%s: headers %v", p, hdr)
		}
		block, rest := pem.Decode(rec.Body.Bytes())
		if block == nil || block.Type != "PUBLIC KEY" || len(rest) != 0 {
			t.Fatalf("%s: body is not one PUBLIC KEY block: %q", p, rec.Body)
		}
		if strings.Contains(rec.Body.String(), "PRIVATE") {
			t.Fatalf("%s: response mentions a private key", p)
		}
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		want, _ := svc.PublicKey(ctx, alice.ID, p)
		got, ok := key.(*rsa.PublicKey)
		if !ok || !got.Equal(want) || got.N.BitLen() != 3072 {
			t.Errorf("%s: served key is not alice's 3072-bit %s key", p, p)
		}
		seen = append(seen, got)
	}
	if seen[0].Equal(seen[1]) {
		t.Error("encryption and signing downloads are the same key")
	}

	// Bob, on the same URL, gets his own key, never Alice's (IDOR).
	block, _ := pem.Decode(get(engine(t, svc, bob, nil), "/keys/signing/public.pem").Body.Bytes())
	key, _ := x509.ParsePKIXPublicKey(block.Bytes)
	bobKey, _ := svc.PublicKey(ctx, bob.ID, keypair.Signing)
	if !bobKey.Equal(key) || seen[1].Equal(key) {
		t.Error("bob was not served his own signing key")
	}
}

func TestDownloadPublicKeyErrors(t *testing.T) {
	svc := keypair.NewTestService(t)
	if err := svc.EnsureKeys(context.Background(), alice.ID, "a long enough password"); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		user   *auth.User
		target string
		want   int
	}{
		{"unknown purpose", alice, "/keys/admin/public.pem", http.StatusNotFound},
		{"purpose in other case", alice, "/keys/Signing/public.pem", http.StatusNotFound},
		{"private key path", alice, "/keys/signing/private.pem", http.StatusNotFound},
		{"user without keys", bob, "/keys/encryption/public.pem", http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := get(engine(t, svc, tt.user, nil), tt.target)
			if rec.Code != tt.want || strings.Contains(rec.Body.String(), "BEGIN") {
				t.Errorf("status %d, want %d; body has a key: %v", rec.Code, tt.want, strings.Contains(rec.Body.String(), "BEGIN"))
			}
		})
	}

	t.Run("login required", func(t *testing.T) {
		deny := func(c *gin.Context) { c.AbortWithStatus(http.StatusUnauthorized) }
		if rec := get(engine(t, svc, nil, deny), "/keys/encryption/public.pem"); rec.Code != http.StatusUnauthorized {
			t.Errorf("status %d, want 401", rec.Code)
		}
	})

	t.Run("tampered public key", func(t *testing.T) {
		keypair.TamperPublicKey(t, svc, alice.ID, keypair.Encryption)
		rec := get(engine(t, svc, alice, nil), "/keys/encryption/public.pem")
		if rec.Code != http.StatusUnprocessableEntity || strings.Contains(rec.Body.String(), "BEGIN") {
			t.Errorf("status %d, want 422 and no key", rec.Code)
		}
	})
}
