package sharing

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/eggboixd/infosec-assignment1-group3/internal/auth"
	"github.com/eggboixd/infosec-assignment1-group3/internal/web"
)

// handlerEnv drives the real engine and templates; every request is logged
// in as *as.
type handlerEnv struct {
	*env
	engine *gin.Engine
	as     *auth.User
}

func newHandlerEnv(t *testing.T) *handlerEnv {
	t.Helper()
	h := &handlerEnv{env: newEnv(t)}
	h.as = h.u("vinno")
	engine, err := web.NewEngine(web.Options{
		Mode:         gin.TestMode,
		MaxBodyBytes: 1 << 20,
		Features:     []web.RouteRegistrar{NewHandler(h.svc)},
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
	req := httptest.NewRequest(method, target, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	rec := httptest.NewRecorder()
	h.engine.ServeHTTP(rec, req)
	return rec
}

func TestSharesRoutes(t *testing.T) {
	type step struct {
		as       string
		method   string
		path     string // "{id}" is replaced by the pending request's ID
		form     url.Values
		status   int
		location string
		body     []string
		notBody  []string
	}
	tests := []struct {
		name string
		step step
	}{
		{"page", step{as: "vinno", method: "GET", path: "/shares", status: 200,
			body: []string{"Data sharing", `action="/shares/requests"`, "rayen"}}},
		{"send ok", step{as: "kenzie", method: "POST", path: "/shares/requests", form: url.Values{"username": {"rayen"}, "reason": {"review"}},
			status: 303, location: "/shares?done=sent"}},
		{"send unknown user", step{as: "vinno", method: "POST", path: "/shares/requests", form: url.Values{"username": {"nobody"}},
			status: 404, body: []string{"No user with that username."}}},
		{"send to self", step{as: "vinno", method: "POST", path: "/shares/requests", form: url.Values{"username": {"vinno"}},
			status: 400, body: []string{"You can&#39;t request your own data."}}},
		{"send duplicate", step{as: "vinno", method: "POST", path: "/shares/requests", form: url.Values{"username": {"rayen"}},
			status: 409, body: []string{"You already have an open request to this user."}}},
		{"approve ok", step{as: "rayen", method: "POST", path: "/shares/requests/{id}/approve", form: url.Values{"duration": {"1d"}},
			status: 303, location: "/shares?done=approved"}},
		{"approve bad duration", step{as: "rayen", method: "POST", path: "/shares/requests/{id}/approve", form: url.Values{"duration": {"2d"}},
			status: 400, body: []string{"Choose 1, 7 or 30 days."}}},
		{"approve by requester", step{as: "vinno", method: "POST", path: "/shares/requests/{id}/approve", form: url.Values{"duration": {"7d"}},
			status: 404, body: []string{"We couldn&#39;t find that request."}}},
		{"approve bad id", step{as: "rayen", method: "POST", path: "/shares/requests/nothex/approve", form: url.Values{"duration": {"7d"}},
			status: 404}},
		{"reject ok", step{as: "rayen", method: "POST", path: "/shares/requests/{id}/reject", form: url.Values{},
			status: 303, location: "/shares?done=rejected"}},
		{"revoke pending", step{as: "rayen", method: "POST", path: "/shares/requests/{id}/revoke", form: url.Values{},
			status: 409, body: []string{"That request has already been answered."}}},
		{"cancel ok", step{as: "vinno", method: "POST", path: "/shares/requests/{id}/cancel", form: url.Values{},
			status: 303, location: "/shares?done=cancelled"}},
		{"cancel by owner", step{as: "rayen", method: "POST", path: "/shares/requests/{id}/cancel", form: url.Values{},
			status: 404}},
		{"done flash", step{as: "vinno", method: "GET", path: "/shares?done=sent", status: 200, body: []string{"Request sent."}}},
		{"bogus done code", step{as: "vinno", method: "GET", path: "/shares?done=bogus", status: 200, notBody: []string{"flash--"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHandlerEnv(t)
			r := h.send(t, "vinno", "rayen") // one pending request vinno -> rayen
			s := tt.step
			h.as = h.u(s.as)
			rec := h.do(s.method, strings.ReplaceAll(s.path, "{id}", r.ID.Hex()), s.form)
			if rec.Code != s.status {
				t.Fatalf("status = %d, want %d; body:\n%s", rec.Code, s.status, rec.Body.String())
			}
			if s.location != "" && rec.Header().Get("Location") != s.location {
				t.Fatalf("Location = %q, want %q", rec.Header().Get("Location"), s.location)
			}
			for _, b := range s.body {
				if !strings.Contains(rec.Body.String(), b) {
					t.Errorf("body is missing %q", b)
				}
			}
			for _, b := range s.notBody {
				if strings.Contains(rec.Body.String(), b) {
					t.Errorf("body must not contain %q", b)
				}
			}
		})
	}
}

func TestSharesPageShowsRowsByState(t *testing.T) {
	h := newHandlerEnv(t)
	pending := h.send(t, "vinno", "rayen")
	if _, err := h.svc.Send(t.Context(), h.u("kenzie"), "rayen", "<script>x</script>"); err != nil {
		t.Fatal(err)
	}

	h.as = h.u("rayen")
	body := h.do(http.MethodGet, "/shares", nil).Body.String()
	for _, want := range []string{
		"/shares/requests/" + pending.ID.Hex() + "/approve",
		"/shares/requests/" + pending.ID.Hex() + "/reject",
		fingerprintOf(h.u("vinno").ID),
		`<option value="7d" selected>`,
		"&lt;script&gt;x&lt;/script&gt;",
		"data-confirm=",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("owner's page is missing %q", want)
		}
	}
	if strings.Contains(body, "<script>x</script>") {
		t.Error("reason is not escaped")
	}

	if _, err := h.svc.Approve(t.Context(), h.u("rayen").ID, pending.ID, "7d"); err != nil {
		t.Fatal(err)
	}
	body = h.do(http.MethodGet, "/shares", nil).Body.String()
	if !strings.Contains(body, "/shares/requests/"+pending.ID.Hex()+"/revoke") {
		t.Error("approved inbox row has no Revoke")
	}
	if strings.Contains(body, "/shares/requests/"+pending.ID.Hex()+"/approve") {
		t.Error("approved inbox row still offers Approve")
	}

	h.as = h.u("vinno")
	body = h.do(http.MethodGet, "/shares", nil).Body.String()
	if strings.Contains(body, "/shares/requests/"+pending.ID.Hex()+"/cancel") {
		t.Error("approved sent row still offers Cancel")
	}
	if !strings.Contains(body, "Access until") {
		t.Error("approved sent row does not show the expiry")
	}
}
