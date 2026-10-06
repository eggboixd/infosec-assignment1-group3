package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

type fakePinger struct{ err error }

func (f fakePinger) Ping(context.Context) error { return f.err }

func TestHealthHandler(t *testing.T) {
	down := errors.New("connection refused")
	tests := []struct {
		name       string
		checks     []HealthCheck
		wantCode   int
		wantStatus string
		wantChecks map[string]string
	}{
		{
			name:       "all healthy",
			checks:     []HealthCheck{{"mongodb", fakePinger{}}, {"minio", fakePinger{}}},
			wantCode:   http.StatusOK,
			wantStatus: "ok",
			wantChecks: map[string]string{"mongodb": "ok", "minio": "ok"},
		},
		{
			name:       "minio down",
			checks:     []HealthCheck{{"mongodb", fakePinger{}}, {"minio", fakePinger{down}}},
			wantCode:   http.StatusServiceUnavailable,
			wantStatus: "unavailable",
			wantChecks: map[string]string{"mongodb": "ok", "minio": "unavailable"},
		},
		{
			name:       "no checks",
			checks:     nil,
			wantCode:   http.StatusOK,
			wantStatus: "ok",
			wantChecks: map[string]string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := gin.New()
			r.GET("/healthz", healthHandler(tt.checks))
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))

			if w.Code != tt.wantCode {
				t.Errorf("status = %d, want %d", w.Code, tt.wantCode)
			}
			var got healthResponse
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			if got.Status != tt.wantStatus {
				t.Errorf("status field = %q, want %q", got.Status, tt.wantStatus)
			}
			if len(got.Checks) != len(tt.wantChecks) {
				t.Errorf("checks = %v, want %v", got.Checks, tt.wantChecks)
			}
			for k, v := range tt.wantChecks {
				if got.Checks[k] != v {
					t.Errorf("checks[%s] = %q, want %q", k, got.Checks[k], v)
				}
			}
			if strings.Contains(w.Body.String(), down.Error()) {
				t.Error("response leaks the underlying error")
			}
		})
	}
}
