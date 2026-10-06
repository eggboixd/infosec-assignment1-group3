package web

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// healthTimeout bounds how long /healthz waits for all dependencies.
const healthTimeout = 3 * time.Second

// Pinger is a dependency that can report whether it is reachable.
type Pinger interface {
	Ping(ctx context.Context) error
}

// HealthCheck names one dependency for /healthz.
type HealthCheck struct {
	Name   string
	Pinger Pinger
}

// healthResponse is the JSON body of /healthz.
type healthResponse struct {
	Status string            `json:"status"`
	Checks map[string]string `json:"checks"`
}

// healthHandler pings every dependency and returns 200 if all respond, or
// 503 otherwise. Error details go to the log, not the response.
func healthHandler(checks []HealthCheck) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), healthTimeout)
		defer cancel()

		resp := healthResponse{Status: "ok", Checks: make(map[string]string, len(checks))}
		code := http.StatusOK
		for _, hc := range checks {
			if err := hc.Pinger.Ping(ctx); err != nil {
				slog.WarnContext(ctx, "health check failed", "dependency", hc.Name, "error", err)
				resp.Checks[hc.Name] = "unavailable"
				resp.Status = "unavailable"
				code = http.StatusServiceUnavailable
				continue
			}
			resp.Checks[hc.Name] = "ok"
		}
		c.JSON(code, resp)
	}
}
