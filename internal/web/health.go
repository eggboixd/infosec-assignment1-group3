package web

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// healthTimeout bounds how long /healthz waits for all dependencies. It is
// a variable so tests can shorten it.
var healthTimeout = 3 * time.Second

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
//
// The pings run at the same time, so a dependency that hangs until the
// timeout does not use up the time of the ones after it and get them
// reported as unavailable too.
func healthHandler(checks []HealthCheck) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), healthTimeout)
		defer cancel()

		errs := make([]error, len(checks))
		var wg sync.WaitGroup
		for i, hc := range checks {
			wg.Go(func() { errs[i] = hc.Pinger.Ping(ctx) })
		}
		wg.Wait()

		resp := healthResponse{Status: "ok", Checks: make(map[string]string, len(checks))}
		code := http.StatusOK
		for i, hc := range checks {
			if errs[i] != nil {
				slog.WarnContext(ctx, "health check failed", "dependency", hc.Name, "error", errs[i])
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
