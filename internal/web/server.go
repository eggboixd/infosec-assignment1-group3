package web

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/eggboixd/infosec-assignment1-group3/internal/auth"
)

// RouteRegistrar is implemented by every feature Handler.
type RouteRegistrar interface {
	RegisterRoutes(public, protected *gin.RouterGroup)
}

// Options configures NewEngine.
type Options struct {
	// Mode is the Gin mode: "release", "debug", or "test". Empty keeps the
	// current mode.
	Mode string
	// MaxBodyBytes caps every request body.
	MaxBodyBytes int64
	// HealthChecks are pinged by GET /healthz.
	HealthChecks []HealthCheck
	// Features are mounted in order.
	Features []RouteRegistrar
	// Session runs on every request to load the logged-in user, normally
	// auth.LoadSession. Nil skips it, so every request is logged out.
	Session gin.HandlerFunc
	// RequireAuth guards the protected group. Nil means auth.RequireAuth();
	// tests override it to observe that protected routes pass through it.
	RequireAuth gin.HandlerFunc
}

// NewEngine builds the Gin engine with explicit middleware.
func NewEngine(opts Options) (*gin.Engine, error) {
	if opts.Mode != "" {
		gin.SetMode(opts.Mode)
	}
	r := gin.New()
	// The app is reached directly, so never trust X-Forwarded-For.
	if err := r.SetTrustedProxies(nil); err != nil {
		return nil, fmt.Errorf("web: trusted proxies: %w", err)
	}
	r.Use(
		gin.Recovery(),
		gin.LoggerWithConfig(gin.LoggerConfig{SkipPaths: []string{"/healthz"}}),
		securityHeaders(),
		crossOriginProtection(),
		maxBodySize(opts.MaxBodyBytes),
	)
	if opts.Session != nil {
		r.Use(opts.Session)
	}
	if err := mountRendering(r); err != nil {
		return nil, err
	}

	r.GET("/healthz", healthHandler(opts.HealthChecks))

	requireAuth := opts.RequireAuth
	if requireAuth == nil {
		requireAuth = auth.RequireAuth()
	}
	public := r.Group("/")
	protected := r.Group("/", requireAuth)

	protected.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusSeeOther, "/files")
	})
	for _, f := range opts.Features {
		f.RegisterRoutes(public, protected)
	}

	// Unknown paths (including missing /static files) get the error page
	// instead of Gin's plain-text 404.
	r.NoRoute(func(c *gin.Context) {
		c.HTML(http.StatusNotFound, "error.html", gin.H{
			"Title":   "Not found",
			"Status":  http.StatusNotFound,
			"Message": "We couldn't find that page.",
		})
	})
	return r, nil
}
