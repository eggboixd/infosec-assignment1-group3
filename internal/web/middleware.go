package web

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// maxBodySize rejects requests whose declared body is larger than limit and
// caps the body reader at limit for requests that do not declare a length
// (chunked uploads). Reading past the cap returns *http.MaxBytesError.
//
// TODO(feature/auth): apply a much smaller limit to the login, register,
// and profile forms; the global limit is sized for video uploads.
func maxBodySize(limit int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.ContentLength > limit {
			c.AbortWithStatus(http.StatusRequestEntityTooLarge)
			return
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, limit)
		c.Next()
	}
}

// contentSecurityPolicy allows scripts only from this origin and the pinned
// htmx CDN, and forbids framing.
const contentSecurityPolicy = "default-src 'self'; " +
	"script-src 'self' https://cdn.jsdelivr.net; " +
	"style-src 'self'; img-src 'self' data:; " +
	"object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"

// securityHeaders sets conservative browser security headers.
func securityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		c.Next()
	}
}
