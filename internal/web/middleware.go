package web

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// formBodyBytes caps every request body except uploads. Forms (login,
// register, profile) are a few hundred bytes; without this cap a multipart
// body sent to them could make Gin spool up to MaxBodyBytes to disk.
const formBodyBytes = 64 << 10

// uploadPath is the only route that accepts the large upload limit.
const uploadPath = "/files"

// maxBodySize rejects requests whose declared body is larger than the limit
// and caps the body reader at the limit for requests that do not declare a
// length (chunked uploads). Reading past the cap returns
// *http.MaxBytesError. POST /files gets uploadLimit; everything else gets
// formBodyBytes (or uploadLimit, if that is smaller).
func maxBodySize(uploadLimit int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		limit := min(uploadLimit, formBodyBytes)
		if c.Request.Method == http.MethodPost && c.FullPath() == uploadPath {
			limit = uploadLimit
		}
		if c.Request.ContentLength > limit {
			c.AbortWithStatus(http.StatusRequestEntityTooLarge)
			return
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, limit)
		c.Next()
	}
}

// crossOriginProtection rejects cross-site state-changing requests (CSRF)
// with the standard library's check: a POST, PUT, PATCH or DELETE is refused
// when Sec-Fetch-Site says another site sent it, or, for older browsers,
// when the Origin header names another host. Requests with neither header
// are not from a browser and are allowed. SameSite=Strict session cookies
// are the second layer (docs/decisions.md D28).
func crossOriginProtection() gin.HandlerFunc {
	cop := http.NewCrossOriginProtection()
	return func(c *gin.Context) {
		if err := cop.Check(c.Request); err != nil {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
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
