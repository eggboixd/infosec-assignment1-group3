package web

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/eggboixd/infosec-assignment1-group3/internal/auth"
)

// showHome serves "/". A logged-in user goes straight to /files, which is
// already the app's hub; everyone else sees the landing page.
//
// "/" is a public route, so auth.RequireAuth has not run and CurrentUser is
// empty for now: every visitor sees the landing page.
// TODO(feature/auth): load the session without aborting on public routes, so
// logged-in users reach the redirect below.
func showHome(c *gin.Context) {
	if _, ok := auth.CurrentUser(c); ok {
		c.Redirect(http.StatusSeeOther, "/files")
		return
	}
	c.HTML(http.StatusOK, "home.html", gin.H{})
}
