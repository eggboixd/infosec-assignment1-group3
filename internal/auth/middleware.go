package auth

import (
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// userKey is the gin.Context key under which RequireAuth stores the user.
const userKey = "auth.user"

// fakeUser is injected by the RequireAuth stub so protected handlers can be
// developed before sessions exist.
var fakeUser = User{
	ID:       bson.ObjectID{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
	Username: "dev-user",
}

// RequireAuth rejects requests without a valid session and stores the
// logged-in user for CurrentUser.
//
// TODO(feature/auth): load the session with github.com/gin-contrib/sessions
// backed by a MongoDB store written on the v2 driver (the store shipped with
// gin-contrib/sessions requires the v1 driver). On a missing or invalid
// session, redirect to /login (or send HX-Redirect for htmx requests) and
// abort. Also add CSRF protection for state-changing requests, for example
// SameSite=Strict session cookies plus an Origin header check.
func RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		u := fakeUser
		c.Set(userKey, &u)
		c.Next()
	}
}

// CurrentUser returns the user stored by RequireAuth.
func CurrentUser(c *gin.Context) (*User, bool) {
	v, ok := c.Get(userKey)
	if !ok {
		return nil, false
	}
	u, ok := v.(*User)
	return u, ok
}
