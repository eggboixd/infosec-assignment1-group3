package auth

import "net/http"

// flashCookieName carries a one-time message across a redirect.
const flashCookieName = "flash"

// Flash is a one-time message for layout.html (.Flash.Kind, .Flash.Message).
type Flash struct {
	Kind    string // "success", "error" or "info"
	Message string
}

// Flash codes. The cookie holds only the code; the text lives here, so a
// forged cookie can at most show one of these fixed messages.
const (
	flashRegistered = "registered"
	flashLoggedOut  = "logged_out"
	flashExpired    = "expired"
)

var flashMessages = map[string]Flash{
	flashRegistered: {Kind: "success", Message: "Account created. Log in to continue."},
	flashLoggedOut:  {Kind: "info", Message: "You've been logged out."},
	flashExpired:    {Kind: "info", Message: "Your session has ended. Please log in again."},
}

// setFlash stores code for the next page load.
func setFlash(w http.ResponseWriter, code string, secure bool) {
	http.SetCookie(w, flashCookie(code, 60, secure))
}

// takeFlash returns the pending message, if any, and clears it.
func takeFlash(w http.ResponseWriter, r *http.Request, secure bool) *Flash {
	c, err := r.Cookie(flashCookieName)
	if err != nil {
		return nil
	}
	http.SetCookie(w, flashCookie("", -1, secure))
	f, ok := flashMessages[c.Value]
	if !ok {
		return nil
	}
	return &f
}

func flashCookie(value string, maxAge int, secure bool) *http.Cookie {
	return &http.Cookie{ // #nosec G124 -- Secure follows COOKIE_SECURE (docs/decisions.md D28); HttpOnly and SameSite=Strict are always set.
		Name:     flashCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	}
}
