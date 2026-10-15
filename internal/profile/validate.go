package profile

import (
	"net/mail"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Field limits. They match the binding tags on PrivateData and the
// maxlength/pattern attributes in profile.html, so the browser, Gin and the
// service all enforce the same rules.
const (
	maxNameRunes    = 100
	maxAddressRunes = 300
	maxEmailBytes   = 254 // RFC 5321 path limit
	nikDigits       = 16
	minPhoneDigits  = 9
	maxPhoneDigits  = 15
	dateLayout      = "2006-01-02"
)

// minDateOfBirth is the earliest accepted date of birth. Anything older is
// almost certainly a typo.
var minDateOfBirth = time.Date(1900, time.January, 1, 0, 0, 0, 0, time.UTC)

// ValidationError lists every problem with submitted private data as
// user-facing messages, in form order.
//
// Messages never contain the submitted values: they are shown on the page and
// could end up in logs, and the values are personal data.
type ValidationError struct {
	Messages []string
}

func (e *ValidationError) Error() string {
	return "profile: invalid private data: " + strings.Join(e.Messages, " ")
}

// normalize trims surrounding whitespace from every field. It runs before
// validation, so "   " counts as empty and a pasted NIK with a trailing
// space is still accepted.
func (d *PrivateData) normalize() {
	d.FullName = strings.TrimSpace(d.FullName)
	d.NIK = strings.TrimSpace(d.NIK)
	d.DateOfBirth = strings.TrimSpace(d.DateOfBirth)
	d.Address = strings.TrimSpace(d.Address)
	d.Phone = strings.TrimSpace(d.Phone)
	d.Email = strings.TrimSpace(d.Email)
}

// validate checks normalised data and returns nil or a *ValidationError.
//
// Why validate here when Gin's binding tags already ran in the handler: the
// service must not trust its caller (defence in depth), the tags cannot
// express "not in the future" or "no control characters", and plain Go is
// testable without Gin. today is passed in so tests do not depend on the
// clock.
func validate(d PrivateData, today time.Time) error {
	var msgs []string
	add := func(m string) { msgs = append(msgs, m) }

	switch {
	case d.FullName == "":
		add("Full name is required.")
	case utf8.RuneCountInString(d.FullName) > maxNameRunes:
		add("Full name must be at most 100 characters.")
	case !utf8.ValidString(d.FullName) || hasControl(d.FullName, false):
		add("Full name contains characters that are not allowed.")
	}

	switch {
	case d.NIK == "":
		add("NIK is required.")
	case len(d.NIK) != nikDigits || !allDigits(d.NIK):
		add("NIK must be exactly 16 digits.")
	}

	if msg := checkDateOfBirth(d.DateOfBirth, today); msg != "" {
		add(msg)
	}

	switch {
	case d.Address == "":
		add("Address is required.")
	case utf8.RuneCountInString(d.Address) > maxAddressRunes:
		add("Address must be at most 300 characters.")
	case !utf8.ValidString(d.Address) || hasControl(d.Address, true):
		add("Address contains characters that are not allowed.")
	}

	switch {
	case d.Phone == "":
		add("Phone number is required.")
	case !allDigits(d.Phone) || len(d.Phone) < minPhoneDigits || len(d.Phone) > maxPhoneDigits:
		add("Phone number must be 9 to 15 digits, for example 081234567890.")
	}

	switch {
	case d.Email == "":
		add("Email is required.")
	case len(d.Email) > maxEmailBytes || !isPlainEmail(d.Email):
		add("Email must be a valid address, for example name@example.com.")
	}

	if len(msgs) > 0 {
		return &ValidationError{Messages: msgs}
	}
	return nil
}

// checkDateOfBirth returns an error message, or "" if s is a real calendar
// date between minDateOfBirth and today.
func checkDateOfBirth(s string, today time.Time) string {
	if s == "" {
		return "Date of birth is required."
	}
	// time.Parse rejects impossible dates such as 2024-02-30.
	dob, err := time.Parse(dateLayout, s)
	if err != nil {
		return "Date of birth must be a valid date (YYYY-MM-DD)."
	}
	y, m, d := today.Date()
	if dob.After(time.Date(y, m, d, 0, 0, 0, 0, time.UTC)) {
		return "Date of birth cannot be in the future."
	}
	if dob.Before(minDateOfBirth) {
		return "Date of birth cannot be before 1900."
	}
	return ""
}

// allDigits reports whether s is non-empty and only ASCII 0-9. unicode.IsDigit
// would also accept other scripts' digits, which a NIK never contains.
func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// hasControl reports whether s contains control characters. Line breaks are
// allowed only in multi-line fields (the address textarea).
func hasControl(s string, multiline bool) bool {
	for _, r := range s {
		if multiline && (r == '\n' || r == '\r') {
			continue
		}
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

// isPlainEmail accepts a bare address such as name@example.com. mail.ParseAddress
// alone also accepts display-name forms like "Alice <a@example.com>", so the
// parsed address must equal the whole input.
func isPlainEmail(s string) bool {
	addr, err := mail.ParseAddress(s)
	if err != nil || addr.Name != "" || addr.Address != s {
		return false
	}
	at := strings.LastIndexByte(s, '@')
	return at > 0 && strings.Contains(s[at+1:], ".")
}
