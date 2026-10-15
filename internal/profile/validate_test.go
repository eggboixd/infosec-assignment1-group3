package profile

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// fixedNow is "today" in tests, so date checks never depend on the clock.
var fixedNow = time.Date(2026, time.October, 14, 9, 0, 0, 0, time.UTC)

// validData is obviously fake test data, not a real person's.
func validData() PrivateData {
	return PrivateData{
		FullName:    "Budi Santoso",
		NIK:         "3578010101990001",
		DateOfBirth: "1999-01-01",
		Address:     "Jl. Teknik Kimia, Keputih, Sukolilo\nSurabaya 60111",
		Phone:       "081234567890",
		Email:       "budi@example.com",
	}
}

func TestValidate(t *testing.T) {
	mod := func(fn func(d *PrivateData)) PrivateData {
		d := validData()
		fn(&d)
		d.normalize()
		return d
	}
	tests := []struct {
		name string
		data PrivateData
		want string // substring of the single expected message; "" means valid
	}{
		{"valid", validData(), ""},
		{"surrounding spaces are trimmed", mod(func(d *PrivateData) { d.NIK = "  " + d.NIK + "\t" }), ""},
		{"multi-byte name of 100 runes", mod(func(d *PrivateData) { d.FullName = strings.Repeat("é", 100) }), ""},

		{"empty name", mod(func(d *PrivateData) { d.FullName = "" }), "Full name is required"},
		{"whitespace-only name", mod(func(d *PrivateData) { d.FullName = "   " }), "Full name is required"},
		{"name of 101 runes", mod(func(d *PrivateData) { d.FullName = strings.Repeat("é", 101) }), "at most 100"},
		{"control character in name", mod(func(d *PrivateData) { d.FullName = "Budi\x00Santoso" }), "not allowed"},
		{"newline in name", mod(func(d *PrivateData) { d.FullName = "Budi\nSantoso" }), "not allowed"},
		{"invalid UTF-8 in name", mod(func(d *PrivateData) { d.FullName = "Budi\xff" }), "not allowed"},

		{"NIK of 15 digits", mod(func(d *PrivateData) { d.NIK = "357801010199000" }), "exactly 16 digits"},
		{"NIK of 17 digits", mod(func(d *PrivateData) { d.NIK = "35780101019900011" }), "exactly 16 digits"},
		{"NIK with a letter", mod(func(d *PrivateData) { d.NIK = "3578O10101990001" }), "exactly 16 digits"},
		{"NIK with non-ASCII digits", mod(func(d *PrivateData) { d.NIK = "٣٥٧٨٠١٠١٠١٩٩٠٠٠١" }), "exactly 16 digits"},
		{"NIK with inner space", mod(func(d *PrivateData) { d.NIK = "3578 010101990001" }), "exactly 16 digits"},
		{"empty NIK", mod(func(d *PrivateData) { d.NIK = "" }), "NIK is required"},

		{"empty date", mod(func(d *PrivateData) { d.DateOfBirth = "" }), "Date of birth is required"},
		{"impossible date", mod(func(d *PrivateData) { d.DateOfBirth = "2024-02-30" }), "valid date"},
		{"wrong date format", mod(func(d *PrivateData) { d.DateOfBirth = "01/01/1999" }), "valid date"},
		{"future date", mod(func(d *PrivateData) { d.DateOfBirth = "2026-10-15" }), "future"},
		{"today is allowed", mod(func(d *PrivateData) { d.DateOfBirth = "2026-10-14" }), ""},
		{"before 1900", mod(func(d *PrivateData) { d.DateOfBirth = "1899-12-31" }), "before 1900"},
		{"1900-01-01 is allowed", mod(func(d *PrivateData) { d.DateOfBirth = "1900-01-01" }), ""},

		{"empty address", mod(func(d *PrivateData) { d.Address = "" }), "Address is required"},
		{"address of 301 runes", mod(func(d *PrivateData) { d.Address = strings.Repeat("a", 301) }), "at most 300"},
		{"address with CRLF line breaks", mod(func(d *PrivateData) { d.Address = "Jl. A\r\nSurabaya" }), ""},
		{"address with tab", mod(func(d *PrivateData) { d.Address = "Jl. A\tSurabaya" }), "not allowed"},

		{"phone of 8 digits", mod(func(d *PrivateData) { d.Phone = "08123456" }), "9 to 15 digits"},
		{"phone of 9 digits", mod(func(d *PrivateData) { d.Phone = "081234567" }), ""},
		{"phone of 15 digits", mod(func(d *PrivateData) { d.Phone = "081234567890123" }), ""},
		{"phone of 16 digits", mod(func(d *PrivateData) { d.Phone = "0812345678901234" }), "9 to 15 digits"},
		{"phone with plus", mod(func(d *PrivateData) { d.Phone = "+6281234567890" }), "9 to 15 digits"},
		{"empty phone", mod(func(d *PrivateData) { d.Phone = "" }), "Phone number is required"},

		{"email without at", mod(func(d *PrivateData) { d.Email = "budi.example.com" }), "valid address"},
		{"email with display name", mod(func(d *PrivateData) { d.Email = "Budi <budi@example.com>" }), "valid address"},
		{"email without domain dot", mod(func(d *PrivateData) { d.Email = "budi@localhost" }), "valid address"},
		{"email too long", mod(func(d *PrivateData) { d.Email = strings.Repeat("a", 250) + "@x.co" }), "valid address"},
		{"empty email", mod(func(d *PrivateData) { d.Email = "" }), "Email is required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validate(tt.data, fixedNow)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("validate = %v, want nil", err)
				}
				return
			}
			var verr *ValidationError
			if !errors.As(err, &verr) {
				t.Fatalf("validate = %v, want *ValidationError", err)
			}
			if len(verr.Messages) != 1 || !strings.Contains(verr.Messages[0], tt.want) {
				t.Errorf("messages = %q, want one containing %q", verr.Messages, tt.want)
			}
		})
	}
}

func TestValidateReportsEveryFieldInFormOrder(t *testing.T) {
	err := validate(PrivateData{}, fixedNow)
	var verr *ValidationError
	if !errors.As(err, &verr) {
		t.Fatalf("validate = %v", err)
	}
	want := []string{"Full name", "NIK", "Date of birth", "Address", "Phone", "Email"}
	if len(verr.Messages) != len(want) {
		t.Fatalf("messages = %q", verr.Messages)
	}
	for i, prefix := range want {
		if !strings.HasPrefix(verr.Messages[i], prefix) {
			t.Errorf("message %d = %q, want prefix %q", i, verr.Messages[i], prefix)
		}
	}
}

// Messages are shown on the page and may be logged, so they must never echo
// what the user typed.
func TestValidationMessagesNeverContainInput(t *testing.T) {
	secret := "3578999999999999"
	d := validData()
	d.NIK = secret + "9"
	d.FullName = strings.Repeat("Z", 101)
	d.Email = "x" + secret
	err := validate(d, fixedNow)
	if err == nil {
		t.Fatal("expected errors")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "ZZZZ") {
		t.Errorf("error echoes input: %v", err)
	}
}
