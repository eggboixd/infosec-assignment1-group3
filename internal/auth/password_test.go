package auth

import (
	"errors"
	"strings"
	"testing"
)

func TestHashPasswordFormatAndRoundTrip(t *testing.T) {
	// One real-cost hash, so the production parameters are exercised.
	h, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=2$") {
		t.Errorf("hash %q does not use the default parameters", h)
	}
	if strings.Contains(h, "correct horse") {
		t.Error("hash contains the password")
	}
	ok, err := VerifyPassword(h, "correct horse battery staple")
	if err != nil || !ok {
		t.Errorf("VerifyPassword(right) = %v, %v; want true, nil", ok, err)
	}
	ok, err = VerifyPassword(h, "correct horse battery stapl")
	if err != nil || ok {
		t.Errorf("VerifyPassword(wrong) = %v, %v; want false, nil", ok, err)
	}
}

func TestHashPasswordUsesRandomSalt(t *testing.T) {
	UseFastHashes(t)
	a, _ := HashPassword("same password here")
	b, _ := HashPassword("same password here")
	if a == b {
		t.Error("two hashes of the same password are equal; the salt is not random")
	}
}

// A hash made with other parameters still verifies: the cost is read from
// the stored string, not from the current defaults.
func TestVerifyReadsParametersFromHash(t *testing.T) {
	UseFastHashes(t)
	h, _ := HashPassword("pa55word-pa55word")
	params = defaultParams
	if ok, err := VerifyPassword(h, "pa55word-pa55word"); err != nil || !ok {
		t.Errorf("VerifyPassword = %v, %v; want true, nil", ok, err)
	}
}

func TestVerifyRejectsMalformedHashes(t *testing.T) {
	salt, key := "c2FsdHNhbHRzYWx0c2FsdA", "a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2U"
	tests := map[string]string{
		"empty":            "",
		"bcrypt":           "$2a$10$abcdefghijklmnopqrstuv",
		"argon2i":          "$argon2i$v=19$m=64,t=1,p=1$" + salt + "$" + key,
		"old version":      "$argon2id$v=16$m=64,t=1,p=1$" + salt + "$" + key,
		"missing part":     "$argon2id$v=19$m=64,t=1,p=1$" + salt,
		"bad params":       "$argon2id$v=19$m=x,t=1,p=1$" + salt + "$" + key,
		"huge memory":      "$argon2id$v=19$m=4194304,t=1,p=1$" + salt + "$" + key,
		"huge time":        "$argon2id$v=19$m=64,t=1000,p=1$" + salt + "$" + key,
		"zero threads":     "$argon2id$v=19$m=64,t=1,p=0$" + salt + "$" + key,
		"short salt":       "$argon2id$v=19$m=64,t=1,p=1$c2FsdA$" + key,
		"bad salt base64":  "$argon2id$v=19$m=64,t=1,p=1$!!!$" + key,
		"short key":        "$argon2id$v=19$m=64,t=1,p=1$" + salt + "$a2V5",
		"key with padding": "$argon2id$v=19$m=64,t=1,p=1$" + salt + "$" + key + "=",
	}
	for name, h := range tests {
		t.Run(name, func(t *testing.T) {
			ok, err := VerifyPassword(h, "anything")
			if ok || !errors.Is(err, ErrMalformedHash) {
				t.Errorf("VerifyPassword = %v, %v; want false, ErrMalformedHash", ok, err)
			}
		})
	}
}
