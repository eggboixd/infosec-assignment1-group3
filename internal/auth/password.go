package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// ErrMalformedHash is returned by VerifyPassword for a string that is not a
// supported Argon2id PHC hash.
var ErrMalformedHash = errors.New("auth: malformed password hash")

// hashParams are the Argon2id cost parameters (see docs/decisions.md D26).
type hashParams struct {
	time    uint32 // passes over memory
	memory  uint32 // KiB
	threads uint8
	saltLen int
	keyLen  uint32
}

// defaultParams follow RFC 9106 section 4's second recommended option
// (t=3, 64 MiB), with 2 lanes instead of 4 to suit a small container.
var defaultParams = hashParams{time: 3, memory: 64 * 1024, threads: 2, saltLen: 16, keyLen: 32}

// params is what HashPassword uses. Tests lower it so they run quickly; the
// cost of an existing hash is always read from the hash itself.
var params = defaultParams

// Upper bounds accepted when parsing a stored hash, so a corrupted or
// planted document cannot make one login allocate gigabytes.
const (
	maxTime    = 10
	maxMemory  = 256 * 1024 // KiB
	maxThreads = 16
)

// b64 is the PHC string encoding: standard alphabet, no padding.
var b64 = base64.RawStdEncoding

// HashPassword returns an Argon2id hash of password in PHC string format:
//
//	$argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>
//
// The salt is 16 random bytes from crypto/rand, so hashing the same password
// twice gives different strings.
func HashPassword(password string) (string, error) {
	p := params
	salt := make([]byte, p.saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: generate salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, p.time, p.memory, p.threads, p.keyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.memory, p.time, p.threads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// VerifyPassword reports whether password matches encoded. A wrong password
// is (false, nil); an unparsable hash is an error wrapping ErrMalformedHash.
// The final comparison is constant-time.
func VerifyPassword(encoded, password string) (bool, error) {
	p, salt, want, err := parseHash(encoded)
	if err != nil {
		return false, err
	}
	got := argon2.IDKey([]byte(password), salt, p.time, p.memory, p.threads, uint32(len(want))) // #nosec G115 -- len(want) is checked to be at most 64 in parseHash.
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// parseHash splits a PHC string into its parameters, salt and key.
func parseHash(encoded string) (hashParams, []byte, []byte, error) {
	// "", "argon2id", "v=19", "m=..,t=..,p=..", salt, key
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return hashParams{}, nil, nil, ErrMalformedHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return hashParams{}, nil, nil, fmt.Errorf("%w: unsupported version", ErrMalformedHash)
	}
	var p hashParams
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.memory, &p.time, &p.threads); err != nil {
		return hashParams{}, nil, nil, fmt.Errorf("%w: parameters", ErrMalformedHash)
	}
	if p.time < 1 || p.time > maxTime || p.memory < 8*uint32(p.threads) || p.memory > maxMemory ||
		p.threads < 1 || p.threads > maxThreads {
		return hashParams{}, nil, nil, fmt.Errorf("%w: parameters out of range", ErrMalformedHash)
	}
	salt, err := b64.DecodeString(parts[4])
	if err != nil || len(salt) < 8 {
		return hashParams{}, nil, nil, fmt.Errorf("%w: salt", ErrMalformedHash)
	}
	key, err := b64.DecodeString(parts[5])
	if err != nil || len(key) < 16 || len(key) > 64 {
		return hashParams{}, nil, nil, fmt.Errorf("%w: key", ErrMalformedHash)
	}
	return p, salt, key, nil
}
