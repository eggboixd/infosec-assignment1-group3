package keypair

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// kdfAlg is the only key-derivation function this format uses.
const kdfAlg = "argon2id"

// KDFParams are the Argon2id settings and salt stored with a user's keys.
// Storing them, like the PHC string of a password hash, means the cost can
// be raised later without breaking existing keys.
type KDFParams struct {
	Alg     string `bson:"alg"`
	Version int    `bson:"v"`
	Time    uint32 `bson:"t"` // passes over memory
	Memory  uint32 `bson:"m"` // KiB
	Threads uint8  `bson:"p"`
	Salt    []byte `bson:"salt"`
}

const (
	// kekSize is the key-encryption key length: an AES-256 key.
	kekSize = 32
	// saltSize is 16 random bytes, as for the password hash (D26). It is a
	// separate salt from the password hash's, so the KEK never equals the
	// stored hash (D41).
	saltSize = 16
)

// kdfCost is the Argon2id cost for new keys. It is the same as the password
// hash (docs/decisions.md D26: RFC 9106's second option with 2 lanes), so
// guessing a password from a stolen keypairs document costs exactly as much
// as guessing it from the users collection.
type kdfCost struct {
	time    uint32
	memory  uint32
	threads uint8
}

var defaultCost = kdfCost{time: 3, memory: 64 * 1024, threads: 2}

// cost is what new KDFParams use. Tests lower it; existing keys always use
// the parameters stored with them.
var cost = defaultCost

// Upper bounds accepted from a stored document (the same as auth's), so a
// planted or corrupted document cannot make one unlock allocate gigabytes.
const (
	maxTime    = 10
	maxMemory  = 256 * 1024 // KiB
	maxThreads = 16
)

// newKDFParams returns the current cost with a fresh random salt.
func newKDFParams() (KDFParams, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return KDFParams{}, fmt.Errorf("keypair: generate salt: %w", err)
	}
	return KDFParams{
		Alg:     kdfAlg,
		Version: argon2.Version,
		Time:    cost.time,
		Memory:  cost.memory,
		Threads: cost.threads,
		Salt:    salt,
	}, nil
}

// validate checks stored parameters before any memory is allocated for
// them. Anything out of range wraps ErrCorrupt.
func (p KDFParams) validate() error {
	switch {
	case p.Alg != kdfAlg || p.Version != argon2.Version:
		return fmt.Errorf("%w: unsupported KDF", ErrCorrupt)
	case p.Time < 1 || p.Time > maxTime,
		p.Threads < 1 || p.Threads > maxThreads,
		p.Memory < 8*uint32(p.Threads) || p.Memory > maxMemory:
		return fmt.Errorf("%w: KDF parameters out of range", ErrCorrupt)
	case len(p.Salt) < saltSize:
		return fmt.Errorf("%w: KDF salt too short", ErrCorrupt)
	}
	return nil
}

// deriveKEK turns password into the 32-byte key-encryption key with
// Argon2id. The caller must clear() the result when done.
func deriveKEK(password string, p KDFParams) ([]byte, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	pw := []byte(password)
	// Best effort only: the caller's string can't be cleared (D13).
	defer clear(pw)
	return argon2.IDKey(pw, p.Salt, p.Time, p.Memory, p.Threads, kekSize), nil
}
