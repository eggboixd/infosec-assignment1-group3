// Package config loads and validates application settings from environment
// variables. Loading fails fast: any missing or malformed value is reported
// before the server connects to anything.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
)

// minSessionSecretLen is the minimum length of SESSION_SECRET in bytes.
const minSessionSecretLen = 32

// Config holds every runtime setting. Secret values are kept here only so
// they can be handed to the components that need them; never log a Config.
type Config struct {
	HTTPAddr        string
	GinMode         string
	MaxBodyBytes    int64
	ShutdownTimeout time.Duration

	MongoURI      string
	MongoDatabase string

	MinIOEndpoint  string
	MinIOAccessKey string
	MinIOSecretKey string
	MinIOBucket    string
	MinIOUseSSL    bool

	// MasterKey is the decoded key-encryption key (KEK), crypto.MasterKeySize bytes.
	MasterKey []byte
	// SessionSecret keys the HMAC that turns session tokens into stored IDs.
	SessionSecret []byte
	// CookieSecure marks session cookies Secure. Set it when the app is
	// served over HTTPS; the Docker setup serves plain HTTP on localhost.
	CookieSecure bool
}

// String redacts secrets so a Config printed by accident leaks nothing.
func (c Config) String() string {
	return fmt.Sprintf("Config{HTTPAddr:%s GinMode:%s MongoDatabase:%s MinIOEndpoint:%s MinIOBucket:%s secrets:redacted}",
		c.HTTPAddr, c.GinMode, c.MongoDatabase, c.MinIOEndpoint, c.MinIOBucket)
}

// Load reads the configuration from the process environment.
func Load() (Config, error) {
	return LoadFrom(os.LookupEnv)
}

// LoadFrom reads the configuration using lookup, which has the signature of
// os.LookupEnv. Tests pass a map-backed lookup instead of mutating the
// process environment. All problems are collected and returned together.
func LoadFrom(lookup func(string) (string, bool)) (Config, error) {
	l := loader{lookup: lookup}

	cfg := Config{
		HTTPAddr:        l.optional("HTTP_ADDR", ":8080"),
		GinMode:         l.optional("GIN_MODE", "release"),
		MaxBodyBytes:    l.int64("MAX_BODY_BYTES", 2<<30), // 2 GiB, sized for video uploads
		ShutdownTimeout: l.duration("SHUTDOWN_TIMEOUT", 15*time.Second),

		MongoURI:      l.required("MONGO_URI"),
		MongoDatabase: l.optional("MONGO_DATABASE", "securestore"),

		MinIOEndpoint:  l.required("MINIO_ENDPOINT"),
		MinIOAccessKey: l.required("MINIO_ACCESS_KEY"),
		MinIOSecretKey: l.required("MINIO_SECRET_KEY"),
		MinIOBucket:    l.optional("MINIO_BUCKET", "securestore"),
		MinIOUseSSL:    l.bool("MINIO_USE_SSL", false),

		MasterKey:     l.masterKey("MASTER_KEY"),
		SessionSecret: l.sessionSecret("SESSION_SECRET"),
		CookieSecure:  l.bool("COOKIE_SECURE", false),
	}

	switch cfg.GinMode {
	case "debug", "release", "test":
	default:
		l.fail("GIN_MODE must be one of debug, release, test")
	}
	if cfg.MaxBodyBytes <= 0 {
		l.fail("MAX_BODY_BYTES must be positive")
	}
	if cfg.ShutdownTimeout <= 0 {
		l.fail("SHUTDOWN_TIMEOUT must be positive")
	}

	if len(l.errs) > 0 {
		return Config{}, fmt.Errorf("invalid configuration: %w", errors.Join(l.errs...))
	}
	return cfg, nil
}

type loader struct {
	lookup func(string) (string, bool)
	errs   []error
}

func (l *loader) fail(format string, args ...any) {
	l.errs = append(l.errs, fmt.Errorf(format, args...))
}

func (l *loader) get(key string) (string, bool) {
	v, ok := l.lookup(key)
	v = strings.TrimSpace(v)
	return v, ok && v != ""
}

func (l *loader) required(key string) string {
	v, ok := l.get(key)
	if !ok {
		l.fail("%s is required", key)
	}
	return v
}

func (l *loader) optional(key, def string) string {
	if v, ok := l.get(key); ok {
		return v
	}
	return def
}

func (l *loader) int64(key string, def int64) int64 {
	v, ok := l.get(key)
	if !ok {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		l.fail("%s must be an integer", key)
		return 0
	}
	return n
}

func (l *loader) bool(key string, def bool) bool {
	v, ok := l.get(key)
	if !ok {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		l.fail("%s must be a boolean", key)
		return false
	}
	return b
}

func (l *loader) duration(key string, def time.Duration) time.Duration {
	v, ok := l.get(key)
	if !ok {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		l.fail("%s must be a duration such as 15s", key)
		return 0
	}
	return d
}

// masterKey decodes the master key. The error never includes the value.
func (l *loader) masterKey(key string) []byte {
	v := l.required(key)
	if v == "" {
		return nil
	}
	b, err := crypto.LoadMasterKey(v)
	if err != nil {
		l.fail("%s: %w", key, err)
		return nil
	}
	return b
}

func (l *loader) sessionSecret(key string) []byte {
	v := l.required(key)
	if v == "" {
		return nil
	}
	if len(v) < minSessionSecretLen {
		l.fail("%s must be at least %d characters", key, minSessionSecretLen)
		return nil
	}
	return []byte(v)
}
