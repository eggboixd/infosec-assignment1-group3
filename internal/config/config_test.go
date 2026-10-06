package config

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// validKey is 32 zero bytes. It is a test fixture, not a real key.
var validKey = base64.StdEncoding.EncodeToString(make([]byte, 32))

func validEnv() map[string]string {
	return map[string]string{
		"MONGO_URI":        "mongodb://user:pass@localhost:27017",
		"MINIO_ENDPOINT":   "localhost:9000",
		"MINIO_ACCESS_KEY": "test-access",
		"MINIO_SECRET_KEY": "test-secret",
		"MASTER_KEY":       validKey,
		"SESSION_SECRET":   strings.Repeat("s", 32),
	}
}

func lookupFrom(env map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := env[k]
		return v, ok
	}
}

func TestLoadFromDefaults(t *testing.T) {
	cfg, err := LoadFrom(lookupFrom(validEnv()))
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	if cfg.HTTPAddr != ":8080" {
		t.Errorf("HTTPAddr = %q, want :8080", cfg.HTTPAddr)
	}
	if cfg.GinMode != "release" {
		t.Errorf("GinMode = %q, want release", cfg.GinMode)
	}
	if cfg.ShutdownTimeout != 15*time.Second {
		t.Errorf("ShutdownTimeout = %v, want 15s", cfg.ShutdownTimeout)
	}
	if cfg.MaxBodyBytes != 2<<30 {
		t.Errorf("MaxBodyBytes = %d, want %d", cfg.MaxBodyBytes, int64(2<<30))
	}
	if len(cfg.MasterKey) != 32 {
		t.Errorf("len(MasterKey) = %d, want 32", len(cfg.MasterKey))
	}
	if cfg.MinIOUseSSL {
		t.Error("MinIOUseSSL = true, want false")
	}
}

func TestLoadFromOverrides(t *testing.T) {
	env := validEnv()
	env["HTTP_ADDR"] = ":9090"
	env["GIN_MODE"] = "debug"
	env["MAX_BODY_BYTES"] = "1024"
	env["SHUTDOWN_TIMEOUT"] = "3s"
	env["MINIO_USE_SSL"] = "true"
	env["MONGO_DATABASE"] = "other"

	cfg, err := LoadFrom(lookupFrom(env))
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	if cfg.HTTPAddr != ":9090" || cfg.GinMode != "debug" || cfg.MaxBodyBytes != 1024 ||
		cfg.ShutdownTimeout != 3*time.Second || !cfg.MinIOUseSSL || cfg.MongoDatabase != "other" {
		t.Errorf("overrides not applied: %+v", cfg)
	}
}

func TestLoadFromErrors(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(map[string]string)
		wantErr string
	}{
		{"missing mongo uri", func(e map[string]string) { delete(e, "MONGO_URI") }, "MONGO_URI is required"},
		{"blank minio endpoint", func(e map[string]string) { e["MINIO_ENDPOINT"] = "  " }, "MINIO_ENDPOINT is required"},
		{"missing access key", func(e map[string]string) { delete(e, "MINIO_ACCESS_KEY") }, "MINIO_ACCESS_KEY is required"},
		{"missing secret key", func(e map[string]string) { delete(e, "MINIO_SECRET_KEY") }, "MINIO_SECRET_KEY is required"},
		{"missing master key", func(e map[string]string) { delete(e, "MASTER_KEY") }, "MASTER_KEY is required"},
		{"master key not base64", func(e map[string]string) { e["MASTER_KEY"] = "not base64!" }, "standard base64"},
		{"master key too short", func(e map[string]string) {
			e["MASTER_KEY"] = base64.StdEncoding.EncodeToString(make([]byte, 16))
		}, "32 bytes, got 16"},
		{"missing session secret", func(e map[string]string) { delete(e, "SESSION_SECRET") }, "SESSION_SECRET is required"},
		{"short session secret", func(e map[string]string) { e["SESSION_SECRET"] = "short" }, "at least 32"},
		{"bad gin mode", func(e map[string]string) { e["GIN_MODE"] = "prod" }, "GIN_MODE"},
		{"bad body size", func(e map[string]string) { e["MAX_BODY_BYTES"] = "big" }, "MAX_BODY_BYTES must be an integer"},
		{"zero body size", func(e map[string]string) { e["MAX_BODY_BYTES"] = "0" }, "MAX_BODY_BYTES must be positive"},
		{"bad timeout", func(e map[string]string) { e["SHUTDOWN_TIMEOUT"] = "15" }, "SHUTDOWN_TIMEOUT must be a duration"},
		{"negative timeout", func(e map[string]string) { e["SHUTDOWN_TIMEOUT"] = "-1s" }, "SHUTDOWN_TIMEOUT must be positive"},
		{"bad ssl flag", func(e map[string]string) { e["MINIO_USE_SSL"] = "maybe" }, "MINIO_USE_SSL must be a boolean"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := validEnv()
			tt.mutate(env)
			_, err := LoadFrom(lookupFrom(env))
			if err == nil {
				t.Fatalf("LoadFrom succeeded, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadFromReportsAllErrors(t *testing.T) {
	_, err := LoadFrom(lookupFrom(map[string]string{}))
	if err == nil {
		t.Fatal("LoadFrom succeeded with empty environment")
	}
	for _, key := range []string{"MONGO_URI", "MINIO_ENDPOINT", "MASTER_KEY", "SESSION_SECRET"} {
		if !strings.Contains(err.Error(), key) {
			t.Errorf("error %q does not mention %s", err, key)
		}
	}
}

func TestErrorsAndStringDoNotLeakSecrets(t *testing.T) {
	env := validEnv()
	env["MASTER_KEY"] = "c2VjcmV0LXZhbHVl" // decodes to 12 bytes, so invalid
	_, err := LoadFrom(lookupFrom(env))
	if err == nil || strings.Contains(err.Error(), env["MASTER_KEY"]) {
		t.Errorf("error leaks master key or is nil: %v", err)
	}

	cfg, err := LoadFrom(lookupFrom(validEnv()))
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	s := cfg.String()
	for _, secret := range []string{"test-secret", "test-access", strings.Repeat("s", 32), "user:pass"} {
		if strings.Contains(s, secret) {
			t.Errorf("String() leaks %q: %s", secret, s)
		}
	}
}
