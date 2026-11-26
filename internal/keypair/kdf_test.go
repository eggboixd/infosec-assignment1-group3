package keypair

import (
	"bytes"
	"errors"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestNewKDFParamsUsesDefaultCostAndFreshSalt(t *testing.T) {
	a, err := newKDFParams()
	if err != nil {
		t.Fatal(err)
	}
	b, err := newKDFParams()
	if err != nil {
		t.Fatal(err)
	}
	if a.Alg != "argon2id" || a.Version != argon2.Version || a.Time != 3 || a.Memory != 64*1024 || a.Threads != 2 {
		t.Errorf("params = %+v, want argon2id v19 t=3 m=65536 p=2 (D26)", a)
	}
	if len(a.Salt) != saltSize {
		t.Errorf("salt is %d bytes, want %d", len(a.Salt), saltSize)
	}
	if bytes.Equal(a.Salt, b.Salt) {
		t.Error("two salts are equal; want a fresh random salt each time")
	}
	if err := a.validate(); err != nil {
		t.Errorf("default params do not validate: %v", err)
	}
}

func TestDeriveKEK(t *testing.T) {
	useFastKDF(t)
	p, err := newKDFParams()
	if err != nil {
		t.Fatal(err)
	}
	k1, err := deriveKEK("correct horse battery", p)
	if err != nil {
		t.Fatal(err)
	}
	if len(k1) != kekSize {
		t.Fatalf("KEK is %d bytes, want %d", len(k1), kekSize)
	}
	k2, _ := deriveKEK("correct horse battery", p)
	if !bytes.Equal(k1, k2) {
		t.Error("same password and salt gave different KEKs")
	}
	if k3, _ := deriveKEK("correct horse batterY", p); bytes.Equal(k1, k3) {
		t.Error("different passwords gave the same KEK")
	}
	other := p
	other.Salt = randomBytes(t, saltSize)
	// This is why the KEK has its own salt (D41): with another salt the
	// same password gives an unrelated key, so the stored password hash
	// (different salt) is not the KEK.
	if k4, _ := deriveKEK("correct horse battery", other); bytes.Equal(k1, k4) {
		t.Error("different salts gave the same KEK")
	}
}

// Stored parameters are checked before Argon2id runs, so a planted document
// can't make an unlock allocate gigabytes or run for minutes.
func TestKDFParamsValidate(t *testing.T) {
	good := KDFParams{Alg: "argon2id", Version: argon2.Version, Time: 3, Memory: 64 * 1024, Threads: 2, Salt: make([]byte, 16)}
	tests := []struct {
		name   string
		mutate func(*KDFParams)
	}{
		{"wrong algorithm", func(p *KDFParams) { p.Alg = "argon2i" }},
		{"empty algorithm", func(p *KDFParams) { p.Alg = "" }},
		{"wrong version", func(p *KDFParams) { p.Version = 0x10 }},
		{"zero time", func(p *KDFParams) { p.Time = 0 }},
		{"time too high", func(p *KDFParams) { p.Time = maxTime + 1 }},
		{"zero threads", func(p *KDFParams) { p.Threads = 0 }},
		{"too many threads", func(p *KDFParams) { p.Threads = maxThreads + 1 }},
		{"memory below 8 KiB per lane", func(p *KDFParams) { p.Memory = 15 }},
		{"memory too high", func(p *KDFParams) { p.Memory = maxMemory + 1 }},
		{"memory 4 GiB", func(p *KDFParams) { p.Memory = 1 << 22 }},
		{"no salt", func(p *KDFParams) { p.Salt = nil }},
		{"short salt", func(p *KDFParams) { p.Salt = make([]byte, 15) }},
	}
	if err := good.validate(); err != nil {
		t.Fatalf("good params: %v", err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := good
			tt.mutate(&p)
			if err := p.validate(); !errors.Is(err, ErrCorrupt) {
				t.Errorf("validate = %v, want ErrCorrupt", err)
			}
			if _, err := deriveKEK("password", p); !errors.Is(err, ErrCorrupt) {
				t.Errorf("deriveKEK = %v, want ErrCorrupt", err)
			}
		})
	}
}
