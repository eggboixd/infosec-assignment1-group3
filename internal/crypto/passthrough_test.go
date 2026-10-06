package crypto

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func TestParseAlgorithm(t *testing.T) {
	tests := []struct {
		in      string
		want    Algorithm
		wantErr bool
	}{
		{"aes", AES, false},
		{"des", DES, false},
		{"rc4", RC4, false},
		{"AES", "", true},
		{"", "", true},
		{"3des", "", true},
	}
	for _, tt := range tests {
		got, err := ParseAlgorithm(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseAlgorithm(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
		}
		if tt.wantErr && !errors.Is(err, ErrUnknownAlgorithm) {
			t.Errorf("ParseAlgorithm(%q) error = %v, want ErrUnknownAlgorithm", tt.in, err)
		}
		if got != tt.want {
			t.Errorf("ParseAlgorithm(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestIVSize(t *testing.T) {
	want := map[Algorithm]int{AES: 16, DES: 8, RC4: 0}
	for _, alg := range All() {
		if got := alg.IVSize(); got != want[alg] {
			t.Errorf("%s.IVSize() = %d, want %d", alg, got, want[alg])
		}
	}
}

func TestPassthroughStreamRoundTrip(t *testing.T) {
	inputs := map[string][]byte{
		"empty": {},
		"small": []byte("hello, world"),
		"large": bytes.Repeat([]byte{0x00, 0xff, 0x5a}, 1<<16),
	}
	var enc Encryptor = PassthroughEncryptor{}
	for _, alg := range All() {
		for name, plaintext := range inputs {
			t.Run(string(alg)+"/"+name, func(t *testing.T) {
				ctx, clock := WithClock(context.Background())

				var ct bytes.Buffer
				meta, err := enc.Encrypt(ctx, alg, &ct, bytes.NewReader(plaintext))
				if err != nil {
					t.Fatalf("Encrypt: %v", err)
				}
				if meta.Algorithm != alg {
					t.Errorf("meta.Algorithm = %q, want %q", meta.Algorithm, alg)
				}
				if len(meta.IV) != alg.IVSize() {
					t.Errorf("len(meta.IV) = %d, want %d", len(meta.IV), alg.IVSize())
				}

				// Pass a reader positioned at the end to check that Decrypt
				// seeks back to the start, as the two-pass flow requires.
				src := bytes.NewReader(ct.Bytes())
				_, _ = src.Seek(0, 2)
				var pt bytes.Buffer
				if err := enc.Decrypt(ctx, alg, meta, &pt, src); err != nil {
					t.Fatalf("Decrypt: %v", err)
				}
				if !bytes.Equal(pt.Bytes(), plaintext) {
					t.Errorf("round trip mismatch: got %d bytes, want %d", pt.Len(), len(plaintext))
				}
				if clock.Elapsed() < 0 {
					t.Errorf("clock elapsed negative: %v", clock.Elapsed())
				}
			})
		}
	}
}

func TestPassthroughFieldRoundTrip(t *testing.T) {
	var enc Encryptor = PassthroughEncryptor{}
	plaintext := []byte("3171234567890001")
	for _, alg := range All() {
		t.Run(string(alg), func(t *testing.T) {
			ct, meta, err := enc.EncryptField(alg, plaintext)
			if err != nil {
				t.Fatalf("EncryptField: %v", err)
			}
			got, err := enc.DecryptField(alg, meta, ct)
			if err != nil {
				t.Fatalf("DecryptField: %v", err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Errorf("DecryptField = %q, want %q", got, plaintext)
			}
		})
	}
}

func TestPassthroughRejectsBadInput(t *testing.T) {
	enc := PassthroughEncryptor{}
	ctx := context.Background()

	if _, err := enc.Encrypt(ctx, "xor", &bytes.Buffer{}, bytes.NewReader(nil)); !errors.Is(err, ErrUnknownAlgorithm) {
		t.Errorf("Encrypt with unknown alg: err = %v", err)
	}
	if _, _, err := enc.EncryptField("xor", nil); !errors.Is(err, ErrUnknownAlgorithm) {
		t.Errorf("EncryptField with unknown alg: err = %v", err)
	}
	meta := Meta{Algorithm: AES}
	if err := enc.Decrypt(ctx, DES, meta, &bytes.Buffer{}, bytes.NewReader(nil)); err == nil {
		t.Error("Decrypt with mismatched meta succeeded")
	}
	if _, err := enc.DecryptField(DES, meta, nil); err == nil {
		t.Error("DecryptField with mismatched meta succeeded")
	}
}

func TestLoadMasterKey(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"valid", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", false},
		{"short", "AAAAAAAAAAAAAAAAAAAAAA==", true},
		{"not base64", "%%%", true},
		{"empty", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := LoadMasterKey(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && len(key) != MasterKeySize {
				t.Errorf("len = %d, want %d", len(key), MasterKeySize)
			}
		})
	}
}

func TestClockNilSafe(t *testing.T) {
	var c *Clock
	c.Add(5)
	if c.Elapsed() != 0 {
		t.Error("nil clock reported elapsed time")
	}
	if ClockFrom(context.Background()) != nil {
		t.Error("ClockFrom on bare context returned non-nil")
	}
}
