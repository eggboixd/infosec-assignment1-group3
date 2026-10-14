package crypto

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"testing"
)

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

func TestDeriveKey(t *testing.T) {
	master := randBytes(t, MasterKeySize)

	a1, err := DeriveKey(master, "nik-blind-index")
	if err != nil {
		t.Fatal(err)
	}
	a2, _ := DeriveKey(master, "nik-blind-index")
	b, _ := DeriveKey(master, "key-wrap")
	other, _ := DeriveKey(randBytes(t, MasterKeySize), "nik-blind-index")

	if len(a1) != 32 {
		t.Errorf("len = %d, want 32", len(a1))
	}
	if !bytes.Equal(a1, a2) {
		t.Error("same master and info gave different keys")
	}
	if bytes.Equal(a1, b) {
		t.Error("different info gave the same key")
	}
	if bytes.Equal(a1, other) {
		t.Error("different master gave the same key")
	}
	if bytes.Equal(a1, master) {
		t.Error("derived key equals the master key")
	}
}

// TestDeriveKeyMatchesRFC5869 recomputes HKDF by hand from its definition in
// RFC 5869 section 2, using only HMAC-SHA256, and checks DeriveKey agrees:
//
//	PRK = HMAC(salt, IKM), where an absent salt is HashLen zero bytes (2.2)
//	T(1) = HMAC(PRK, info || 0x01); OKM = first L bytes, here L = 32 (2.3)
func TestDeriveKeyMatchesRFC5869(t *testing.T) {
	master := randBytes(t, MasterKeySize)
	const info = "key-wrap"

	extract := hmac.New(sha256.New, make([]byte, sha256.Size))
	extract.Write(master)
	prk := extract.Sum(nil)

	expand := hmac.New(sha256.New, prk)
	expand.Write([]byte(info))
	expand.Write([]byte{0x01})
	want := expand.Sum(nil)[:32]

	got, err := DeriveKey(master, info)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("DeriveKey = %x, hand-computed HKDF = %x", got, want)
	}
}

func TestDeriveKeyRejectsBadInput(t *testing.T) {
	tests := []struct {
		name   string
		master []byte
		info   string
	}{
		{"nil master", nil, "x"},
		{"short master", make([]byte, 16), "x"},
		{"long master", make([]byte, 33), "x"},
		{"empty info", make([]byte, 32), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := DeriveKey(tt.master, tt.info); err == nil {
				t.Error("DeriveKey accepted bad input")
			}
		})
	}
}

func TestWrapKeyRoundTrip(t *testing.T) {
	kek := randBytes(t, MasterKeySize)
	for _, n := range []int{1, desKeySize, aesKeySize, macKeySize, 64} {
		key := randBytes(t, n)
		w1, err := WrapKey(kek, key)
		if err != nil {
			t.Fatal(err)
		}
		if len(w1) != n+28 {
			t.Errorf("len(wrapped %d B) = %d, want %d (12 B nonce + key + 16 B tag)", n, len(w1), n+28)
		}
		if bytes.Contains(w1, key) && n >= 8 {
			t.Error("wrapped output contains the plaintext key")
		}
		w2, _ := WrapKey(kek, key)
		if bytes.Equal(w1, w2) {
			t.Error("wrapping the same key twice gave identical output (nonce reuse?)")
		}
		for _, w := range [][]byte{w1, w2} {
			got, err := UnwrapKey(kek, w)
			if err != nil {
				t.Fatalf("UnwrapKey: %v", err)
			}
			if !bytes.Equal(got, key) {
				t.Errorf("UnwrapKey = %x, want %x", got, key)
			}
		}
	}
}

func TestUnwrapKeyDetectsTampering(t *testing.T) {
	kek := randBytes(t, MasterKeySize)
	wrapped, err := WrapKey(kek, randBytes(t, 32))
	if err != nil {
		t.Fatal(err)
	}

	// Flip one bit in every position: nonce, encrypted key and tag.
	for i := range wrapped {
		bad := bytes.Clone(wrapped)
		bad[i] ^= 0x01
		if _, err := UnwrapKey(kek, bad); !errors.Is(err, ErrAuthentication) {
			t.Errorf("byte %d flipped: err = %v, want ErrAuthentication", i, err)
		}
	}

	cases := map[string][]byte{
		"nil":                nil,
		"nonce only":         wrapped[:12],
		"nonce and tag only": wrapped[:28],
		"one byte short":     wrapped[:len(wrapped)-1],
		"one byte extra":     append(bytes.Clone(wrapped), 0),
	}
	for name, bad := range cases {
		if _, err := UnwrapKey(kek, bad); !errors.Is(err, ErrAuthentication) {
			t.Errorf("%s: err = %v, want ErrAuthentication", name, err)
		}
	}

	if _, err := UnwrapKey(randBytes(t, MasterKeySize), wrapped); !errors.Is(err, ErrAuthentication) {
		t.Errorf("wrong KEK: err = %v, want ErrAuthentication", err)
	}
}

func TestWrapKeyRejectsBadInput(t *testing.T) {
	if _, err := WrapKey(randBytes(t, MasterKeySize), nil); err == nil {
		t.Error("WrapKey accepted an empty key")
	}
	for _, n := range []int{0, 16, 31, 33} {
		if _, err := WrapKey(make([]byte, n), randBytes(t, 32)); err == nil {
			t.Errorf("WrapKey accepted a %d-byte KEK", n)
		}
		if _, err := UnwrapKey(make([]byte, n), make([]byte, 60)); err == nil {
			t.Errorf("UnwrapKey accepted a %d-byte KEK", n)
		}
	}
}
