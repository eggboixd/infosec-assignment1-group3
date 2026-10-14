package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func randBytes(t testing.TB, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// TestAESCTRKnownAnswer checks newStream(AES) against NIST SP 800-38A,
// Appendix F.5.5 "CTR-AES256.Encrypt" (all four blocks). Values were copied
// from the text of the PDF, not typed from memory.
func TestAESCTRKnownAnswer(t *testing.T) {
	key := mustHex(t, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
	iv := mustHex(t, "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff") // "Init. Counter"
	plaintext := mustHex(t, "6bc1bee22e409f96e93d7e117393172a"+
		"ae2d8a571e03ac9c9eb76fac45af8e51"+
		"30c81c46a35ce411e5fbc1191a0a52ef"+
		"f69f2445df4f9b17ad2b417be66c3710")
	want := mustHex(t, "601ec313775789a5b7a7f504bbf3d228"+
		"f443e3ca4d62b59aca84e990cacaf5c5"+
		"2b0930daa23de94ce87017ba2d84988d"+
		"dfc9c58db67aada613c2dd08457941a6")

	enc, err := newStream(AES, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(plaintext))
	enc.XORKeyStream(got, plaintext)
	if !bytes.Equal(got, want) {
		t.Fatalf("encrypt:\n got %x\nwant %x", got, want)
	}

	// F.5.6 (CTR-AES256.Decrypt) uses the same values the other way round.
	dec, err := newStream(AES, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	dec.XORKeyStream(got, want)
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("decrypt:\n got %x\nwant %x", got, plaintext)
	}
}

// TestDESCTRKnownAnswer checks newStream(DES) against NIST's published DES
// known-answer values:
//
//   - NIST CAVP KAT_TDES.zip, files TECBvartext.rsp and TECBvarkey.rsp
//     ([ENCRYPT] section, COUNT as listed). "KEYs" means K1 = K2 = K3, and
//     triple DES with three equal keys is exactly single DES.
//   - The vartext rows are the same values as NIST SP 800-17, Appendix B,
//     Table 1 (key 01 01 01 01 01 01 01 01).
//
// Values were extracted from the .rsp files by script, not typed by hand.
//
// No published DES-CTR vectors exist, so each single-block vector is run
// through our CTR wrapper: with IV = the vector's plaintext and an all-zero
// data block, CTR outputs E_K(IV) XOR 0 = E_K(IV), the published ciphertext.
// This checks our DES key handling and that our CTR starts its counter at
// the IV.
func TestDESCTRKnownAnswer(t *testing.T) {
	tests := []struct {
		file       string
		count      int
		key        string
		plaintext  string
		ciphertext string
	}{
		{"TECBvartext", 0, "0101010101010101", "8000000000000000", "95f8a5e5dd31d900"},
		{"TECBvartext", 1, "0101010101010101", "4000000000000000", "dd7f121ca5015619"},
		{"TECBvartext", 2, "0101010101010101", "2000000000000000", "2e8653104f3834ea"},
		{"TECBvartext", 3, "0101010101010101", "1000000000000000", "4bd388ff6cd81d4f"},
		{"TECBvartext", 55, "0101010101010101", "0000000000000100", "dd7c0bbd61fafd54"},
		{"TECBvartext", 63, "0101010101010101", "0000000000000001", "166b40b44aba4bd6"},
		{"TECBvarkey", 0, "8001010101010101", "0000000000000000", "95a8d72813daa94d"},
		{"TECBvarkey", 1, "4001010101010101", "0000000000000000", "0eec1487dd8c26d5"},
		{"TECBvarkey", 2, "2001010101010101", "0000000000000000", "7ad16ffb79c45926"},
		{"TECBvarkey", 3, "1001010101010101", "0000000000000000", "d3746294ca6a6cf3"},
		{"TECBvarkey", 55, "0101010101010102", "0000000000000000", "869efd7f9f265a09"},
	}
	for _, tt := range tests {
		stream, err := newStream(DES, mustHex(t, tt.key), mustHex(t, tt.plaintext))
		if err != nil {
			t.Fatal(err)
		}
		got := make([]byte, DESIVSize)
		stream.XORKeyStream(got, make([]byte, DESIVSize))
		if want := mustHex(t, tt.ciphertext); !bytes.Equal(got, want) {
			t.Errorf("%s COUNT=%d: got %x, want %x", tt.file, tt.count, got, want)
		}
	}
}

// TestCTRCounterIncrement checks that after the first block, our CTR
// keystream continues with E_K(IV+1), E_K(IV+2), ... where the IV is treated
// as one big-endian number, including the carry when the IV ends in 0xff.
// The expected blocks are computed with a single raw block-cipher call each
// (the primitive, not ECB mode over data).
func TestCTRCounterIncrement(t *testing.T) {
	ivs := map[string]func(n int) []byte{
		"random": func(n int) []byte { return randBytes(t, n) },
		"carry":  func(n int) []byte { iv := randBytes(t, n); iv[n-1] = 0xfe; return iv },
		"wrap":   func(n int) []byte { return bytes.Repeat([]byte{0xff}, n) },
	}
	newBlock := map[Algorithm]func(key []byte) (cipher.Block, error){
		AES: aes.NewCipher,
		DES: des.NewCipher,
	}
	const blocks = 4
	for _, alg := range []Algorithm{AES, DES} {
		for name, mkIV := range ivs {
			t.Run(string(alg)+"/"+name, func(t *testing.T) {
				key := randBytes(t, dekSize(alg))
				iv := mkIV(alg.IVSize())
				block, err := newBlock[alg](key)
				if err != nil {
					t.Fatal(err)
				}
				bs := block.BlockSize()

				want := make([]byte, 0, blocks*bs)
				ctr := bytes.Clone(iv)
				for range blocks {
					out := make([]byte, bs)
					block.Encrypt(out, ctr)
					want = append(want, out...)
					increment(ctr)
				}

				stream, err := newStream(alg, key, iv)
				if err != nil {
					t.Fatal(err)
				}
				got := make([]byte, blocks*bs)
				stream.XORKeyStream(got, make([]byte, blocks*bs)) // zeros in -> keystream out
				if !bytes.Equal(got, want) {
					t.Errorf("keystream:\n got %x\nwant %x", got, want)
				}
			})
		}
	}
}

// increment adds 1 to b as a big-endian number, wrapping at the top.
func increment(b []byte) {
	for i := len(b) - 1; i >= 0; i-- {
		b[i]++
		if b[i] != 0 {
			return
		}
	}
}

// TestRC4KnownAnswer checks newStream(RC4) against RFC 6229 section 2, the
// 256-bit key 0x0102...20 (the key length we use). Each row is 16 keystream
// bytes at the given offset ("DEC" column). Values were extracted from the
// RFC text by script. The RFC's shorter-key vectors are not used because
// newStream only accepts our 32-byte RC4 key.
func TestRC4KnownAnswer(t *testing.T) {
	key := mustHex(t, "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
	tests := []struct {
		offset    int
		keystream string
	}{
		{0, "eaa6bd25880bf93d3f5d1e4ca2611d91"},
		{16, "cfa45c9f7e714b54bdfa80027cb14380"},
		{240, "114ae344ded71b35f2e60febad727fd8"},
		{256, "02e1e7056b0f623900496422943e97b6"},
		{1520, "40f250b26d1f096a4afd4c340a588815"},
		{1536, "3e34135c79db010200767651cf263073"},
		{4080, "a13a7c79c7e119b5ab0296ab28c300b9"},
		{4096, "f3e4c0a2e02d1d01f7f0a74618af2b48"},
	}
	stream, err := newStream(RC4, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	ks := make([]byte, 4096+16)
	stream.XORKeyStream(ks, make([]byte, len(ks))) // zeros in -> keystream out
	for _, tt := range tests {
		if got, want := ks[tt.offset:tt.offset+16], mustHex(t, tt.keystream); !bytes.Equal(got, want) {
			t.Errorf("offset %d: got %x, want %x", tt.offset, got, want)
		}
	}
}

// TestStreamChunking checks that encrypting in pieces of awkward sizes gives
// the same bytes as encrypting in one go. The envelope reads files in chunks,
// so the keystream must continue seamlessly across calls, including in the
// middle of a block.
func TestStreamChunking(t *testing.T) {
	pieces := []int{1, 7, 8, 9, 15, 16, 17, 31, 64, 100}
	data := randBytes(t, 1000)
	for _, alg := range All() {
		t.Run(string(alg), func(t *testing.T) {
			key, iv := randBytes(t, dekSize(alg)), randBytes(t, alg.IVSize())
			if alg == RC4 {
				iv = nil
			}

			whole, err := newStream(alg, key, iv)
			if err != nil {
				t.Fatal(err)
			}
			want := make([]byte, len(data))
			whole.XORKeyStream(want, data)

			chunked, err := newStream(alg, key, iv)
			if err != nil {
				t.Fatal(err)
			}
			got := make([]byte, 0, len(data))
			for off, i := 0, 0; off < len(data); i++ {
				n := min(pieces[i%len(pieces)], len(data)-off)
				out := make([]byte, n)
				chunked.XORKeyStream(out, data[off:off+n])
				got = append(got, out...)
				off += n
			}
			if !bytes.Equal(got, want) {
				t.Error("chunked output differs from one-shot output")
			}
		})
	}
}

func TestNewStreamRejectsBadParams(t *testing.T) {
	tests := []struct {
		name string
		alg  Algorithm
		key  int
		iv   int
	}{
		{"unknown alg", "xor", 32, 16},
		{"empty alg", "", 32, 16},
		{"aes short key", AES, 16, 16}, // AES-128 is valid AES but not what we use
		{"aes long key", AES, 33, 16},
		{"aes no iv", AES, 32, 0},
		{"aes short iv", AES, 32, 15},
		{"aes long iv", AES, 32, 17},
		{"des short key", DES, 7, 8},
		{"des 3des key", DES, 24, 8},
		{"des no iv", DES, 8, 0},
		{"des short iv", DES, 8, 7},
		{"des aes-sized iv", DES, 8, 16},
		{"rc4 empty key", RC4, 0, 0},
		{"rc4 short key", RC4, 16, 0},
		{"rc4 with iv", RC4, 32, 16},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := newStream(tt.alg, make([]byte, tt.key), make([]byte, tt.iv)); err == nil {
				t.Error("newStream accepted bad parameters")
			}
		})
	}
}
