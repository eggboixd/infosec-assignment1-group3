package crypto

import (
	"bytes"
	"context"
	"io"
	"testing"
)

// Benchmarks for the report. Run, for example:
//
//	go test -run=^$ -bench=. -benchmem ./internal/crypto
//
// Add -short to skip the 100 MiB size. Each result line shows MB/s because
// of b.SetBytes. Three views are measured:
//
//   - Keystream: newStream + XORKeyStream only, i.e. the raw cipher.
//   - Encrypt:   the full Envelope.Encrypt (key generation, key wrapping,
//     cipher, HMAC).
//   - Decrypt:   the full Envelope.Decrypt (unwrapping, verify pass, decrypt
//     pass).
//
// The difference between Keystream and Encrypt/Decrypt is the fixed cost of
// the envelope (dominant for small inputs) plus HMAC-SHA256.
var benchSizes = []struct {
	name string
	n    int
}{
	{"1KiB", 1 << 10},
	{"1MiB", 1 << 20},
	{"10MiB", 10 << 20},
	{"100MiB", 100 << 20},
}

func forEachBench(b *testing.B, fn func(b *testing.B, alg Algorithm, data []byte)) {
	for _, alg := range All() {
		for _, size := range benchSizes {
			b.Run(string(alg)+"/"+size.name, func(b *testing.B) {
				if testing.Short() && size.n > 10<<20 {
					b.Skip("skipping 100 MiB in -short mode")
				}
				data := randBytes(b, size.n)
				b.SetBytes(int64(size.n))
				b.ReportAllocs()
				fn(b, alg, data)
			})
		}
	}
}

func BenchmarkKeystream(b *testing.B) {
	forEachBench(b, func(b *testing.B, alg Algorithm, data []byte) {
		key, iv := randBytes(b, dekSize(alg)), randBytes(b, alg.IVSize())
		if alg == RC4 {
			iv = nil
		}
		for b.Loop() {
			stream, err := newStream(alg, key, iv)
			if err != nil {
				b.Fatal(err)
			}
			stream.XORKeyStream(data, data)
		}
	})
}

func BenchmarkEncrypt(b *testing.B) {
	e := newTestEnvelope(b)
	ctx := context.Background()
	forEachBench(b, func(b *testing.B, alg Algorithm, data []byte) {
		src := bytes.NewReader(data)
		for b.Loop() {
			src.Reset(data)
			if _, err := e.Encrypt(ctx, alg, io.Discard, src); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkDecrypt(b *testing.B) {
	e := newTestEnvelope(b)
	ctx := context.Background()
	forEachBench(b, func(b *testing.B, alg Algorithm, data []byte) {
		var ct bytes.Buffer
		meta, err := e.Encrypt(ctx, alg, &ct, bytes.NewReader(data))
		if err != nil {
			b.Fatal(err)
		}
		src := bytes.NewReader(ct.Bytes())
		for b.Loop() {
			if err := e.Decrypt(ctx, alg, meta, io.Discard, src); err != nil {
				b.Fatal(err)
			}
		}
	})
}
