package crypto

import (
	"crypto/rand"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"
)

// TestFieldReport times encrypting and decrypting one whole profile (the six
// private-data fields) for the report (docs/benchmark/README.md). It is
// skipped unless FIELD_REPORT is set, so `go test ./...` and CI never run it:
//
//	FIELD_REPORT=1 go test -run TestFieldReport -count=1 -v ./internal/crypto
//
// Each algorithm runs fieldReportRuns times; the test prints the median and
// the 95th percentile. The timings include key generation and wrapping,
// like Encrypt and Decrypt in bench_test.go.
func TestFieldReport(t *testing.T) {
	if os.Getenv("FIELD_REPORT") == "" {
		t.Skip("set FIELD_REPORT=1 to run")
	}
	const fieldReportRuns = 3000
	master := make([]byte, MasterKeySize)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	e, err := NewEnvelope(master)
	if err != nil {
		t.Fatal(err)
	}
	// A fake profile: name, NIK, date of birth, address, phone, email.
	fields := [][]byte{
		[]byte("Budi Santoso"),
		[]byte("3578010101900001"),
		[]byte("1990-01-01"),
		[]byte("Jl. Teknik Kimia, Keputih, Sukolilo, Surabaya"),
		[]byte("081234567890"),
		[]byte("budi.santoso@example.com"),
	}
	total := 0
	for _, f := range fields {
		total += len(f)
	}
	fmt.Println("bytes", total)

	type sealed struct {
		ct   []byte
		meta Meta
	}
	for _, alg := range All() {
		var enc, dec []time.Duration
		for range fieldReportRuns {
			out := make([]sealed, 0, len(fields))
			start := time.Now()
			for _, f := range fields {
				ct, meta, err := e.EncryptField(alg, f)
				if err != nil {
					t.Fatal(err)
				}
				out = append(out, sealed{ct, meta})
			}
			enc = append(enc, time.Since(start))

			start = time.Now()
			for _, s := range out {
				if _, err := e.DecryptField(alg, s.meta, s.ct); err != nil {
					t.Fatal(err)
				}
			}
			dec = append(dec, time.Since(start))
		}
		slices.Sort(enc)
		slices.Sort(dec)
		p50, p95 := fieldReportRuns/2, fieldReportRuns*95/100
		fmt.Printf("%s enc med=%v p95=%v dec med=%v p95=%v\n", alg, enc[p50], enc[p95], dec[p50], dec[p95])
	}
}
