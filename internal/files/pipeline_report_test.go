package files

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
)

// TestPipelineReport times the real upload and download pipeline for the
// report (docs/benchmark/README.md). It is skipped unless PIPE_REPORT names
// the CSV file to write, so `go test ./...` and CI never run it:
//
//	PIPE_REPORT=docs/benchmark/pipe.csv go test -run TestPipelineReport -count=1 ./internal/files
//
// Each kind is uploaded, downloaded once per algorithm and deleted, for
// pipeReportRuns rounds. Storage is in memory (memObjects, memMeta), so the
// timings show the pipeline and the ciphers without MinIO or network time.
// Round 0 is a warm-up; the report uses the median of the other rounds.
func TestPipelineReport(t *testing.T) {
	path := os.Getenv("PIPE_REPORT")
	if path == "" {
		t.Skip("set PIPE_REPORT=<csv path> to run")
	}
	const pipeReportRuns = 7
	cases := []struct {
		kind Kind
		name string
		head string // sample whose first bytes pass the content check
		size int
	}{
		{KindIDCard, "ktp.jpg", "ktp-fake.jpg", 1 << 20},
		{KindDocument, "doc.pdf", "sample.pdf", 10 << 20},
		{KindVideo, "clip.mp4", "sample.mp4", 100 << 20},
	}

	out, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	fmt.Fprintln(out, "kind,bytes,op,alg,run,crypto_ns,total_ns,wall_ns")

	ctx := context.Background()
	for _, c := range cases {
		r := newTestRig(t)
		// Random bytes behind the first 4 KiB of a real sample file.
		data := make([]byte, c.size)
		if _, err := rand.Read(data); err != nil {
			t.Fatal(err)
		}
		h := sample(t, c.head)
		copy(data, h[:min(len(h), 4096)])
		owner := bson.NewObjectID()

		for run := range pipeReportRuns {
			before := len(r.bench.Records())
			start := time.Now()
			rec, err := r.svc.Upload(ctx, owner, c.kind, c.name, bytes.NewReader(data))
			wall := time.Since(start)
			if err != nil {
				t.Fatal(err)
			}
			for _, b := range r.bench.Records()[before:] {
				fmt.Fprintf(out, "%s,%d,upload,%s,%d,%d,%d,%d\n", c.kind, c.size, b.Algorithm, run, b.CryptoDuration, b.TotalDuration, wall)
			}
			for _, alg := range crypto.All() {
				before := len(r.bench.Records())
				start := time.Now()
				if err := r.svc.Download(ctx, rec, alg, io.Discard); err != nil {
					t.Fatal(err)
				}
				wall := time.Since(start)
				b := r.bench.Records()[before]
				fmt.Fprintf(out, "%s,%d,download,%s,%d,%d,%d,%d\n", c.kind, c.size, alg, run, b.CryptoDuration, b.TotalDuration, wall)
			}
			if err := r.svc.Delete(ctx, owner, rec.ID); err != nil {
				t.Fatal(err)
			}
		}
	}
}
