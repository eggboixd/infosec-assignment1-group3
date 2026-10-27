package main

import (
	"io"
	"net/http"
	"testing"

	"github.com/eggboixd/infosec-assignment1-group3/internal/benchmark"
)

func TestFakeVideoIsDetectedAsMP4(t *testing.T) {
	for _, size := range []int64{24, 1 << 10, 1 << 20} {
		b, err := io.ReadAll(fakeVideo(size))
		if err != nil {
			t.Fatal(err)
		}
		if int64(len(b)) != size {
			t.Errorf("%d bytes, want %d", len(b), size)
		}
		if got := http.DetectContentType(b); got != "video/mp4" {
			t.Errorf("size %d detected as %q, want video/mp4", size, got)
		}
	}
}

func TestParseAndFormatSizes(t *testing.T) {
	got, err := parseSizes("1KiB, 64KiB,1MiB,2GiB,100,7B")
	if err != nil {
		t.Fatal(err)
	}
	want := []int64{1 << 10, 64 << 10, 1 << 20, 2 << 30, 100, 7}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("size %d = %d, want %d", i, got[i], want[i])
		}
	}
	for _, bad := range []string{"", "0", "-1KiB", "1.5MiB", "3GiB", "10TB", "KiB"} {
		if _, err := parseSizes(bad); err == nil {
			t.Errorf("parseSizes(%q) accepted", bad)
		}
	}
	for n, want := range map[int64]string{1 << 10: "1KiB", 16 << 20: "16MiB", 1000: "1000B", 3 << 30: "3GiB"} {
		if got := formatSize(n); got != want {
			t.Errorf("formatSize(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestCheckCounts(t *testing.T) {
	var recs []benchmark.Record
	add := func(op benchmark.Operation, k int) {
		for range k {
			recs = append(recs, benchmark.Record{Operation: op})
		}
	}
	// 2 sizes, 4 uploads and n = 3 each: 24 encrypts, 18 decrypts, 18 downloads.
	add(benchmark.OpEncrypt, 24)
	add(benchmark.OpDecrypt, 18)
	add(benchmark.OpDownload, 18)
	if err := checkCounts(recs, 2, 4, 3); err != nil {
		t.Errorf("complete run rejected: %v", err)
	}
	if err := checkCounts(recs, 2, 1, 3); err == nil {
		t.Error("extra uploads were not noticed")
	}
	if err := checkCounts(recs[1:], 2, 4, 3); err == nil {
		t.Error("a missing record was not noticed")
	}
	add(benchmark.OpEncrypt, 1) // another client's private-data save, say
	if err := checkCounts(recs, 2, 4, 3); err == nil {
		t.Error("an extra record was not noticed")
	}
}
