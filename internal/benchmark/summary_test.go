package benchmark

import (
	"math"
	"testing"
	"time"

	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
)

func rec(op Operation, kind string, alg crypto.Algorithm, n int64, cryptoMS, totalMS float64) Record {
	return Record{
		Operation: op, FileKind: kind, Algorithm: alg, Bytes: n,
		CryptoDuration: time.Duration(cryptoMS * float64(time.Millisecond)),
		TotalDuration:  time.Duration(totalMS * float64(time.Millisecond)),
	}
}

func TestSummarizeStatistics(t *testing.T) {
	// 1 MiB decrypted in 2, 4 and 6 ms: mean 4, sample sd 2, min 2,
	// throughput 3 MiB / 12 ms = 250 MiB/s.
	stats := Summarize([]Record{
		rec(OpDecrypt, "video", crypto.DES, 1<<20, 2, 10),
		rec(OpDecrypt, "video", crypto.DES, 1<<20, 4, 20),
		rec(OpDecrypt, "video", crypto.DES, 1<<20, 6, 30),
	})
	if len(stats) != 1 {
		t.Fatalf("%d groups, want 1", len(stats))
	}
	s := stats[0]
	if s.Count != 3 || s.Bytes != 3<<20 {
		t.Errorf("count %d bytes %d", s.Count, s.Bytes)
	}
	checks := []struct {
		name      string
		got, want float64
	}{
		{"crypto mean", s.Crypto.MeanMS(), 4},
		{"crypto sd", s.Crypto.StdDevMS(), 2},
		{"crypto min", s.Crypto.MinMS(), 2},
		{"total mean", s.Total.MeanMS(), 20},
		{"crypto MiB/s", s.CryptoMiBPerSec(), 250},
		{"total MiB/s", s.TotalMiBPerSec(), 50},
	}
	for _, c := range checks {
		if math.Abs(c.got-c.want) > 1e-6 {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
	if s.Size.Label != "64 KiB–1 MiB" {
		t.Errorf("size class %q", s.Size.Label)
	}
}

func TestSummarizeSingleRecordHasNoSpread(t *testing.T) {
	s := Summarize([]Record{rec(OpEncrypt, "", crypto.RC4, 100, 0.5, 1)})[0]
	if s.Crypto.StdDev != 0 || s.Crypto.Min != s.Crypto.Mean {
		t.Errorf("sd %v min %v mean %v", s.Crypto.StdDev, s.Crypto.Min, s.Crypto.Mean)
	}
}

func TestSummarizeZeroTimeThroughput(t *testing.T) {
	if got := Summarize([]Record{rec(OpEncrypt, "", crypto.AES, 100, 0, 0)})[0].CryptoMiBPerSec(); got != 0 {
		t.Errorf("throughput with no recorded time = %v, want 0", got)
	}
}

func TestSummarizeGroupsAndOrder(t *testing.T) {
	stats := Summarize([]Record{
		rec(OpDownload, "video", crypto.RC4, 1<<20, 1, 1),
		rec(OpEncrypt, "video", crypto.RC4, 16<<20, 1, 1),
		rec(OpEncrypt, "video", crypto.AES, 16<<20, 1, 1),
		rec(OpEncrypt, "video", crypto.DES, 16<<20, 1, 1),
		rec(OpEncrypt, "video", crypto.AES, 1<<10, 1, 1),
		rec(OpEncrypt, "", crypto.AES, 120, 1, 1),
		rec(OpDecrypt, "document", crypto.AES, 1<<10+1, 1, 1),
		rec(OpEncrypt, "video", crypto.AES, 16<<20+1, 1, 1),
	})
	type key struct {
		op   Operation
		kind string
		size string
		alg  crypto.Algorithm
	}
	want := []key{
		{OpEncrypt, "", "≤ 1 KiB", crypto.AES},
		{OpEncrypt, "video", "≤ 1 KiB", crypto.AES},
		{OpEncrypt, "video", "1–16 MiB", crypto.AES},
		{OpEncrypt, "video", "1–16 MiB", crypto.DES},
		{OpEncrypt, "video", "1–16 MiB", crypto.RC4},
		{OpEncrypt, "video", "16–128 MiB", crypto.AES},
		{OpDecrypt, "document", "1–64 KiB", crypto.AES},
		{OpDownload, "video", "64 KiB–1 MiB", crypto.RC4},
	}
	if len(stats) != len(want) {
		t.Fatalf("%d groups, want %d", len(stats), len(want))
	}
	for i, s := range stats {
		if got := (key{s.Operation, s.FileKind, s.Size.Label, s.Algorithm}); got != want[i] {
			t.Errorf("group %d = %v, want %v", i, got, want[i])
		}
	}
}

func TestClassOfBoundaries(t *testing.T) {
	tests := []struct {
		n    int64
		want string
	}{
		{0, "≤ 1 KiB"},
		{1 << 10, "≤ 1 KiB"},
		{1<<10 + 1, "1–64 KiB"},
		{1 << 20, "64 KiB–1 MiB"},
		{128 << 20, "16–128 MiB"},
		{128<<20 + 1, "> 128 MiB"},
		{math.MaxInt64, "> 128 MiB"},
	}
	for _, tt := range tests {
		if got := classOf(tt.n).Label; got != tt.want {
			t.Errorf("classOf(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}
