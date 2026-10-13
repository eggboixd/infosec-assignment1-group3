package web

import (
	"math"
	"testing"
)

func TestHumanBytes(t *testing.T) {
	tests := []struct {
		in   int64
		want string
	}{
		{-1, "0 B"},
		{0, "0 B"},
		{1, "1 B"},
		{1023, "1023 B"},
		{1024, "1.0 KiB"},
		{1536, "1.5 KiB"},
		{1<<20 - 1, "1.0 MiB"},
		{1 << 20, "1.0 MiB"},
		{5 << 30, "5.0 GiB"},
		{3_000_000_017, "2.8 GiB"},
		{math.MaxInt64, "8.0 EiB"},
	}
	for _, tt := range tests {
		if got := humanBytes(tt.in); got != tt.want {
			t.Errorf("humanBytes(%d) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
