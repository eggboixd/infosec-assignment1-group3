package crypto

import (
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

func TestNestedClockAddsToParent(t *testing.T) {
	ctx, outer := WithClock(context.Background())
	outer.Add(1)
	ctx, inner := WithClock(ctx)
	if ClockFrom(ctx) != inner {
		t.Fatal("ClockFrom does not return the innermost clock")
	}
	inner.Add(10)
	if inner.Elapsed() != 10 || outer.Elapsed() != 11 {
		t.Errorf("inner %d, outer %d; want 10 and 11", inner.Elapsed(), outer.Elapsed())
	}
}
