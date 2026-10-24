package cipheranalysis

import (
	"bytes"
	"crypto/rand"
	"errors"
	"math"
	"testing"
)

// everyByte returns each of the 256 byte values times times.
func everyByte(times int) []byte {
	out := make([]byte, 0, 256*times)
	for range times {
		for v := range 256 {
			out = append(out, byte(v))
		}
	}
	return out
}

func TestEntropy(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want float64
	}{
		{"empty", nil, 0},
		{"one byte", []byte{7}, 0},
		{"all zero", make([]byte, 4096), 0},
		{"two values 50/50", bytes.Repeat([]byte{0, 1}, 100), 1},
		{"four values equal", bytes.Repeat([]byte{0, 1, 2, 3}, 50), 2},
		{"every byte value equally often", everyByte(10), 8},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Entropy(tt.data); math.Abs(got-tt.want) > 1e-9 {
				t.Errorf("Entropy = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEntropyRandomIsNearEight(t *testing.T) {
	data := make([]byte, 1<<20)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	if got := Entropy(data); got < 7.99 || got > 8 {
		t.Errorf("Entropy of 1 MiB random = %v, want in [7.99, 8]", got)
	}
}

func TestEntropyShortInputIsCapped(t *testing.T) {
	// 16 distinct bytes can carry at most log2(16) = 4 bits per byte.
	data := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	if got := Entropy(data); math.Abs(got-4) > 1e-9 {
		t.Errorf("Entropy = %v, want 4", got)
	}
}

func TestChiSquare(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want float64
	}{
		{"empty is defined, not NaN", nil, 0},
		{"perfectly uniform", everyByte(5), 0},
		// One value only: (n-n/256)^2/(n/256) + 255*(n/256) = 255*n.
		{"single repeated byte", make([]byte, 1000), 255 * 1000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ChiSquare(tt.data)
			if math.IsNaN(got) || math.Abs(got-tt.want) > 1e-6 {
				t.Errorf("ChiSquare = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestChiSquareRandomIsNearDegreesOfFreedom(t *testing.T) {
	data := make([]byte, 1<<20)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	// Mean 255, standard deviation sqrt(2*255) = 22.6. Five sigma is ~113; a
	// failure here is far more likely a bug than bad luck.
	got := ChiSquare(data)
	if math.Abs(got-ChiSquareDegreesOfFreedom) > 113 {
		t.Errorf("ChiSquare of random data = %v, want within 113 of 255", got)
	}
}

func TestChiSquareReliable(t *testing.T) {
	if ChiSquareReliable(make([]byte, 1279)) {
		t.Error("1279 bytes should be too short")
	}
	if !ChiSquareReliable(make([]byte, 1280)) {
		t.Error("1280 bytes should be long enough")
	}
}

func TestHistogram(t *testing.T) {
	h := Histogram([]byte{1, 1, 2, 255})
	if h[1] != 2 || h[2] != 1 || h[255] != 1 || h[0] != 0 {
		t.Errorf("unexpected histogram: %v", h[:3])
	}
}

func TestDiff(t *testing.T) {
	tests := []struct {
		name      string
		a, b      []byte
		wantBytes int
		wantPct   float64
		wantBits  int
		wantErr   error
	}{
		{"both empty", nil, nil, 0, 0, 0, nil},
		{"equal", []byte{1, 2, 3}, []byte{1, 2, 3}, 0, 0, 0, nil},
		{"one bit", []byte{0, 0, 0, 0}, []byte{0, 0x10, 0, 0}, 1, 25, 1, nil},
		{"all different", []byte{0, 0}, []byte{0xff, 0xff}, 2, 100, 16, nil},
		{"different lengths", []byte{1}, []byte{1, 2}, 0, 0, 0, ErrLengthMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, err := DiffBytes(tt.a, tt.b)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("DiffBytes error = %v, want %v", err, tt.wantErr)
			}
			pct, _ := DiffPercent(tt.a, tt.b)
			nb, _ := DiffBits(tt.a, tt.b)
			if n != tt.wantBytes || pct != tt.wantPct || nb != tt.wantBits {
				t.Errorf("got bytes=%d pct=%v bits=%d, want %d %v %d", n, pct, nb, tt.wantBytes, tt.wantPct, tt.wantBits)
			}
		})
	}
	if _, err := DiffBits([]byte{1}, nil); !errors.Is(err, ErrLengthMismatch) {
		t.Errorf("DiffBits length mismatch error = %v", err)
	}
	if _, err := DiffPercent([]byte{1}, nil); !errors.Is(err, ErrLengthMismatch) {
		t.Errorf("DiffPercent length mismatch error = %v", err)
	}
}
