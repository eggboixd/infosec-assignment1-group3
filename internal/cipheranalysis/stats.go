// Package cipheranalysis measures what the ciphertext of AES, DES and RC4 looks
// like: its entropy, how uniform its bytes are, how much of it changes between
// two encryptions, and how a one-bit plaintext change spreads. It is analysis
// only; nothing here is used by the running application.
package cipheranalysis

import (
	"errors"
	"math"
	"math/bits"
)

// ErrLengthMismatch is returned when two slices that must be equally long are not.
var ErrLengthMismatch = errors.New("cipheranalysis: inputs have different lengths")

// Histogram counts how often each byte value occurs in data.
func Histogram(data []byte) [256]int {
	var h [256]int
	for _, b := range data {
		h[b]++
	}
	return h
}

// Entropy returns the Shannon entropy of data in bits per byte, from 0 (one
// repeated byte) to 8 (every byte value equally likely). Good ciphertext should
// be close to 8. Empty input has entropy 0. For short inputs the maximum is
// log2(len(data)), because at most len(data) different values can appear.
func Entropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	h := Histogram(data)
	n := float64(len(data))
	var e float64
	for _, c := range h {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		e -= p * math.Log2(p)
	}
	// Floating-point rounding can leave a tiny negative zero.
	return math.Max(e, 0)
}

// MinExpectedPerBin is the smallest expected count per byte value for which the
// chi-square statistic is considered meaningful (the usual rule of thumb is 5).
const MinExpectedPerBin = 5

// ChiSquare returns the chi-square statistic of the byte histogram of data
// against a uniform distribution over the 256 byte values. For uniform random
// bytes it is about 255 (the degrees of freedom) with a standard deviation of
// about 22.6; values above ~293 reject uniformity at the 5% level. Empty input
// returns 0. Use ChiSquareReliable to see whether the input is long enough.
func ChiSquare(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	h := Histogram(data)
	expected := float64(len(data)) / 256
	var x float64
	for _, c := range h {
		d := float64(c) - expected
		x += d * d / expected
	}
	return x
}

// ChiSquareReliable reports whether data is long enough (expected count of at
// least MinExpectedPerBin per byte value, i.e. 1280 bytes) for ChiSquare to mean anything.
func ChiSquareReliable(data []byte) bool {
	return len(data) >= 256*MinExpectedPerBin
}

// ChiSquareDegreesOfFreedom is the degrees of freedom of ChiSquare.
const ChiSquareDegreesOfFreedom = 255

// ChiSquareCritical5 is the 5% critical value for 255 degrees of freedom.
const ChiSquareCritical5 = 293.25

// DiffBytes returns how many positions differ between a and b.
func DiffBytes(a, b []byte) (int, error) {
	if len(a) != len(b) {
		return 0, ErrLengthMismatch
	}
	n := 0
	for i := range a {
		if a[i] != b[i] {
			n++
		}
	}
	return n, nil
}

// DiffPercent returns the percentage of byte positions that differ between a
// and b. Two independent random streams differ in 255/256 = 99.6% of positions.
// Two empty slices differ in 0%.
func DiffPercent(a, b []byte) (float64, error) {
	n, err := DiffBytes(a, b)
	if err != nil {
		return 0, err
	}
	if len(a) == 0 {
		return 0, nil
	}
	return 100 * float64(n) / float64(len(a)), nil
}

// DiffBits returns how many bits differ between a and b (the Hamming distance).
func DiffBits(a, b []byte) (int, error) {
	if len(a) != len(b) {
		return 0, ErrLengthMismatch
	}
	n := 0
	for i := range a {
		n += bits.OnesCount8(a[i] ^ b[i])
	}
	return n, nil
}
