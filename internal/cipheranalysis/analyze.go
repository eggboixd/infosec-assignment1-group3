package cipheranalysis

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
)

// HexPrefixLen is how many leading bytes of plaintext and ciphertext the
// report shows. 32 bytes is enough to see a file signature such as %PDF or
// PK\x03\x04 in the plaintext and nothing recognisable in the ciphertext.
const HexPrefixLen = 32

// NotApplicable marks a count that cannot be measured (for example a one-bit
// flip in an empty file).
const NotApplicable = -1

// Row is the result for one file encrypted with one algorithm.
type Row struct {
	File      string
	Algorithm crypto.Algorithm

	PlainSize  int
	CipherSize int
	// MetaSize is the stored overhead next to the ciphertext: IV, both wrapped
	// keys and the HMAC tag. CTR and RC4 add no padding, so CipherSize equals
	// PlainSize and all overhead is here.
	MetaSize int

	PlainEntropy  float64
	CipherEntropy float64
	PlainChi      float64
	CipherChi     float64
	// ChiReliable is false for files shorter than 1280 bytes, where the
	// chi-square statistic is not meaningful.
	ChiReliable bool

	// TwiceDiffPercent is the share of byte positions that differ between two
	// real encryptions of the same file (fresh key and IV each time).
	TwiceDiffPercent float64

	// PlainHist and CipherHist are the byte histograms behind the entropy and
	// chi-square numbers, kept for the histogram chart.
	PlainHist  [256]int
	CipherHist [256]int

	PlainHex  string // first HexPrefixLen bytes
	CipherHex string

	// OneBitCipherBytes and OneBitCipherBits: with the same key and IV, how
	// many ciphertext bytes and bits change when one plaintext bit changes.
	// NotApplicable for an empty file.
	OneBitCipherBytes int
	OneBitCipherBits  int

	// TamperDetected is true when flipping one stored bit made the real
	// Decrypt fail with crypto.ErrAuthentication.
	TamperDetected bool
	// RoundTripOK is true when the untouched ciphertext decrypts to the input.
	RoundTripOK bool
}

// Analyze encrypts plain once per algorithm with enc (the real Envelope) and
// measures the result. The file is held in memory: the samples are small, and
// the analysis needs the whole ciphertext to build its histograms.
func Analyze(ctx context.Context, enc crypto.Encryptor, file string, plain []byte) ([]Row, error) {
	rows := make([]Row, 0, len(crypto.All()))
	for _, alg := range crypto.All() {
		row, err := analyzeOne(ctx, enc, alg, file, plain)
		if err != nil {
			return nil, fmt.Errorf("%s with %s: %w", file, alg, err)
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func encrypt(ctx context.Context, enc crypto.Encryptor, alg crypto.Algorithm, plain []byte) ([]byte, crypto.Meta, error) {
	var ct bytes.Buffer
	meta, err := enc.Encrypt(ctx, alg, &ct, bytes.NewReader(plain))
	if err != nil {
		return nil, crypto.Meta{}, err
	}
	return ct.Bytes(), meta, nil
}

func analyzeOne(ctx context.Context, enc crypto.Encryptor, alg crypto.Algorithm, file string, plain []byte) (Row, error) {
	ct, meta, err := encrypt(ctx, enc, alg, plain)
	if err != nil {
		return Row{}, err
	}
	// A second, independent encryption of the same bytes.
	ct2, _, err := encrypt(ctx, enc, alg, plain)
	if err != nil {
		return Row{}, err
	}
	diff, err := DiffPercent(ct, ct2)
	if err != nil {
		return Row{}, err
	}

	row := Row{
		File:              file,
		Algorithm:         alg,
		PlainSize:         len(plain),
		CipherSize:        len(ct),
		MetaSize:          len(meta.IV) + len(meta.WrappedDEK) + len(meta.WrappedMACKey) + len(meta.Tag),
		PlainEntropy:      Entropy(plain),
		CipherEntropy:     Entropy(ct),
		PlainChi:          ChiSquare(plain),
		CipherChi:         ChiSquare(ct),
		ChiReliable:       ChiSquareReliable(ct),
		TwiceDiffPercent:  diff,
		PlainHist:         Histogram(plain),
		CipherHist:        Histogram(ct),
		PlainHex:          hexPrefix(plain),
		CipherHex:         hexPrefix(ct),
		OneBitCipherBytes: NotApplicable,
		OneBitCipherBits:  NotApplicable,
	}

	// Sanity check: the ciphertext we just analysed really decrypts.
	var back bytes.Buffer
	if err := enc.Decrypt(ctx, alg, meta, &back, bytes.NewReader(ct)); err != nil {
		return Row{}, fmt.Errorf("round trip: %w", err)
	}
	row.RoundTripOK = bytes.Equal(back.Bytes(), plain)

	row.TamperDetected, err = tamperDetected(ctx, enc, alg, meta, ct)
	if err != nil {
		return Row{}, err
	}

	if len(plain) > 0 {
		row.OneBitCipherBytes, row.OneBitCipherBits, err = oneBitDiffusion(alg, plain)
		if err != nil {
			return Row{}, err
		}
	}
	return row, nil
}

// tamperDetected flips one bit of the stored ciphertext (or, for an empty file
// that has none, one bit of the tag) and reports whether Decrypt rejected it
// with ErrAuthentication. Any other error is a bug and is returned.
func tamperDetected(ctx context.Context, enc crypto.Encryptor, alg crypto.Algorithm, meta crypto.Meta, ct []byte) (bool, error) {
	badCT, badMeta := ct, meta
	if len(ct) > 0 {
		badCT = FlipBit(ct, len(ct)/2, 0)
	} else {
		badMeta.Tag = FlipBit(meta.Tag, 0, 0)
	}
	var sink bytes.Buffer
	err := enc.Decrypt(ctx, alg, badMeta, &sink, bytes.NewReader(badCT))
	switch {
	case errors.Is(err, crypto.ErrAuthentication):
		// Nothing may be written before the tag is verified.
		return sink.Len() == 0, nil
	case err == nil:
		return false, nil
	default:
		return false, fmt.Errorf("tamper check: unexpected error: %w", err)
	}
}

// oneBitDiffusion encrypts plain and a copy with one bit flipped, under the
// same demo key and IV, and returns how many ciphertext bytes and bits differ.
func oneBitDiffusion(alg crypto.Algorithm, plain []byte) (bytesChanged, bitsChanged int, err error) {
	a, err := DemoEncrypt(alg, plain)
	if err != nil {
		return 0, 0, err
	}
	b, err := DemoEncrypt(alg, FlipBit(plain, len(plain)/2, 0))
	if err != nil {
		return 0, 0, err
	}
	if bytesChanged, err = DiffBytes(a, b); err != nil {
		return 0, 0, err
	}
	bitsChanged, err = DiffBits(a, b)
	return bytesChanged, bitsChanged, err
}

func hexPrefix(b []byte) string {
	if len(b) > HexPrefixLen {
		b = b[:HexPrefixLen]
	}
	return hex.EncodeToString(b)
}
