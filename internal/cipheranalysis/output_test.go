package cipheranalysis

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/xml"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
)

func sampleRows(t *testing.T) []Row {
	t.Helper()
	enc := newTestEnvelope(t)
	var rows []Row
	// A slice, not a map, so the row order (and the report) is stable.
	for _, s := range []struct {
		name string
		data []byte
	}{
		{"a.bin", randomBytes(t, 3000)},
		{"b.txt", bytes.Repeat([]byte("hello "), 700)},
		{"c.bin", nil},
	} {
		r, err := Analyze(context.Background(), enc, s.name, s.data)
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, r...)
	}
	return rows
}

func TestWriteCSV(t *testing.T) {
	rows := sampleRows(t)
	var buf bytes.Buffer
	if err := WriteCSV(&buf, rows); err != nil {
		t.Fatal(err)
	}
	recs, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != len(rows)+1 {
		t.Fatalf("got %d records, want header + %d", len(recs), len(rows))
	}
	for i, h := range csvHeader {
		if recs[0][i] != h {
			t.Errorf("column %d = %q, want %q", i, recs[0][i], h)
		}
	}
	for _, rec := range recs[1:] {
		if len(rec) != len(csvHeader) {
			t.Fatalf("record has %d fields, want %d", len(rec), len(csvHeader))
		}
		// The ciphertext column is at most 32 bytes of hex: no more can leak.
		if hex := rec[len(rec)-1]; len(hex) > 2*HexPrefixLen {
			t.Errorf("hex column has %d chars", len(hex))
		}
	}
}

func TestWriteMarkdown(t *testing.T) {
	rows := sampleRows(t)
	var buf bytes.Buffer
	in := ReportInput{
		Rows:     rows,
		Skipped:  []string{"sample.mp4 is missing"},
		Pictures: []PictureInfo{{Title: "ECB (demo only)", File: "ecb.png", RepeatedBlocks: 5, TotalBlocks: 9}},
		Charts:   []string{"entropy.svg"},
	}
	if err := WriteMarkdown(&buf, in); err != nil {
		t.Fatal(err)
	}
	md := buf.String()
	for _, want := range []string{"sample.mp4 is missing", "AES-256-CTR", "DES-CTR", "RC4", "a.bin", "n/a (empty file)", "ecb.png", "entropy.svg", "not used by the application"} {
		if !strings.Contains(md, want) {
			t.Errorf("report is missing %q", want)
		}
	}
	if strings.Contains(md, "**NO**") {
		t.Error("a real Envelope must pass the tamper and round-trip checks")
	}
}

func TestWritersPropagateWriteError(t *testing.T) {
	if err := WriteMarkdown(errWriter{}, ReportInput{}); err == nil {
		t.Error("WriteMarkdown: expected the write error to be returned")
	}
	if err := WriteCSV(errWriter{}, sampleRows(t)); err == nil {
		t.Error("WriteCSV: expected the write error to be returned")
	}
}

type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

// wellFormed fails the test if svg is not valid XML.
func wellFormed(t *testing.T, svg string) {
	t.Helper()
	dec := xml.NewDecoder(strings.NewReader(svg))
	for {
		_, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			t.Fatalf("SVG is not well-formed: %v", err)
		}
	}
}

func TestEntropyChart(t *testing.T) {
	svg := EntropyChart(sampleRows(t))
	wellFormed(t, svg)
	for _, want := range []string{"AES-256-CTR", "DES-CTR", "RC4", "plaintext", "a.bin", "b.txt"} {
		if !strings.Contains(svg, want) {
			t.Errorf("chart is missing %q", want)
		}
	}
}

func TestEntropyChartEscapesFileNames(t *testing.T) {
	rows := []Row{{File: `<a&"b>.bin`, Algorithm: crypto.AES}}
	wellFormed(t, EntropyChart(rows))
}

func TestHistogramChart(t *testing.T) {
	rows := sampleRows(t)
	svg := HistogramChart("a.bin", rows)
	wellFormed(t, svg)
	if got := strings.Count(svg, "ciphertext</text>"); got != 3 {
		t.Errorf("got %d ciphertext panels, want 3", got)
	}
	// An unknown file draws an empty chart rather than panicking, and an
	// empty file has all-zero histograms.
	wellFormed(t, HistogramChart("nope", rows))
	wellFormed(t, HistogramChart("c.bin", rows))
}

// testBMP builds a width x height 24-bit bottom-up BMP: left half red, right half blue.
func testBMP(width, height int) []byte {
	stride := (width*3 + 3) &^ 3
	le := func(v uint32) []byte { return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)} }
	hdr := []byte("BM")
	hdr = append(hdr, le(uint32(54+stride*height))...)
	hdr = append(hdr, le(0)...)
	hdr = append(hdr, le(54)...)
	hdr = append(hdr, le(40)...)
	hdr = append(hdr, le(uint32(width))...)
	hdr = append(hdr, le(uint32(height))...)
	hdr = append(hdr, 1, 0, 24, 0)
	hdr = append(hdr, le(0)...)
	hdr = append(hdr, le(uint32(stride*height))...)
	hdr = append(hdr, make([]byte, 16)...)
	px := make([]byte, stride*height)
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			o := y*stride + x*3
			if x < width/2 {
				px[o+2] = 0xff // red
			} else {
				px[o] = 0xff // blue
			}
		}
	}
	return append(hdr, px...)
}

func TestBMPToPNGAndPixels(t *testing.T) {
	data := testBMP(64, 64)
	pixels, err := BMPPixels(data)
	if err != nil || len(pixels) != 64*64*3 {
		t.Fatalf("BMPPixels = %d bytes, err %v", len(pixels), err)
	}
	png, err := BMPToPNG(data)
	if err != nil || !bytes.HasPrefix(png, []byte("\x89PNG")) {
		t.Fatalf("BMPToPNG: err %v", err)
	}
	// Odd width forces row padding.
	if _, err := BMPToPNG(testBMP(5, 3)); err != nil {
		t.Errorf("padded BMP: %v", err)
	}
}

func TestParseBMPRejectsBadInput(t *testing.T) {
	bad := testBMP(4, 4)
	bad[28] = 8 // 8 bits per pixel
	huge := testBMP(4, 4)
	huge[21], huge[25] = 0x7f, 0x7f // width and height ~2^31: would overflow stride*height
	zero := testBMP(4, 4)
	zero[22], zero[23], zero[24], zero[25] = 0, 0, 0, 0 // height 0
	for name, in := range map[string][]byte{
		"huge":      huge,
		"zero":      zero,
		"empty":     nil,
		"not a bmp": []byte(strings.Repeat("x", 100)),
		"8-bit":     bad,
		"truncated": testBMP(8, 8)[:100],
	} {
		if _, err := BMPToPNG(in); !errors.Is(err, ErrUnsupportedBMP) {
			t.Errorf("%s: BMPToPNG error = %v, want ErrUnsupportedBMP", name, err)
		}
		if _, err := BMPPixels(in); !errors.Is(err, ErrUnsupportedBMP) {
			t.Errorf("%s: BMPPixels error = %v, want ErrUnsupportedBMP", name, err)
		}
	}
}

func TestECBPictures(t *testing.T) {
	pics, err := ECBPictures(context.Background(), newTestEnvelope(t), testBMP(64, 64))
	if err != nil {
		t.Fatal(err)
	}
	if len(pics) != 5 { // original, ECB, AES, DES, RC4
		t.Fatalf("got %d pictures, want 5", len(pics))
	}
	repeats := map[string]int{}
	for _, p := range pics {
		px, err := BMPPixels(p.BMP)
		if err != nil {
			t.Fatalf("%s: %v", p.Name, err)
		}
		repeats[p.Name] = RepeatedBlocks(px)
		if _, err := BMPToPNG(p.BMP); err != nil {
			t.Errorf("%s: %v", p.Name, err)
		}
	}
	// A two-colour image: ECB keeps nearly all blocks repeated, the real modes none.
	if repeats["ecb"] < 200 {
		t.Errorf("ECB repeated blocks = %d, want many", repeats["ecb"])
	}
	for _, alg := range crypto.All() {
		if repeats[string(alg)] != 0 {
			t.Errorf("%s repeated blocks = %d, want 0", alg, repeats[string(alg)])
		}
	}
}

func TestECBPicturesRejectsNonBMP(t *testing.T) {
	if _, err := ECBPictures(context.Background(), newTestEnvelope(t), []byte("not a bmp")); !errors.Is(err, ErrUnsupportedBMP) {
		t.Errorf("error = %v, want ErrUnsupportedBMP", err)
	}
}

func TestRepeatedBlocks(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want int
	}{
		{"empty", nil, 0},
		{"shorter than a block", make([]byte, 15), 0},
		{"two equal blocks", make([]byte, 32), 1},
		{"four equal blocks", make([]byte, 64), 3},
		{"trailing partial block ignored", make([]byte, 40), 1},
	}
	for _, tt := range tests {
		if got := RepeatedBlocks(tt.data); got != tt.want {
			t.Errorf("%s: got %d, want %d", tt.name, got, tt.want)
		}
	}
}

func TestBMPTopDownIsAccepted(t *testing.T) {
	bm := testBMP(8, 4)
	// Height -4 as two's complement: rows stored top-down.
	bm[22], bm[23], bm[24], bm[25] = 0xfc, 0xff, 0xff, 0xff
	if _, err := BMPToPNG(bm); err != nil {
		t.Errorf("top-down BMP: %v", err)
	}
}
