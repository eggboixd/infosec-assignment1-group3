// Command gentestdata writes the FAKE sample files used by cmd/cipheranalysis
// into scripts/testdata. Nothing here is real personal data: the "ID card" is a
// drawn layout with no text, and every document says it is a fake sample.
//
// The output is deterministic (same bytes on every run) so the committed
// samples can be checked against a regeneration. Noise comes from a SHA-256
// counter stream rather than math/rand, which this repository bans.
//
// The MP4 sample is not generated: the standard library has no video encoder.
// Add scripts/testdata/sample.mp4 by hand (see scripts/testdata/README.md).
//
// Run from the repository root: go run ./scripts/gentestdata
package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	out := flag.String("out", "scripts/testdata", "directory to write the samples into")
	flag.Parse()

	if err := os.MkdirAll(*out, 0o750); err != nil {
		fatal(err)
	}

	files := []struct {
		name string
		data func() ([]byte, error)
	}{
		{"ktp-fake.png", func() ([]byte, error) { return encodeIDCard(true) }},
		{"ktp-fake.jpg", func() ([]byte, error) { return encodeIDCard(false) }},
		{"sample.pdf", func() ([]byte, error) { return makePDF(), nil }},
		{"sample.docx", makeDOCX},
		{"sample.xlsx", makeXLSX},
		{"sample.txt", func() ([]byte, error) { return []byte(sampleText()), nil }},
		{"repetitive.txt", func() ([]byte, error) { return bytes.Repeat([]byte("ABCDEFGHIJKLMNOP"), 4096), nil }},
		{"pattern.bmp", func() ([]byte, error) { return makeBMP(), nil }},
	}
	for _, f := range files {
		data, err := f.data()
		if err != nil {
			fatal(fmt.Errorf("%s: %w", f.name, err))
		}
		if err := os.WriteFile(filepath.Join(*out, f.name), data, 0o600); err != nil {
			fatal(err)
		}
		fmt.Printf("%-16s %8d bytes\n", f.name, len(data))
	}
	fmt.Println("sample.mp4 is not generated: add it by hand, see scripts/testdata/README.md")
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "gentestdata:", err)
	os.Exit(1)
}

// prng is a deterministic byte stream: SHA-256(seed || counter), block by block.
type prng struct {
	seed    string
	counter uint64
	buf     []byte
}

func (p *prng) byte() byte {
	if len(p.buf) == 0 {
		var c [8]byte
		binary.BigEndian.PutUint64(c[:], p.counter)
		p.counter++
		sum := sha256.Sum256(append([]byte(p.seed), c[:]...))
		p.buf = sum[:]
	}
	b := p.buf[0]
	p.buf = p.buf[1:]
	return b
}

// encodeIDCard draws a KTP-style card: header band, photo box, and grey bars
// where the text lines would be. It contains no text and no real data.
func encodeIDCard(asPNG bool) ([]byte, error) {
	const w, h = 640, 400
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	fill := func(r image.Rectangle, c color.Color) {
		for y := r.Min.Y; y < r.Max.Y; y++ {
			for x := r.Min.X; x < r.Max.X; x++ {
				img.Set(x, y, c)
			}
		}
	}
	fill(img.Bounds(), color.RGBA{0xdd, 0xe9, 0xf5, 0xff})            // card body
	fill(image.Rect(0, 0, w, 60), color.RGBA{0x1f, 0x4e, 0x9a, 0xff}) // header band
	fill(image.Rect(250, 20, 390, 40), color.RGBA{0xff, 0xff, 0xff, 0xff})
	// "Text lines": label bar then value bar, varying lengths.
	for i := range 7 {
		y := 90 + i*38
		fill(image.Rect(30, y, 130, y+10), color.RGBA{0x55, 0x55, 0x55, 0xff})
		fill(image.Rect(150, y, 150+150+(i*37%160), y+10), color.RGBA{0x22, 0x22, 0x22, 0xff})
	}
	// Photo box with deterministic noise so the file is not trivially compressible.
	rng := &prng{seed: "ktp-fake-photo"}
	for y := 110; y < 330; y++ {
		for x := 460; x < 600; x++ {
			base := 90 + (y-110)/2
			n := int(rng.byte() % 48)
			img.Set(x, y, color.RGBA{uint8(base + n), uint8(base/2 + n), uint8(60 + n), 0xff})
		}
	}
	var buf bytes.Buffer
	if asPNG {
		if err := png.Encode(&buf, img); err != nil {
			return nil, err
		}
	} else if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 80}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// makePDF returns a one-page PDF with a fixed text line. The cross-reference
// table is computed from the real object offsets.
func makePDF() []byte {
	stream := "BT /F1 18 Tf 72 720 Td (FAKE SAMPLE DOCUMENT - no real personal data) Tj ET\n" +
		"BT /F1 12 Tf 72 690 Td (Used only to compare AES, DES and RC4 ciphertext.) Tj ET\n"
	objs := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
		fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", len(stream), stream),
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
	}
	var b bytes.Buffer
	b.WriteString("%PDF-1.4\n")
	offsets := make([]int, len(objs))
	for i, o := range objs {
		offsets[i] = b.Len()
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", i+1, o)
	}
	xref := b.Len()
	fmt.Fprintf(&b, "xref\n0 %d\n0000000000 65535 f \n", len(objs)+1)
	for _, off := range offsets {
		fmt.Fprintf(&b, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&b, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objs)+1, xref)
	return b.Bytes()
}

// zipFiles builds a ZIP with a fixed timestamp so the output is reproducible.
func zipFiles(parts [][2]string) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, p := range parts {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: p[0], Method: zip.Deflate, Modified: fixed})
		if err != nil {
			return nil, err
		}
		if _, err := w.Write([]byte(p[1])); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

const xmlHead = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + "\n"

func makeDOCX() ([]byte, error) {
	var paras strings.Builder
	for i := range 40 {
		fmt.Fprintf(&paras, `<w:p><w:r><w:t>Fake sample paragraph %d. No real personal data.</w:t></w:r></w:p>`, i+1)
	}
	return zipFiles([][2]string{
		{"[Content_Types].xml", xmlHead + `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`},
		{"_rels/.rels", xmlHead + `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`},
		{"word/document.xml", xmlHead + `<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>` + paras.String() + `</w:body></w:document>`},
	})
}

func makeXLSX() ([]byte, error) {
	var rows strings.Builder
	for r := 1; r <= 60; r++ {
		fmt.Fprintf(&rows, `<row r="%d"><c r="A%d" t="inlineStr"><is><t>fake row %d</t></is></c><c r="B%d"><v>%d</v></c></row>`, r, r, r, r, r*r)
	}
	return zipFiles([][2]string{
		{"[Content_Types].xml", xmlHead + `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>`},
		{"_rels/.rels", xmlHead + `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>`},
		{"xl/workbook.xml", xmlHead + `<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>`},
		{"xl/_rels/workbook.xml.rels", xmlHead + `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>`},
		{"xl/worksheets/sheet1.xml", xmlHead + `<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>` + rows.String() + `</sheetData></worksheet>`},
	})
}

// sampleText is about 4 KB of plain English prose, built from fixed sentences.
func sampleText() string {
	sentences := []string{
		"This is a fake sample text file used to compare AES, DES and RC4 ciphertext.",
		"It contains no real personal data of any kind.",
		"Natural language has low entropy because some letters and words repeat often.",
		"A good cipher hides that structure completely, so the output looks random.",
		"Secure Store encrypts every item three times, once with each algorithm.",
	}
	var b strings.Builder
	for i := 0; b.Len() < 4096; i++ {
		b.WriteString(sentences[i%len(sentences)])
		if i%3 == 2 {
			b.WriteString("\n")
		} else {
			b.WriteString(" ")
		}
	}
	return b.String()
}

// makeBMP returns a 256x256 24-bit BMP with large flat shapes. Flat areas give
// many identical 16-byte blocks, which is what makes ECB visibly leak the
// outline in the "why not ECB" demo. 256*3 = 768 bytes per row is already a
// multiple of 4, so there is no row padding.
func makeBMP() []byte {
	const size = 256
	const pixelBytes = size * size * 3
	const headerBytes = 54
	le := binary.LittleEndian
	hdr := []byte("BM")
	hdr = le.AppendUint32(hdr, headerBytes+pixelBytes) // file size
	hdr = le.AppendUint32(hdr, 0)                      // reserved
	hdr = le.AppendUint32(hdr, headerBytes)            // pixel data offset
	hdr = le.AppendUint32(hdr, 40)                     // DIB header size
	hdr = le.AppendUint32(hdr, size)                   // width
	hdr = le.AppendUint32(hdr, size)                   // height (positive: bottom-up)
	hdr = le.AppendUint16(hdr, 1)                      // colour planes
	hdr = le.AppendUint16(hdr, 24)                     // bits per pixel
	hdr = le.AppendUint32(hdr, 0)                      // no compression
	hdr = le.AppendUint32(hdr, pixelBytes)
	hdr = le.AppendUint32(hdr, 2835) // 72 DPI
	hdr = le.AppendUint32(hdr, 2835)
	hdr = le.AppendUint32(hdr, 0) // palette colours
	hdr = le.AppendUint32(hdr, 0) // important colours
	var b bytes.Buffer
	b.Write(hdr)

	for y := range size {
		for x := range size {
			// BMP stores pixels as B, G, R.
			r, g, bl := uint8(0xf0), uint8(0xf0), uint8(0xf0) // background
			dx, dy := x-128, y-128
			switch {
			case dx*dx+dy*dy < 50*50: // disc
				r, g, bl = 0xc0, 0x20, 0x20
			case dx*dx+dy*dy < 70*70: // ring
				r, g, bl = 0x20, 0x20, 0xc0
			case x > 20 && x < 70 && y > 20 && y < 70: // square
				r, g, bl = 0x20, 0x90, 0x20
			}
			b.Write([]byte{bl, g, r})
		}
	}
	return b.Bytes()
}
