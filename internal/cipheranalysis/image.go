package cipheranalysis

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"

	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
)

// bmpHeaderMin is the size of the BMP file header (14) plus BITMAPINFOHEADER (40).
const bmpHeaderMin = 54

// ErrUnsupportedBMP is returned for anything but an uncompressed 24-bit BMP.
var ErrUnsupportedBMP = errors.New("cipheranalysis: only uncompressed 24-bit BMP files are supported")

// bmp is the parsed layout of an uncompressed 24-bit BMP.
type bmp struct {
	pixelOffset   int
	width, height int
	bottomUp      bool
}

func parseBMP(data []byte) (bmp, error) {
	if len(data) < bmpHeaderMin || data[0] != 'B' || data[1] != 'M' {
		return bmp{}, ErrUnsupportedBMP
	}
	le := binary.LittleEndian
	b := bmp{
		pixelOffset: int(le.Uint32(data[10:14])),
		width:       int(int32(le.Uint32(data[18:22]))),
		height:      int(int32(le.Uint32(data[22:26]))),
	}
	if b.height < 0 {
		b.height = -b.height
	} else {
		b.bottomUp = true
	}
	bpp, compression := le.Uint16(data[28:30]), le.Uint32(data[30:34])
	if bpp != 24 || compression != 0 || b.width <= 0 || b.height <= 0 {
		return bmp{}, ErrUnsupportedBMP
	}
	if b.pixelOffset < bmpHeaderMin || b.pixelOffset+b.stride()*b.height > len(data) {
		return bmp{}, ErrUnsupportedBMP
	}
	return b, nil
}

// stride is the length of one pixel row in the file, padded to 4 bytes.
func (b bmp) stride() int { return (b.width*3 + 3) &^ 3 }

// BMPPixels returns the pixel bytes of a 24-bit BMP (everything after the
// header). Only these are encrypted in the image demo, so the result still
// opens as an image and the eye sees the cipher, not a broken header.
func BMPPixels(data []byte) ([]byte, error) {
	b, err := parseBMP(data)
	if err != nil {
		return nil, err
	}
	return data[b.pixelOffset : b.pixelOffset+b.stride()*b.height], nil
}

// BMPToPNG converts an uncompressed 24-bit BMP to PNG, so the pictures can be
// shown in Markdown and browsers. It uses only the standard library.
func BMPToPNG(data []byte) ([]byte, error) {
	b, err := parseBMP(data)
	if err != nil {
		return nil, err
	}
	img := image.NewRGBA(image.Rect(0, 0, b.width, b.height))
	for y := 0; y < b.height; y++ {
		row := y
		if b.bottomUp {
			row = b.height - 1 - y
		}
		base := b.pixelOffset + row*b.stride()
		for x := 0; x < b.width; x++ {
			p := data[base+x*3 : base+x*3+3] // B, G, R
			img.Set(x, y, color.RGBA{R: p[2], G: p[1], B: p[0], A: 0xff})
		}
	}
	var out bytes.Buffer
	if err := png.Encode(&out, img); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// Picture is one image of the "why not ECB" figure.
type Picture struct {
	Name  string // file name stem, for example "ecb"
	Title string
	BMP   []byte
}

// ECBPictures builds the pictures for the "why not ECB" figure from a BMP:
// the original, AES-256-ECB (DEMO ONLY), and then the pixel bytes encrypted by
// the real Envelope with AES, DES and RC4. Each BMP keeps the original header.
func ECBPictures(ctx context.Context, enc crypto.Encryptor, original []byte) ([]Picture, error) {
	pixels, err := BMPPixels(original)
	if err != nil {
		return nil, err
	}
	b, _ := parseBMP(original)
	withPixels := func(p []byte) []byte {
		out := append([]byte(nil), original[:b.pixelOffset]...)
		return append(out, p...)
	}

	ecb, err := DemoECBEncrypt(pixels)
	if err != nil {
		return nil, fmt.Errorf("ecb demo: %w", err)
	}
	pics := []Picture{
		{"original", "Original image", append([]byte(nil), original...)},
		{"ecb", "AES-256-ECB (demo only, forbidden)", withPixels(ecb)},
	}
	for _, alg := range crypto.All() {
		ct, _, err := encrypt(ctx, enc, alg, pixels)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", alg, err)
		}
		pics = append(pics, Picture{string(alg), fmt.Sprintf("%s via crypto.Envelope", algLabel(alg)), withPixels(ct)})
	}
	return pics, nil
}

// algLabel is the human-readable cipher name used in reports and charts.
func algLabel(a crypto.Algorithm) string {
	switch a {
	case crypto.AES:
		return "AES-256-CTR"
	case crypto.DES:
		return "DES-CTR"
	case crypto.RC4:
		return "RC4"
	}
	return string(a)
}

// RepeatedBlocks returns how many 16-byte blocks of data are an exact copy of
// an earlier block. ECB of a flat image has thousands; a good mode has none.
func RepeatedBlocks(data []byte) int {
	seen := make(map[[16]byte]struct{})
	repeated := 0
	for i := 0; i+16 <= len(data); i += 16 {
		var k [16]byte
		copy(k[:], data[i:i+16])
		if _, ok := seen[k]; ok {
			repeated++
		}
		seen[k] = struct{}{}
	}
	return repeated
}
