// Command cipheranalysis encrypts the fake sample files with the real
// crypto.Envelope (AES-256-CTR, DES-CTR, RC4) and writes a ciphertext analysis:
// a Markdown report, a CSV, SVG charts and the "why not ECB" pictures.
//
// It reads only scripts/testdata (fake data), holds each sample in memory, and
// writes only statistics, hex prefixes and pictures. Keys are generated per run
// from crypto/rand and are never written.
//
// Run from the repository root: go run ./cmd/cipheranalysis
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/eggboixd/infosec-assignment1-group3/internal/cipheranalysis"
	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
)

// maxSample refuses surprise large files: the analysis keeps each in memory.
const maxSample = 16 << 20

// histogramFiles are the samples that get a byte-histogram chart: one very
// repetitive file and one ordinary text file.
var histogramFiles = []string{"repetitive.txt", "sample.txt"}

func main() {
	in := flag.String("in", "scripts/testdata", "directory with the sample files")
	out := flag.String("out", "docs/analysis", "directory to write the report into")
	flag.Parse()
	if err := run(*in, *out); err != nil {
		fmt.Fprintln(os.Stderr, "cipheranalysis:", err)
		os.Exit(1)
	}
}

func run(inDir, outDir string) error {
	master := make([]byte, crypto.MasterKeySize)
	if _, err := rand.Read(master); err != nil {
		return err
	}
	defer clear(master)
	enc, err := crypto.NewEnvelope(master)
	if err != nil {
		return err
	}
	ctx := context.Background()

	names, err := sampleNames(inDir)
	if err != nil {
		return err
	}
	var in cipheranalysis.ReportInput
	for _, want := range []string{"sample.mp4"} {
		if !slices.Contains(names, want) {
			in.Skipped = append(in.Skipped, want+" is not in "+filepath.ToSlash(inDir)+" (add a small clip by hand, see its README)")
		}
	}

	var bmpData []byte
	for _, name := range names {
		data, err := readSample(filepath.Join(inDir, name))
		if err != nil {
			return err
		}
		if name == "pattern.bmp" {
			bmpData = data
		}
		rows, err := cipheranalysis.Analyze(ctx, enc, name, data)
		if err != nil {
			return err
		}
		in.Rows = append(in.Rows, rows...)
	}

	if err := os.MkdirAll(outDir, 0o750); err != nil {
		return err
	}
	write := func(name string, data []byte) error {
		return os.WriteFile(filepath.Join(outDir, name), data, 0o600)
	}

	// Charts.
	if err := write("entropy.svg", []byte(cipheranalysis.EntropyChart(in.Rows))); err != nil {
		return err
	}
	in.Charts = append(in.Charts, "entropy.svg")
	for _, f := range histogramFiles {
		if !slices.Contains(names, f) {
			continue
		}
		svg := "histogram-" + strings.TrimSuffix(f, filepath.Ext(f)) + ".svg"
		if err := write(svg, []byte(cipheranalysis.HistogramChart(f, in.Rows))); err != nil {
			return err
		}
		in.Charts = append(in.Charts, svg)
	}

	// "Why not ECB" pictures.
	if bmpData != nil {
		pics, err := cipheranalysis.ECBPictures(ctx, enc, bmpData)
		if err != nil {
			return err
		}
		for _, p := range pics {
			png, err := cipheranalysis.BMPToPNG(p.BMP)
			if err != nil {
				return err
			}
			file := "ecb-demo-" + p.Name + ".png"
			if err := write(file, png); err != nil {
				return err
			}
			pixels, _ := cipheranalysis.BMPPixels(p.BMP)
			in.Pictures = append(in.Pictures, cipheranalysis.PictureInfo{
				Title: p.Title, File: file,
				RepeatedBlocks: cipheranalysis.RepeatedBlocks(pixels), TotalBlocks: len(pixels) / 16,
			})
		}
	} else {
		in.Skipped = append(in.Skipped, "pattern.bmp is missing, so the ECB picture was not made (run go run ./scripts/gentestdata)")
	}

	var csvBuf, mdBuf bytes.Buffer
	if err := cipheranalysis.WriteCSV(&csvBuf, in.Rows); err != nil {
		return err
	}
	if err := cipheranalysis.WriteMarkdown(&mdBuf, in); err != nil {
		return err
	}
	if err := write("results.csv", csvBuf.Bytes()); err != nil {
		return err
	}
	if err := write("report.md", mdBuf.Bytes()); err != nil {
		return err
	}
	fmt.Printf("analysed %d files x %d algorithms; wrote report to %s\n", len(names), len(crypto.All()), outDir)
	return nil
}

// sampleNames lists the sample files in dir, sorted, without the README and
// hidden files.
func sampleNames(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || strings.HasPrefix(n, ".") || strings.EqualFold(n, "README.md") {
			continue
		}
		names = append(names, n)
	}
	slices.Sort(names)
	if len(names) == 0 {
		return nil, fmt.Errorf("no sample files in %s (run go run ./scripts/gentestdata)", dir)
	}
	return names, nil
}

func readSample(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > maxSample {
		return nil, fmt.Errorf("%s is %d bytes; samples must be at most %d", path, info.Size(), maxSample)
	}
	return os.ReadFile(path) // #nosec G304 -- path is built from a directory listing of the -in flag, which the developer controls.
}
