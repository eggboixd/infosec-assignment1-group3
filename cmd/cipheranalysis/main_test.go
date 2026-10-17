package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunWritesReport(t *testing.T) {
	in, out := t.TempDir(), filepath.Join(t.TempDir(), "out")
	// Sizes around the block sizes, plus a README and a hidden file that must be ignored.
	for name, size := range map[string]int{"a.bin": 7, "b.bin": 17, "c.bin": 5000, "empty.bin": 0} {
		if err := os.WriteFile(filepath.Join(in, name), make([]byte, size), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"README.md", ".gitattributes"} {
		if err := os.WriteFile(filepath.Join(in, name), []byte("ignore me"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if err := run(in, out); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"report.md", "results.csv", "entropy.svg"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Errorf("missing output %s: %v", f, err)
		}
	}
	md, _ := os.ReadFile(filepath.Join(out, "report.md"))
	for _, want := range []string{"sample.mp4 is not in", "pattern.bmp is missing", "c.bin"} {
		if !strings.Contains(string(md), want) {
			t.Errorf("report does not mention %q", want)
		}
	}
	if strings.Contains(string(md), "ignore me") || strings.Contains(string(md), "README.md") {
		t.Error("README and hidden files must not be analysed")
	}
}

func TestRunErrors(t *testing.T) {
	if err := run(t.TempDir(), t.TempDir()); err == nil {
		t.Error("an empty input directory must be an error")
	}
	if err := run(filepath.Join(t.TempDir(), "missing"), t.TempDir()); err == nil {
		t.Error("a missing input directory must be an error")
	}
}

func TestReadSampleRejectsHugeFiles(t *testing.T) {
	p := filepath.Join(t.TempDir(), "big.bin")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxSample + 1); err != nil { // sparse file: no real disk use
		t.Fatal(err)
	}
	f.Close()
	if _, err := readSample(p); err == nil {
		t.Error("expected an error for a file over maxSample")
	}
}
