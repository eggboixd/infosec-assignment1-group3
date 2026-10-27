package benchmark

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
)

func TestCSVRoundTrip(t *testing.T) {
	in := []Record{
		{Algorithm: crypto.AES, Operation: OpEncrypt, FileKind: "video", Bytes: 1 << 20,
			CryptoDuration: 1234567, TotalDuration: 7654321,
			CreatedAt: time.Date(2026, 10, 27, 9, 0, 0, 123456789, time.UTC)},
		{Algorithm: crypto.RC4, Operation: OpDecrypt, Bytes: 120, CryptoDuration: 1, TotalDuration: 2,
			CreatedAt: time.Date(2026, 10, 27, 9, 0, 1, 0, time.FixedZone("WIB", 7*3600))},
	}
	var buf bytes.Buffer
	w, err := NewCSVWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range in {
		if err := w.Write(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if lines[0] != "created_at,algorithm,operation,file_kind,bytes,crypto_ns,total_ns" {
		t.Errorf("header = %q", lines[0])
	}
	if lines[1] != "2026-10-27T09:00:00.123456789Z,aes,encrypt,video,1048576,1234567,7654321" {
		t.Errorf("row = %q", lines[1])
	}
	// Times are written in UTC; the private-data row has an empty kind.
	if lines[2] != "2026-10-27T02:00:01Z,rc4,decrypt,,120,1,2" {
		t.Errorf("row = %q", lines[2])
	}

	out, err := ReadCSV(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != len(in) {
		t.Fatalf("%d records read back, want %d", len(out), len(in))
	}
	for i := range in {
		if !out[i].CreatedAt.Equal(in[i].CreatedAt) {
			t.Errorf("record %d time %v, want %v", i, out[i].CreatedAt, in[i].CreatedAt)
		}
		out[i].CreatedAt, in[i].CreatedAt = time.Time{}, time.Time{}
		if out[i] != in[i] {
			t.Errorf("record %d = %+v, want %+v", i, out[i], in[i])
		}
	}
}

func TestReadCSVRejects(t *testing.T) {
	const header = "created_at,algorithm,operation,file_kind,bytes,crypto_ns,total_ns\n"
	tests := []struct {
		name, in string
	}{
		{"empty", ""},
		{"wrong header", "a,b,c,d,e,f,g\n"},
		{"bad time", header + "yesterday,aes,encrypt,,1,1,1\n"},
		{"bad algorithm", header + "2026-10-27T09:00:00Z,3des,encrypt,,1,1,1\n"},
		{"bad number", header + "2026-10-27T09:00:00Z,aes,encrypt,,1.5,1,1\n"},
		{"short row", header + "2026-10-27T09:00:00Z,aes,encrypt\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ReadCSV(strings.NewReader(tt.in)); err == nil {
				t.Error("no error")
			}
		})
	}
	if _, err := ReadCSV(strings.NewReader("a,b,c,d,e,f,g\n")); !errors.Is(err, ErrCSVHeader) {
		t.Errorf("wrong header: err = %v, want ErrCSVHeader", err)
	}
}
