package files

import (
	"errors"
	"strings"
	"testing"
)

func TestDetectMIME(t *testing.T) {
	ole := append([]byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, make([]byte, 100)...)
	zip := []byte("PK\x03\x04rest-of-zip")
	webm := []byte("\x1a\x45\xdf\xa3\x9f\x42\x86\x81\x01\x42\xf7\x81\x01\x42\xf2\x81\x04\x42\xf3\x81\x08\x42\x82\x84webm")
	tests := []struct {
		kind Kind
		name string
		head []byte
		want string // "" means rejected
	}{
		{KindDocument, "old.DOC", ole, mimeDOC},
		{KindDocument, "old.xls", ole, mimeXLS},
		{KindDocument, "new.docx", zip, mimeDOCX},
		{KindDocument, "new.XLSX", zip, mimeXLSX},
		{KindVideo, "clip.webm", webm, "video/webm"},
		{KindDocument, "old.doc", zip, ""},     // ZIP is not OLE2
		{KindDocument, "new.docx", ole, ""},    // OLE2 is not ZIP
		{KindDocument, "archive.zip", zip, ""}, // plain ZIP is not a document
		{KindIDCard, "old.doc", ole, ""},       // right content, wrong kind
		{KindVideo, "clip.webm", zip, ""},
	}
	for _, tt := range tests {
		got, err := detectMIME(tt.kind, tt.name, tt.head)
		if tt.want == "" {
			if !errors.Is(err, ErrMIMENotAllowed) {
				t.Errorf("detectMIME(%s, %s) = %q, %v; want ErrMIMENotAllowed", tt.kind, tt.name, got, err)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("detectMIME(%s, %s) = %q, %v; want %q", tt.kind, tt.name, got, err, tt.want)
		}
	}
}

func TestCleanFilename(t *testing.T) {
	tests := []struct{ in, want string }{
		{"report.pdf", "report.pdf"},
		{`C:\Users\budi\Desktop\ktp.png`, "ktp.png"},
		{"../../etc/passwd.pdf", "passwd.pdf"},
		{"evil\r\nX-Header: 1.pdf", "evilX-Header: 1.pdf"},
		{"  spaced.pdf  ", "spaced.pdf"},
		{"KTP Budi Ñoño.png", "KTP Budi Ñoño.png"},
		{"", "file"},
		{"/", "file"},
		{"..", "file"},
		{strings.Repeat("é", 200) + ".pdf", strings.Repeat("é", 127)},
	}
	for _, tt := range tests {
		if got := cleanFilename(tt.in); got != tt.want {
			t.Errorf("cleanFilename(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestContentDisposition(t *testing.T) {
	tests := []struct{ name, want string }{
		{"report.pdf", `attachment; filename=report.pdf`},
		{`my "quoted" file.pdf`, `attachment; filename="my \"quoted\" file.pdf"`},
		{"KTP Ñoño.png", `attachment; filename*=utf-8''KTP%20%C3%91o%C3%B1o.png`},
	}
	for _, tt := range tests {
		got := contentDisposition(tt.name)
		if got != tt.want {
			t.Errorf("contentDisposition(%q) = %q, want %q", tt.name, got, tt.want)
		}
		if strings.ContainsAny(got, "\r\n") {
			t.Errorf("contentDisposition(%q) contains a line break", tt.name)
		}
	}
}
