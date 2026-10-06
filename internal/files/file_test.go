package files

import (
	"errors"
	"testing"
)

func TestParseKind(t *testing.T) {
	tests := []struct {
		in      string
		want    Kind
		wantErr bool
	}{
		{"idcard", KindIDCard, false},
		{"document", KindDocument, false},
		{"video", KindVideo, false},
		{"IDCARD", "", true},
		{"", "", true},
		{"audio", "", true},
	}
	for _, tt := range tests {
		got, err := ParseKind(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseKind(%q) err = %v, wantErr %v", tt.in, err, tt.wantErr)
		}
		if tt.wantErr && !errors.Is(err, ErrUnknownKind) {
			t.Errorf("ParseKind(%q) err = %v, want ErrUnknownKind", tt.in, err)
		}
		if got != tt.want {
			t.Errorf("ParseKind(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestKindAllows(t *testing.T) {
	tests := []struct {
		kind Kind
		mime string
		want bool
	}{
		{KindIDCard, "image/jpeg", true},
		{KindIDCard, "image/png", true},
		{KindIDCard, "image/gif", false},
		{KindIDCard, "application/pdf", false},
		{KindDocument, "application/pdf", true},
		{KindDocument, "application/msword", true},
		{KindDocument, "application/vnd.openxmlformats-officedocument.wordprocessingml.document", true},
		{KindDocument, "application/vnd.ms-excel", true},
		{KindDocument, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", true},
		{KindDocument, "application/zip", false},
		{KindDocument, "text/html", false},
		{KindVideo, "video/mp4", true},
		{KindVideo, "video/webm", true},
		{KindVideo, "video/x-msvideo", false},
		{KindVideo, "image/png", false},
		{Kind("other"), "image/png", false},
	}
	for _, tt := range tests {
		if got := tt.kind.Allows(tt.mime); got != tt.want {
			t.Errorf("%s.Allows(%q) = %v, want %v", tt.kind, tt.mime, got, tt.want)
		}
	}
}

func TestAllowedMIMETypesReturnsCopy(t *testing.T) {
	list := KindIDCard.AllowedMIMETypes()
	list[0] = "text/html"
	if KindIDCard.Allows("text/html") {
		t.Error("mutating the returned slice changed the allowlist")
	}
}
