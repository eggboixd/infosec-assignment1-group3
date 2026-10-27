package files

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
)

func TestParseSlot(t *testing.T) {
	for _, si := range Slots() {
		got, err := ParseSlot(string(si.Slot))
		if err != nil || got.Slot != si.Slot || got.Kind != si.Kind {
			t.Errorf("ParseSlot(%q) = %+v, %v", si.Slot, got, err)
		}
		// Every extension a slot accepts must be allowed by its kind,
		// otherwise the slot could never be filled.
		for _, ext := range si.Exts {
			if !si.Kind.Allows(fileTypes[ext].mime) {
				t.Errorf("slot %s accepts %s but kind %s does not", si.Slot, ext, si.Kind)
			}
		}
	}
	for _, bad := range []string{"", "KTP", "passport", "document", "../ktp"} {
		if _, err := ParseSlot(bad); !errors.Is(err, ErrUnknownSlot) {
			t.Errorf("ParseSlot(%q) error = %v, want ErrUnknownSlot", bad, err)
		}
	}
}

func TestUploadSlot(t *testing.T) {
	tests := []struct {
		name string
		slot Slot
		file string // sample file to send
		as   string // filename sent
		want error
	}{
		{"ktp png", SlotKTP, "ktp-fake.png", "ktp.png", nil},
		{"ktp jpg uppercase ext", SlotKTP, "ktp-fake.jpg", "KTP.JPG", nil},
		{"cv pdf", SlotCV, "sample.pdf", "cv.pdf", nil},
		{"transcript pdf", SlotTranscript, "sample.pdf", "transkrip.pdf", nil},
		{"recommendation docx", SlotRecommendation, "sample.docx", "rec.docx", nil},
		{"salary xlsx", SlotSalary, "sample.xlsx", "slip.xlsx", nil},
		{"intro video", SlotIntroVideo, "sample.mp4", "intro.mp4", nil},
		{"pdf is not a salary slip", SlotSalary, "sample.pdf", "slip.pdf", ErrMIMENotAllowed},
		{"xlsx is not a CV", SlotCV, "sample.xlsx", "cv.xlsx", ErrMIMENotAllowed},
		{"docx is not a transcript", SlotTranscript, "sample.docx", "t.docx", ErrMIMENotAllowed},
		{"video is not a KTP", SlotKTP, "sample.mp4", "ktp.mp4", ErrMIMENotAllowed},
		{"extension lies about content", SlotCV, "sample.xlsx", "cv.pdf", ErrMIMENotAllowed},
		{"no extension", SlotCV, "sample.pdf", "cv", ErrMIMENotAllowed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rig := newTestRig(t)
			si, err := ParseSlot(string(tt.slot))
			if err != nil {
				t.Fatal(err)
			}
			rec, err := rig.svc.UploadSlot(context.Background(), owner, si, tt.as, bytes.NewReader(sample(t, tt.file)))
			if !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
			if tt.want != nil {
				if rig.meta.Len() != 0 || rig.objects.Len() != 0 {
					t.Error("a rejected upload left data behind")
				}
				return
			}
			if rec.Slot != tt.slot || rec.Kind != si.Kind {
				t.Errorf("record slot/kind = %s/%s, want %s/%s", rec.Slot, rec.Kind, tt.slot, si.Kind)
			}
			views, err := rig.svc.List(context.Background(), owner)
			if err != nil || len(views) != 1 || views[0].Slot != tt.slot {
				t.Errorf("List = %+v, %v; want one view with slot %s", views, err, tt.slot)
			}
		})
	}
}

func TestUploadSlotEmptyFile(t *testing.T) {
	rig := newTestRig(t)
	si, _ := ParseSlot("cv")
	if _, err := rig.svc.UploadSlot(context.Background(), owner, si, "cv.pdf", bytes.NewReader(nil)); !errors.Is(err, ErrEmptyFile) {
		t.Errorf("error = %v, want ErrEmptyFile", err)
	}
}

func TestListSlotIsOwnerScoped(t *testing.T) {
	rig := newTestRig(t)
	si, _ := ParseSlot("cv")
	if _, err := rig.svc.UploadSlot(context.Background(), owner, si, "cv.pdf", bytes.NewReader(sample(t, "sample.pdf"))); err != nil {
		t.Fatal(err)
	}
	views, err := rig.svc.List(context.Background(), bson.NewObjectID())
	if err != nil || len(views) != 0 {
		t.Errorf("another user's List = %+v, %v; want empty", views, err)
	}
}

// A record stored before slots existed has no slot and must still list.
func TestListLegacyRecordHasNoSlot(t *testing.T) {
	rig := newTestRig(t)
	if _, err := rig.svc.Upload(context.Background(), owner, KindDocument, "old.pdf", bytes.NewReader(sample(t, "sample.pdf"))); err != nil {
		t.Fatal(err)
	}
	views, err := rig.svc.List(context.Background(), owner)
	if err != nil || len(views) != 1 || views[0].Slot != "" || views[0].Name != "old.pdf" {
		t.Errorf("List = %+v, %v; want one slotless view", views, err)
	}
}

func TestHTTPUploadSlot(t *testing.T) {
	r := newHTTPRig(t)
	pdf := sample(t, "sample.pdf")
	send := func(parts ...part) *httptest.ResponseRecorder { return r.do(multipartRequest(t, parts...)) }

	if up := send(part{name: "slot", data: []byte("cv")}, part{name: "file", filename: "cv.pdf", data: pdf}); up.Code != http.StatusSeeOther {
		t.Fatalf("cv upload: %d", up.Code)
	}
	if rec := r.onlyFile(t); rec.Slot != SlotCV || rec.Kind != KindDocument {
		t.Errorf("stored slot/kind = %s/%s, want cv/document", rec.Slot, rec.Kind)
	}

	for _, tt := range []struct {
		name   string
		parts  []part
		status int
	}{
		{"unknown slot", []part{{name: "slot", data: []byte("passport")}, {name: "file", filename: "a.pdf", data: pdf}}, http.StatusBadRequest},
		{"wrong type for slot", []part{{name: "slot", data: []byte("salary")}, {name: "file", filename: "a.pdf", data: pdf}}, http.StatusUnsupportedMediaType},
		{"file before slot", []part{{name: "file", filename: "a.pdf", data: pdf}, {name: "slot", data: []byte("cv")}}, http.StatusBadRequest},
		{"empty file", []part{{name: "slot", data: []byte("cv")}, {name: "file", filename: "a.pdf"}}, http.StatusBadRequest},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := send(tt.parts...); got.Code != tt.status {
				t.Errorf("status = %d, want %d", got.Code, tt.status)
			}
			if r.meta.Len() != 1 {
				t.Errorf("%d records stored, want 1 (the CV)", r.meta.Len())
			}
		})
	}
}
