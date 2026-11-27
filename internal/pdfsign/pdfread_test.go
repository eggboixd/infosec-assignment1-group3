package pdfsign

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
)

func TestReadPDFFixtures(t *testing.T) {
	ctx := context.Background()
	for name, raw := range map[string][]byte{
		"classic xref": simplePDF(),
		"form":         formPDF(),
		"xref stream":  xrefStreamPDF(t),
	} {
		doc, err := readPDF(ctx, raw)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, _, err := doc.catalog(); err != nil {
			t.Fatalf("%s: catalog: %v", name, err)
		}
		page, ref, err := doc.firstPage(ctx)
		if err != nil {
			t.Fatalf("%s: first page: %v", name, err)
		}
		if typ, _ := page["Type"].(types.Name); typ != "Page" {
			t.Fatalf("%s: first page /Type = %v", name, page["Type"])
		}
		if _, ok := doc.objectOffset(ref.ObjectNumber.Value()); !ok {
			t.Fatalf("%s: no offset for the page object", name)
		}
		if n := doc.nextObjectNumber(); n <= doc.xref.MaxObjNr {
			t.Fatalf("%s: next object number %d is in use", name, n)
		}
		sigs, err := doc.signatureFields()
		if err != nil || len(sigs) != 0 {
			t.Fatalf("%s: signature fields = %v, %v; want none", name, sigs, err)
		}
	}
}

func TestReadPDFRejects(t *testing.T) {
	ctx := context.Background()
	pdf := simplePDF()
	png := []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00")
	cases := map[string]struct {
		raw  []byte
		want error
	}{
		"0 bytes":                   {nil, ErrNotPDF},
		"PNG":                       {png, ErrNotPDF},
		"text":                      {[]byte("hello, this is not a PDF"), ErrNotPDF},
		"header then garbage":       {append([]byte("%PDF-1.7\n"), bytes.Repeat([]byte{0x42}, 300)...), ErrNotPDF},
		"over MaxSize":              {make([]byte, MaxSize+1), ErrTooLarge},
		"encrypted (user password)": {encryptedPDF(t, "user-password"), ErrEncrypted},
		"encrypted (empty user pw)": {encryptedPDF(t, ""), ErrEncrypted},
	}
	for _, n := range []int{7, 8, 9, 15, 16, 17} {
		cases[fmt.Sprintf("first %d bytes", n)] = struct {
			raw  []byte
			want error
		}{pdf[:n], ErrNotPDF}
	}
	for name, tc := range cases {
		if _, err := readPDF(ctx, tc.raw); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", name, err, tc.want)
		}
	}
}

func TestReadPDFHonoursCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := readPDF(ctx, simplePDF()); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestLastXRef(t *testing.T) {
	pdf := simplePDF()
	off, isStream, err := lastXRef(pdf)
	if err != nil || isStream || !bytes.HasPrefix(pdf[off:], []byte("xref")) {
		t.Fatalf("classic: off=%d stream=%v err=%v", off, isStream, err)
	}
	// Bytes appended after %%EOF don't hide the last startxref.
	if off2, _, err := lastXRef(append(bytes.Clone(pdf), "\n% trailing comment\n"...)); err != nil || off2 != off {
		t.Fatalf("trailing junk: off=%d err=%v", off2, err)
	}

	bad := map[string][]byte{
		"no startxref":    bytes.ReplaceAll(bytes.Clone(pdf), []byte("startxref"), []byte("startxxxx")),
		"offset past EOF": replaceStartXRef(pdf, "99999999"),
		"offset zero":     replaceStartXRef(pdf, "0"),
		"offset not xref": replaceStartXRef(pdf, "20"),
		"no digits":       replaceStartXRef(pdf, "abc"),
	}
	for name, raw := range bad {
		if _, _, err := lastXRef(raw); !errors.Is(err, errNoStartXRef) {
			t.Errorf("%s: err = %v, want errNoStartXRef", name, err)
		}
	}
}

func replaceStartXRef(pdf []byte, value string) []byte {
	i := bytes.LastIndex(pdf, []byte("startxref\n"))
	j := bytes.Index(pdf[i:], []byte("\n%%EOF"))
	out := append(bytes.Clone(pdf[:i]), "startxref\n"+value...)
	return append(out, pdf[i+j:]...)
}

func TestLooksLikeObjectHeader(t *testing.T) {
	for in, want := range map[string]bool{
		"12 0 obj\n<<": true,
		"1 0 obj<<":    true,
		"12\r\n0\tobj": true,
		"12 0 ob":      false,
		"12 obj":       false,
		"x 0 obj":      false,
		"120obj":       false,
		"":             false,
		"xref\n0 1":    false,
	} {
		if got := looksLikeObjectHeader([]byte(in)); got != want {
			t.Errorf("%q: %v, want %v", in, got, want)
		}
	}
}

// signatureFields must survive hostile form trees: cycles, inherited /FT,
// direct (not indirect) /V values and duplicate references.
func TestSignatureFieldsHostileTrees(t *testing.T) {
	ctx := context.Background()
	raw := buildPDF([]string{
		"<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [6 0 R 6 0 R 8 0 R 9 0 R] >> >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>",
		contentStream("x"),
		"<< /Type /Sig /Filter /SecureStore /ByteRange [0 1 2 3] /Contents <00> >>",
		// 6: parent with /FT /Sig, kid 7 inherits it; 7 lists 6 as a kid (cycle).
		"<< /FT /Sig /T (parent) /Kids [7 0 R] >>",
		"<< /T (child) /V 5 0 R /Kids [6 0 R] >>",
		// 8: a second field pointing at the same signature dictionary.
		"<< /FT /Sig /T (dup) /V 5 0 R >>",
		// 9: a direct /V dictionary, which we can't locate in the file.
		"<< /FT /Sig /T (direct) /V << /Type /Sig >> >>",
	}, 1)
	doc, err := readPDF(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	sigs, err := doc.signatureFields()
	if err != nil {
		t.Fatal(err)
	}
	if len(sigs) != 2 {
		t.Fatalf("got %d signatures, want 2 (one real, one malformed)", len(sigs))
	}
	if sigs[0].dict == nil || sigs[0].ref.ObjectNumber.Value() != 5 {
		t.Errorf("first: %+v, want object 5", sigs[0])
	}
	if sigs[1].dict != nil {
		t.Errorf("second: want the malformed direct value, got %+v", sigs[1])
	}
}
