package pdfsign

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
)

// Test PDFs are built in code, so the repository holds no binary fixtures
// and every byte is synthetic (no personal data).

// buildPDF writes a classic PDF 1.7 file with objects 1..len(objs) (object
// i+1 is objs[i]) and a single xref table. rootObj is the catalog.
func buildPDF(objs []string, rootObj int) []byte {
	var b bytes.Buffer
	b.WriteString("%PDF-1.7\n%\xE2\xE3\xCF\xD3\n")
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
	fmt.Fprintf(&b, "trailer\n<< /Size %d /Root %d 0 R /ID [<0123456789abcdef0123456789abcdef> <0123456789abcdef0123456789abcdef>] >>\nstartxref\n%d\n%%%%EOF\n",
		len(objs)+1, rootObj, xref)
	return b.Bytes()
}

func contentStream(text string) string {
	s := fmt.Sprintf("BT /F1 24 Tf 72 700 Td (%s) Tj ET", text)
	return fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(s), s)
}

// simplePDF is one page with one line of text and a classic xref table.
func simplePDF() []byte {
	return buildPDF([]string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
		contentStream("Hello, signed world"),
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
	}, 1)
}

// formPDF has two pages, an indirect AcroForm with a text field, and an
// indirect /Annots array on page 1 holding that field's widget. The
// signer must extend those objects instead of the catalog and page.
func formPDF() []byte {
	return buildPDF([]string{
		"<< /Type /Catalog /Pages 2 0 R /AcroForm 7 0 R /Lang (en-US) >>",
		"<< /Type /Pages /Kids [3 0 R 6 0 R] /Count 2 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> /Annots 9 0 R >>",
		contentStream("Page one (with a form)"),
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 10 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
		"<< /Fields [8 0 R] /DA (/Helv 0 Tf 0 g) >>",
		"<< /FT /Tx /T (name) /V (Ana) /Type /Annot /Subtype /Widget /Rect [72 600 300 620] /P 3 0 R >>",
		"[8 0 R]",
		contentStream("Page two"),
	}, 1)
}

// pdfcpuConf is a configuration that never touches pdfcpu's config
// directory.
func pdfcpuConf() *model.Configuration {
	conf := model.NewStatelessConfiguration()
	conf.Offline = true
	return conf
}

// xrefStreamPDF re-saves simplePDF with pdfcpu, which writes a
// cross-reference stream and compressed object streams, the way Word and
// pdfTeX output often looks.
func xrefStreamPDF(t testing.TB) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := api.Optimize(context.Background(), bytes.NewReader(simplePDF()), &out, pdfcpuConf(), nil); err != nil {
		t.Fatalf("pdfcpu optimize: %v", err)
	}
	if _, isStream, err := lastXRef(out.Bytes()); err != nil || !isStream {
		t.Fatalf("fixture: want an xref stream, got stream=%v err=%v", isStream, err)
	}
	return out.Bytes()
}

// encryptedPDF encrypts simplePDF with AES-256. With userPW == "" any reader
// opens it without a password, but its content is still encrypted.
func encryptedPDF(t testing.TB, userPW string) []byte {
	t.Helper()
	conf := pdfcpuConf()
	conf.Cmd = model.ENCRYPT
	conf.UserPW = userPW
	conf.OwnerPW = "owner-password"
	conf.EncryptUsingAES = true
	conf.EncryptKeyLength = 256
	var out bytes.Buffer
	if err := api.Encrypt(context.Background(), bytes.NewReader(simplePDF()), &out, conf); err != nil {
		t.Fatalf("pdfcpu encrypt: %v", err)
	}
	return out.Bytes()
}
