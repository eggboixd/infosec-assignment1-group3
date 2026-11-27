package pdfsign

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/eggboixd/infosec-assignment1-group3/internal/keypair"
)

// fakeKeys is a key directory: user ID → registered signing key.
type fakeKeys struct {
	pubs map[bson.ObjectID]*rsa.PublicKey
	err  error // returned for every lookup if set
}

func (f fakeKeys) PublicKey(_ context.Context, id bson.ObjectID, p keypair.Purpose) (*rsa.PublicKey, error) {
	if f.err != nil {
		return nil, f.err
	}
	if p != keypair.Signing {
		return nil, fmt.Errorf("test: verifier asked for the %s key", p)
	}
	pub, ok := f.pubs[id]
	if !ok {
		return nil, keypair.ErrNoKeys
	}
	return pub, nil
}

var signTime = time.Date(2026, 11, 28, 9, 30, 15, 0, time.UTC)

type signer struct {
	id   Identity
	priv *rsa.PrivateKey
}

// testSigners returns Ana (keyA) and Budi (keyB) and a directory holding
// both of their registered keys.
func testSigners(t testing.TB) (ana, budi signer, dir fakeKeys) {
	t.Helper()
	a, b, _ := testKeys(t)
	ana = signer{Identity{UserID: bson.NewObjectID(), Username: "ana"}, a}
	budi = signer{Identity{UserID: bson.NewObjectID(), Username: "Budi Müller 漢字"}, b}
	dir = fakeKeys{pubs: map[bson.ObjectID]*rsa.PublicKey{
		ana.id.UserID:  &a.PublicKey,
		budi.id.UserID: &b.PublicKey,
	}}
	return ana, budi, dir
}

func mustSign(t testing.TB, raw []byte, s signer) []byte {
	t.Helper()
	out, err := signPDF(context.Background(), raw, s.priv, s.id, signTime)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return out
}

func mustVerify(t *testing.T, raw []byte, dir keyDirectory) *Report {
	t.Helper()
	rep, err := verifyPDF(context.Background(), raw, dir)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	return rep
}

func fixtures(t *testing.T) map[string][]byte {
	return map[string][]byte{
		"classic xref": simplePDF(),
		"form":         formPDF(),
		"xref stream":  xrefStreamPDF(t),
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	ana, budi, dir := testSigners(t)
	for name, raw := range fixtures(t) {
		for _, s := range []signer{ana, budi} {
			out := mustSign(t, raw, s)
			if !bytes.HasPrefix(out, raw) {
				t.Fatalf("%s: original bytes changed", name)
			}
			rep := mustVerify(t, out, dir)
			if rep.Status != StatusValid || len(rep.Signatures) != 1 || rep.AppendedBytes != 0 || rep.FileSize != int64(len(out)) {
				t.Fatalf("%s/%s: report %+v", name, s.id.Username, rep)
			}
			sig := rep.Signatures[0]
			fp, _ := keyFingerprint(&s.priv.PublicKey)
			if !sig.Valid || sig.Problem != nil || sig.Format != FormatInApp || !sig.KeyMatches || !sig.CoversWholeFile ||
				sig.CoveredByLater || sig.SignerID != s.id.UserID || sig.SignerName != s.id.Username ||
				!sig.SignedAt.Equal(signTime) || sig.Fingerprint != keypair.FormatFingerprint(fp) ||
				sig.RevisionEnd != int64(len(out)) || sig.ByteRange[0] != 0 {
				t.Fatalf("%s/%s: signature %+v", name, s.id.Username, sig)
			}
			// pdfcpu still reads the signed file, with the widget on page 1.
			doc, err := readPDF(context.Background(), out)
			if err != nil {
				t.Fatalf("%s: signed file unreadable: %v", name, err)
			}
			page, _, err := doc.firstPage(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if annots, err := doc.derefArray(page["Annots"]); err != nil || len(annots) == 0 {
				t.Fatalf("%s: page 1 has no /Annots after signing: %v", name, err)
			}
		}
	}
}

// The signature in the file is a standard PKCS #1 v1.5 signature over the
// ByteRange: crypto/rsa (test-only reference) accepts it.
func TestEmbeddedSignatureMatchesStdlib(t *testing.T) {
	ana, _, _ := testSigners(t)
	out := mustSign(t, simplePDF(), ana)
	br := byteRangeOf(t, out)
	k := (ana.priv.N.BitLen() + 7) / 8
	sig, err := hex.DecodeString(string(out[br[1]+1 : br[1]+1+int64(2*k)]))
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	h.Write(out[:br[1]])
	h.Write(out[br[2] : br[2]+br[3]])
	if err := rsa.VerifyPKCS1v15(&ana.priv.PublicKey, crypto.SHA256, h.Sum(nil), sig); err != nil {
		t.Fatalf("crypto/rsa rejects the embedded signature: %v", err)
	}
}

var byteRangeRE = regexp.MustCompile(`/ByteRange \[0 (\d+) (\d+) (\d+)\] *`)

// byteRangeOf reads the newest /ByteRange from the raw bytes.
func byteRangeOf(t *testing.T, raw []byte) [4]int64 {
	t.Helper()
	all := byteRangeRE.FindAllSubmatch(raw, -1)
	if len(all) == 0 {
		t.Fatal("no /ByteRange in output")
	}
	m := all[len(all)-1]
	var br [4]int64
	for i := 1; i <= 3; i++ {
		br[i], _ = strconv.ParseInt(string(m[i]), 10, 64)
	}
	return br
}

// flipAt returns a copy of raw with the byte at i changed to c.
func flipAt(raw []byte, i int64, c byte) []byte {
	out := bytes.Clone(raw)
	out[i] = c
	return out
}

// problemOf verifies raw and returns the single signature's problem, or
// nil and the report when verification itself fails.
func problemOf(t *testing.T, raw []byte, dir keyDirectory) (*Report, error) {
	t.Helper()
	rep, err := verifyPDF(context.Background(), raw, dir)
	if err != nil {
		return nil, err
	}
	if len(rep.Signatures) != 1 {
		t.Fatalf("got %d signatures", len(rep.Signatures))
	}
	return rep, nil
}

func TestVerifyDetectsTampering(t *testing.T) {
	ana, _, dir := testSigners(t)
	out := mustSign(t, simplePDF(), ana)
	br := byteRangeOf(t, out)

	// A byte inside range 1: the visible text "Hello" → "Jello" (same length).
	hello := int64(bytes.Index(out, []byte("Hello")))
	// A byte inside range 2: a hex digit of the signer's /Name.
	name := int64(bytes.Index(out[br[2]:], []byte("/Name <FEFF"))) + br[2] + len64("/Name <FEFF")
	// A digit inside the signature in the hole.
	inSig := br[1] + 1 + 10

	cases := map[string]struct {
		raw  []byte
		want error
	}{
		"range 1 (page text)":   {flipAt(out, hello, 'J'), ErrBadSignature},
		"range 2 (signer name)": {flipAt(out, name, flipHex(out[name])), ErrBadSignature},
		"signature digit":       {flipAt(out, inSig, flipHex(out[inSig])), ErrBadSignature},
		"zeroed signature":      {zeroHole(out, br), ErrBadSignature},
		"padding not zero":      {flipAt(out, br[2]-2, '1'), ErrMalformedSignature},
	}
	for label, tc := range cases {
		rep, err := problemOf(t, tc.raw, dir)
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if rep.Status != StatusInvalid || rep.Signatures[0].Valid || !errors.Is(rep.Signatures[0].Problem, tc.want) {
			t.Errorf("%s: status %s, problem %v; want invalid / %v", label, rep.Status, rep.Signatures[0].Problem, tc.want)
		}
	}
}

func len64(s string) int64 { return int64(len(s)) }

func flipHex(c byte) byte {
	if c == '0' {
		return '1'
	}
	return '0'
}

func zeroHole(raw []byte, br [4]int64) []byte {
	out := bytes.Clone(raw)
	for i := br[1] + 1; i < br[2]-1; i++ {
		out[i] = '0'
	}
	return out
}

// Truncating the file or the signature hex breaks it: either it is no
// longer a readable PDF, or the signature is invalid. Never valid.
func TestVerifyTruncated(t *testing.T) {
	ana, _, dir := testSigners(t)
	out := mustSign(t, simplePDF(), ana)
	br := byteRangeOf(t, out)
	shortSig := append(bytes.Clone(out[:br[1]+1+700]), out[br[1]+1+702:]...)
	for name, raw := range map[string][]byte{
		"cut inside range 2":      out[:br[2]+20],
		"cut 1 byte":              out[:len(out)-1],
		"cut inside the hole":     out[:br[1]+50],
		"signature hex 2 shorter": shortSig,
	} {
		rep, err := verifyPDF(context.Background(), raw, dir)
		if err == nil && rep.Status == StatusValid {
			t.Errorf("%s: still valid", name)
		}
	}
}

// Rewrites the ByteRange text in place (same width), keeping the file's
// offsets, so only the ByteRange checks decide.
func withByteRange(t *testing.T, raw []byte, br [4]int64) []byte {
	t.Helper()
	locs := byteRangeRE.FindAllIndex(raw, -1)
	loc := locs[len(locs)-1]
	text := fmt.Sprintf("/ByteRange [%d %d %d %d]", br[0], br[1], br[2], br[3])
	width := loc[1] - loc[0]
	if len(text) > width {
		t.Fatalf("ByteRange %q does not fit in %d bytes", text, width)
	}
	out := bytes.Clone(raw)
	copy(out[loc[0]:], text+string(bytes.Repeat([]byte{' '}, width-len(text))))
	return out
}

func TestVerifyRejectsByteRangeManipulation(t *testing.T) {
	ana, _, dir := testSigners(t)
	out := mustSign(t, simplePDF(), ana)
	br := byteRangeOf(t, out)
	size := int64(len(out))
	for name, bad := range map[string][4]int64{
		"not starting at 0":     {1, br[1] - 1, br[2], br[3]},
		"hole before /Contents": {0, br[1] - 2, br[2], br[3]},
		"hole shifted":          {0, br[1] + 2, br[2] + 2, br[3] - 2},
		"hole too small":        {0, br[1] + 2, br[2], br[3]},
		"overlapping ranges":    {0, br[2], br[1], br[3]},
		"empty first range":     {0, 0, br[2], br[3]},
		"past end of file":      {0, br[1], br[2], br[3] + 1},
		"huge length":           {0, br[1], br[2], 9_999_999_999},
		"odd hole":              {0, br[1], br[2] - 1, br[3] + 1},
		// Covers less than the file: a valid-looking range that leaves
		// bytes unsigned at the end must still fail, because those bytes
		// were signed (the range text itself was signed).
		"shorter second range": {0, br[1], br[2], br[3] - 10},
	} {
		raw := withByteRange(t, out, bad)
		rep, err := verifyPDF(context.Background(), raw, dir)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		sig := rep.Signatures[0]
		if sig.Valid || rep.Status != StatusInvalid {
			t.Errorf("%s: accepted (size %d, br %v)", name, size, bad)
		}
		if name != "shorter second range" && !errors.Is(sig.Problem, ErrByteRange) {
			t.Errorf("%s: problem %v, want ErrByteRange", name, sig.Problem)
		}
	}
}

// Bytes appended after signing (here a whole incremental update that
// changes the catalog, as in the incremental saving attack) leave the
// signature valid for its revision but must be reported.
func TestVerifyFlagsAppendedContent(t *testing.T) {
	ana, _, dir := testSigners(t)
	for name, raw := range fixtures(t) {
		out := mustSign(t, raw, ana)

		comment := append(bytes.Clone(out), "% added later\n"...)
		rep := mustVerify(t, comment, dir)
		if rep.Status != StatusModified || rep.AppendedBytes != int64(len("% added later\n")) {
			t.Fatalf("%s comment: status %s appended %d", name, rep.Status, rep.AppendedBytes)
		}
		if s := rep.Signatures[0]; !s.Valid || s.CoversWholeFile {
			t.Fatalf("%s comment: signature %+v", name, s)
		}

		u, _ := newUpdate(t, out)
		w, err := u.write()
		if err != nil {
			t.Fatal(err)
		}
		rep = mustVerify(t, w.out, dir)
		if rep.Status != StatusModified || rep.AppendedBytes != int64(len(w.out)-len(out)) {
			t.Fatalf("%s update: status %s appended %d", name, rep.Status, rep.AppendedBytes)
		}
	}
}

func TestVerifySignerProblems(t *testing.T) {
	ana, budi, dir := testSigners(t)
	out := mustSign(t, simplePDF(), ana)

	// Ana's registered key is now Budi's: the fingerprint in the PDF no
	// longer matches (a key swapped in the database, or a different key).
	swapped := fakeKeys{pubs: map[bson.ObjectID]*rsa.PublicKey{ana.id.UserID: &budi.priv.PublicKey}}
	rep, _ := problemOf(t, out, swapped)
	if s := rep.Signatures[0]; s.Valid || s.KeyMatches || !errors.Is(s.Problem, ErrKeyMismatch) {
		t.Errorf("swapped key: %+v", s)
	}

	// The signer isn't known here.
	rep, _ = problemOf(t, out, fakeKeys{pubs: map[bson.ObjectID]*rsa.PublicKey{}})
	if s := rep.Signatures[0]; s.Valid || !errors.Is(s.Problem, ErrUnknownSigner) || s.SignerID != ana.id.UserID {
		t.Errorf("unknown signer: %+v", s)
	}

	// The signer ID in the PDF is changed to Budi's (same length): his key
	// fingerprint differs from the one in the PDF.
	swappedID := bytes.Replace(out, []byte(ana.id.UserID.Hex()), []byte(budi.id.UserID.Hex()), 1)
	rep, _ = problemOf(t, swappedID, dir)
	if s := rep.Signatures[0]; s.Valid || !errors.Is(s.Problem, ErrKeyMismatch) {
		t.Errorf("swapped signer ID: %+v", s)
	}

	// The directory itself fails: that's an error, not a verdict.
	if _, err := verifyPDF(context.Background(), out, fakeKeys{err: errors.New("mongo down")}); err == nil {
		t.Error("directory failure: no error")
	}
}

func TestVerifyUnsupportedFormat(t *testing.T) {
	ana, _, dir := testSigners(t)
	out := mustSign(t, simplePDF(), ana)
	// Same length, so every offset stays valid.
	for name, sub := range map[string]string{
		"CMS":     "adbe.pkcs7.detached",
		"unknown": "ETSI.CAdES.detached",
	} {
		from := "/SubFilter /" + subFilterInApp
		to := "/SubFilter /" + sub
		to += string(bytes.Repeat([]byte{' '}, len(from)-len(to)))
		raw := bytes.Replace(out, []byte(from), []byte(to), 1)
		rep, _ := problemOf(t, raw, dir)
		if s := rep.Signatures[0]; s.Valid || !errors.Is(s.Problem, ErrUnsupportedFormat) {
			t.Errorf("%s: %+v", name, s)
		}
	}
}

func TestVerifyUnsigned(t *testing.T) {
	_, _, dir := testSigners(t)
	for name, raw := range fixtures(t) {
		rep := mustVerify(t, raw, dir)
		if rep.Status != StatusUnsigned || len(rep.Signatures) != 0 || rep.AppendedBytes != 0 {
			t.Errorf("%s: %+v", name, rep)
		}
	}
}

func TestVerifyMalformedSignatureValue(t *testing.T) {
	_, _, dir := testSigners(t)
	raw := buildPDF([]string{
		"<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [4 0 R] >> >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>",
		"<< /FT /Sig /T (direct) /V << /Type /Sig /ByteRange [0 1 2 3] >> >>",
	}, 1)
	rep := mustVerify(t, raw, dir)
	if rep.Status != StatusInvalid || !errors.Is(rep.Signatures[0].Problem, ErrMalformedSignature) {
		t.Fatalf("%+v", rep)
	}
}

// Ana signs, then Budi signs the signed file: both stay valid, and Ana's
// signature is reported as covered by Budi's.
func TestSignTwice(t *testing.T) {
	ana, budi, dir := testSigners(t)
	for name, raw := range fixtures(t) {
		once := mustSign(t, raw, ana)
		twice := mustSign(t, once, budi)
		rep := mustVerify(t, twice, dir)
		if rep.Status != StatusValid || len(rep.Signatures) != 2 {
			t.Fatalf("%s: %+v", name, rep)
		}
		first, second := rep.Signatures[0], rep.Signatures[1]
		if !first.Valid || first.SignerID != ana.id.UserID || first.CoversWholeFile || !first.CoveredByLater ||
			first.RevisionEnd != int64(len(once)) {
			t.Fatalf("%s: first %+v", name, first)
		}
		if !second.Valid || second.SignerID != budi.id.UserID || !second.CoversWholeFile || second.CoveredByLater {
			t.Fatalf("%s: second %+v", name, second)
		}
		// The same user may sign again too.
		thrice := mustSign(t, twice, ana)
		if rep := mustVerify(t, thrice, dir); rep.Status != StatusValid || len(rep.Signatures) != 3 {
			t.Fatalf("%s: third signature: %+v", name, rep)
		}
	}
}

func TestSignRejects(t *testing.T) {
	ana, _, _ := testSigners(t)
	_, _, small := testKeys(t)
	ctx := context.Background()
	for name, tc := range map[string]struct {
		raw  []byte
		want error
	}{
		"0 bytes":      {nil, ErrNotPDF},
		"not a PDF":    {[]byte("GIF89a……"), ErrNotPDF},
		"encrypted":    {encryptedPDF(t, ""), ErrEncrypted},
		"no startxref": {bytes.ReplaceAll(simplePDF(), []byte("startxref"), []byte("startxxxx")), ErrUnsupportedPDF},
	} {
		if _, err := signPDF(ctx, tc.raw, ana.priv, ana.id, signTime); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", name, err, tc.want)
		}
	}
	if _, err := signPDF(ctx, simplePDF(), nil, ana.id, signTime); !errors.Is(err, errBadKey) {
		t.Errorf("nil key: %v", err)
	}
	if _, err := signPDF(ctx, simplePDF(), ana.priv, Identity{Username: "x"}, signTime); err == nil {
		t.Error("empty signer ID accepted")
	}

	// The 17th signature is refused (2048-bit key to keep the test fast).
	s := signer{Identity{UserID: bson.NewObjectID(), Username: "many"}, small}
	raw := simplePDF()
	for range maxSignatures {
		raw = mustSign(t, raw, s)
	}
	if _, err := signPDF(ctx, raw, s.priv, s.id, signTime); !errors.Is(err, ErrTooManySignatures) {
		t.Errorf("17th signature: %v", err)
	}
	dir := fakeKeys{pubs: map[bson.ObjectID]*rsa.PublicKey{s.id.UserID: &small.PublicKey}}
	if rep := mustVerify(t, raw, dir); rep.Status != StatusValid || len(rep.Signatures) != maxSignatures {
		t.Errorf("16 signatures: status %s, %d signatures", rep.Status, len(rep.Signatures))
	}
}

func TestTextStringRoundTrip(t *testing.T) {
	for _, s := range []string{"", "ana", "Budi Müller", "漢字 😀", "a(b)c\\"} {
		if got := textString(encodeTextString(s)); got != s {
			t.Errorf("%q → %q", s, got)
		}
	}
	if got := cleanName("evil‮exe.pdf\x00\n"); got != "evilexe.pdf" {
		t.Errorf("cleanName = %q", got)
	}
	long := cleanName(string(bytes.Repeat([]byte("é"), 100)))
	if n := len([]rune(long)); n != maxNameRunes {
		t.Errorf("cleanName kept %d runes", n)
	}
}

// FuzzVerifyPDF: verification never panics, whatever the input. The seed
// corpus runs with every go test; go test -fuzz explores further.
//
// It uses one 2048-bit key so that each fuzz worker starts quickly. When
// fuzzing, pass a short -fuzzminimizetime (for example 2s): minimising each
// new input of a ~2 KiB PDF otherwise pauses progress for up to a minute.
func FuzzVerifyPDF(f *testing.F) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatal(err)
	}
	ana := signer{Identity{UserID: bson.NewObjectID(), Username: "ana"}, key}
	dir := fakeKeys{pubs: map[bson.ObjectID]*rsa.PublicKey{ana.id.UserID: &key.PublicKey}}
	signed := mustSign(f, simplePDF(), ana)
	f.Add(signed)
	f.Add(simplePDF())
	f.Add(formPDF())
	f.Add([]byte("%PDF-1.7\n"))
	f.Add(signed[:len(signed)/2])
	f.Fuzz(func(t *testing.T, raw []byte) {
		rep, err := verifyPDF(context.Background(), raw, dir)
		if err == nil && rep == nil {
			t.Fatal("nil report without error")
		}
	})
}

// TestWriteSamples writes signed sample PDFs for checking with third-party
// tools (qpdf, pdfsig, pyHanko; see docs/pdfsign.md). It runs only when
// PDFSIGN_SAMPLES_DIR is set. The keys are throwaway test keys and the
// content is synthetic.
func TestWriteSamples(t *testing.T) {
	dirPath := os.Getenv("PDFSIGN_SAMPLES_DIR")
	if dirPath == "" {
		t.Skip("set PDFSIGN_SAMPLES_DIR to write signed samples")
	}
	ana, budi, _ := testSigners(t)
	samples := map[string][]byte{}
	for name, raw := range fixtures(t) {
		file := strings.ReplaceAll(name, " ", "-")
		once := mustSign(t, raw, ana)
		samples[file+"-unsigned.pdf"] = raw
		samples[file+"-signed.pdf"] = once
		samples[file+"-signed-twice.pdf"] = mustSign(t, once, budi)
	}
	for name, b := range samples {
		if err := os.WriteFile(filepath.Join(dirPath, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
