package pdfsign

// Embedding a signature (D48). signPDF adds one incremental update with:
//
//   - a signature dictionary (format.go) whose /ByteRange and /Contents are
//     fixed-width placeholders;
//   - a signature field that is also its own invisible widget annotation
//     (/Rect [0 0 0 0]), pointing at that dictionary with /V;
//   - the field added to the AcroForm (/Fields, /SigFlags 3), and the widget
//     to the first page's /Annots, rewriting only the objects that hold
//     those arrays.
//
// After the update is laid out, the offsets are known: /ByteRange is filled
// in, SHA-256 is computed over everything except the /Contents hole, the
// digest is signed with our RSA code, and the signature's hex is written
// into the hole. Nothing moves, so the offsets stay correct.

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
)

// sigFlagsSignaturesExist|sigFlagsAppendOnly (ISO 32000-1 Table 219): the
// document has signatures, and must be saved incrementally so they stay
// valid.
const sigFlags = 3

// annotFlagsPrintLocked is /F for the widget: Print (4) | Locked (128).
const annotFlagsPrintLocked = 132

// signPDF returns raw with an in-app signature by priv for id at time now.
// It neither reads nor writes anything outside memory.
func signPDF(ctx context.Context, raw []byte, priv *rsa.PrivateKey, id Identity, now time.Time) ([]byte, error) {
	if priv == nil {
		return nil, errBadKey
	}
	if err := checkPublic(&priv.PublicKey); err != nil {
		return nil, err
	}
	if k := (priv.N.BitLen() + 7) / 8; k > inAppContentsSize {
		return nil, fmt.Errorf("%w: %d-byte signatures don't fit", errBadKey, k)
	}
	if id.UserID.IsZero() {
		return nil, fmt.Errorf("pdfsign: sign: empty signer ID")
	}

	doc, err := readPDF(ctx, raw)
	if err != nil {
		return nil, err
	}
	existing, err := doc.signatureFields()
	if err != nil {
		return nil, err
	}
	if len(existing) >= maxSignatures {
		return nil, ErrTooManySignatures
	}
	prevXRef, isStream, err := lastXRef(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnsupportedPDF, err)
	}
	cat, rootRef, err := doc.catalog()
	if err != nil {
		return nil, err
	}
	page, pageRef, err := doc.firstPage(ctx)
	if err != nil {
		return nil, err
	}
	fp, err := keyFingerprint(&priv.PublicKey)
	if err != nil {
		return nil, err
	}

	next := doc.nextObjectNumber()
	sigNr, fieldNr := next, next+1
	sigRef, fieldRef := ref(sigNr, 0), ref(fieldNr, 0)
	u := &incrementalUpdate{
		base:       raw,
		prevXRef:   prevXRef,
		xrefStream: isStream,
		nextNr:     next + 2,
		root:       rootRef,
		info:       doc.xref.Info,
		id:         doc.xref.ID,
	}
	add := func(r types.IndirectRef, o types.Object) error {
		body, err := objectBody(o)
		if err != nil {
			return err
		}
		u.objects = append(u.objects, updateObject{nr: r.ObjectNumber.Value(), gen: r.GenerationNumber.Value(), body: body})
		return nil
	}

	// 1. The field + widget.
	field := types.Dict{
		"FT":      types.Name("Sig"),
		"Type":    types.Name("Annot"),
		"Subtype": types.Name("Widget"),
		"F":       types.Integer(annotFlagsPrintLocked),
		"Rect":    types.Array{types.Integer(0), types.Integer(0), types.Integer(0), types.Integer(0)},
		"T":       types.StringLiteral(fmt.Sprintf("SecureStore Signature %d", sigNr)),
		"V":       sigRef,
		"P":       pageRef,
	}
	if err := add(fieldRef, field); err != nil {
		return nil, err
	}

	// 2. The AcroForm: in its own object, or inline in the catalog.
	var newForm types.Dict
	formObj := cat["AcroForm"]
	form, err := doc.derefDict(formObj)
	if err != nil {
		return nil, fmt.Errorf("%w: AcroForm", ErrUnsupportedPDF)
	}
	if form == nil {
		form = types.Dict{}
	}
	fields, err := doc.derefArray(form["Fields"])
	if err != nil {
		return nil, fmt.Errorf("%w: AcroForm fields", ErrUnsupportedPDF)
	}
	flags := sigFlags
	if f, ok := form["SigFlags"].(types.Integer); ok {
		flags |= int(f)
	}
	// /Fields becomes a direct array: the same content, without having to
	// rewrite a separate array object.
	newForm = withEntry(withEntry(form, "Fields", appendRef(fields, fieldRef)), "SigFlags", types.Integer(flags))
	if formRef, ok := formObj.(types.IndirectRef); ok {
		if err := add(formRef, newForm); err != nil {
			return nil, err
		}
	} else if err := add(rootRef, withEntry(cat, "AcroForm", newForm)); err != nil {
		return nil, err
	}

	// 3. The widget on page 1: extend an /Annots array object, or the page.
	annotsObj := page["Annots"]
	annots, err := doc.derefArray(annotsObj)
	if err != nil {
		return nil, fmt.Errorf("%w: page annotations", ErrUnsupportedPDF)
	}
	if annotsRef, ok := annotsObj.(types.IndirectRef); ok {
		err = add(annotsRef, appendRef(annots, fieldRef))
	} else {
		err = add(pageRef, withEntry(page, "Annots", appendRef(annots, fieldRef)))
	}
	if err != nil {
		return nil, err
	}

	// 4. The signature dictionary, with placeholders.
	sigBody, brAt, contentsAt := inAppSigDict(id, fp, now)
	u.objects = append(u.objects, updateObject{nr: sigNr, gen: 0, body: sigBody})

	w, err := u.write()
	if err != nil {
		return nil, err
	}
	out := w.out
	body := w.bodyAt[sigNr]
	holeStart := body + int64(contentsAt)                 // the '<'
	holeEnd := holeStart + 2 + 2*int64(inAppContentsSize) // after the '>'
	br := [4]int64{0, holeStart, holeEnd, int64(len(out)) - holeEnd}

	// 5. Fill in /ByteRange (inside the signed bytes), then sign.
	brText := []byte(fmt.Sprintf("[0 %d %d %d]", br[1], br[2], br[3]))
	if len(brText) > byteRangeWidth {
		return nil, ErrTooLarge
	}
	brText = append(brText, bytes.Repeat([]byte{' '}, byteRangeWidth-len(brText))...)
	copy(out[body+int64(brAt):], brText)

	sig, err := signDigest(priv, signedDigest(out, br))
	if err != nil {
		return nil, err
	}
	hex.Encode(out[holeStart+1:], sig) // the rest of the hole stays '0'
	return out, nil
}

// inAppSigDict returns the signature dictionary body and the offsets,
// within it, of the /ByteRange placeholder and of the '<' opening
// /Contents. It is written as text, not with writeObject, because the
// placeholders' positions must be known exactly.
func inAppSigDict(id Identity, fp []byte, now time.Time) (body []byte, byteRangeAt, contentsAt int) {
	var b bytes.Buffer
	b.WriteString("<</Type /Sig /Filter /" + filterInApp + " /SubFilter /" + subFilterInApp + "\n/ByteRange ")
	byteRangeAt = b.Len()
	b.Write(bytes.Repeat([]byte{' '}, byteRangeWidth))
	b.WriteString("\n/Contents ")
	contentsAt = b.Len()
	b.WriteByte('<')
	b.Write(bytes.Repeat([]byte{'0'}, 2*inAppContentsSize))
	b.WriteString(">\n")
	// Everything below is signed (it is after the hole, in the second range).
	fmt.Fprintf(&b, "/M (%s)\n", now.UTC().Format(pdfDateLayout))
	fmt.Fprintf(&b, "/Name %s\n", encodeTextString(cleanName(id.Username)).PDFString())
	fmt.Fprintf(&b, "/%s (%s)\n", keySigner, id.UserID.Hex())
	fmt.Fprintf(&b, "/%s <%X>\n>>", keyKeyFP, fp)
	return b.Bytes(), byteRangeAt, contentsAt
}

// signedDigest is SHA-256 over the two ranges a ByteRange names. The caller
// has already checked that br lies within raw.
func signedDigest(raw []byte, br [4]int64) []byte {
	h := sha256.New()
	h.Write(raw[br[0] : br[0]+br[1]])
	h.Write(raw[br[2] : br[2]+br[3]])
	return h.Sum(nil)
}
