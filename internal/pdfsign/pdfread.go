package pdfsign

// Reading the PDF structure. pdfcpu parses the file (cross-reference tables
// and streams, object streams, filters); this file only asks it questions:
// the catalog, the first page, the signature fields and where objects sit
// in the file. Nothing here signs or verifies anything (D47).

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
)

const (
	// headerWindow is how far into the file the "%PDF-" header may start.
	// The spec says byte 0, but readers accept up to 1024 bytes of junk
	// before it, and so do we.
	headerWindow = 1024
	// tailWindow is how far from the end we look for "startxref".
	tailWindow = 2048
	// maxFieldDepth and maxFields bound the AcroForm walk, which follows
	// references an attacker controls.
	maxFieldDepth = 32
	maxFields     = 10_000
)

// pdfDoc is a parsed PDF together with its raw bytes.
type pdfDoc struct {
	raw  []byte
	xref *model.XRefTable
}

// readPDF parses raw with pdfcpu. It returns ErrNotPDF for anything that
// isn't a readable PDF, ErrEncrypted for a password-protected one and
// ErrTooLarge above MaxSize.
//
// pdfcpu's own error text is deliberately dropped: parser messages can
// quote pieces of the file, and the file may hold private data that must
// not reach the logs.
func readPDF(ctx context.Context, raw []byte) (doc *pdfDoc, err error) {
	if len(raw) > MaxSize {
		return nil, ErrTooLarge
	}
	if !bytes.Contains(raw[:min(len(raw), headerWindow)], []byte("%PDF-")) {
		return nil, ErrNotPDF
	}
	// A parser bug on hostile input must not take the server down.
	defer func() {
		if r := recover(); r != nil {
			doc, err = nil, ErrNotPDF
		}
	}()

	// The stateless configuration never reads or writes pdfcpu's config
	// directory (NewDefaultConfiguration would create one under the user's
	// profile).
	conf := model.NewStatelessConfiguration()
	conf.Offline = true // reading never needs the network; make sure it can't use it
	pctx, err := api.ReadContext(ctx, bytes.NewReader(raw), conf)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		// pdfcpu fails on a PDF it can't decrypt with an empty password.
		// "/Encrypt" only picks the clearer message; either way we refuse.
		if bytes.Contains(raw, []byte("/Encrypt")) {
			return nil, ErrEncrypted
		}
		return nil, ErrNotPDF
	}
	xref := pctx.XRefTable
	if xref.Encrypt != nil {
		// Opened with the empty user password, but still encrypted: the
		// stored bytes are ciphertext, and our update would be plaintext.
		return nil, ErrEncrypted
	}
	if xref.Root == nil {
		return nil, ErrNotPDF
	}
	if _, err := xref.Catalog(); err != nil {
		return nil, ErrNotPDF
	}
	return &pdfDoc{raw: raw, xref: xref}, nil
}

// catalog returns the document catalog (/Root) and its reference.
func (d *pdfDoc) catalog() (types.Dict, types.IndirectRef, error) {
	cat, err := d.xref.Catalog()
	if err != nil || d.xref.Root == nil {
		return nil, types.IndirectRef{}, ErrUnsupportedPDF
	}
	return cat, *d.xref.Root, nil
}

// firstPage returns page 1 and its reference. The invisible signature
// widget is attached to it.
func (d *pdfDoc) firstPage(ctx context.Context) (types.Dict, types.IndirectRef, error) {
	if err := d.xref.EnsurePageCount(); err != nil || d.xref.PageCount < 1 {
		return nil, types.IndirectRef{}, ErrUnsupportedPDF
	}
	page, ref, _, err := d.xref.PageDict(ctx, 1, false)
	if err != nil || page == nil || ref == nil {
		return nil, types.IndirectRef{}, ErrUnsupportedPDF
	}
	return page, *ref, nil
}

// deref resolves o if it is an indirect reference. A dangling reference
// resolves to nil, as the PDF spec says.
func (d *pdfDoc) deref(o types.Object) (types.Object, error) {
	return d.xref.Dereference(o)
}

// derefDict resolves o and returns it as a dictionary, or nil if it is
// missing or null. Anything else is an error.
func (d *pdfDoc) derefDict(o types.Object) (types.Dict, error) {
	v, err := d.deref(o)
	if err != nil {
		return nil, err
	}
	switch v := v.(type) {
	case nil:
		return nil, nil
	case types.Dict:
		return v, nil
	}
	return nil, fmt.Errorf("pdfsign: expected a dictionary, got %T", v)
}

// derefArray is derefDict for arrays.
func (d *pdfDoc) derefArray(o types.Object) (types.Array, error) {
	v, err := d.deref(o)
	if err != nil {
		return nil, err
	}
	switch v := v.(type) {
	case nil:
		return nil, nil
	case types.Array:
		return v, nil
	}
	return nil, fmt.Errorf("pdfsign: expected an array, got %T", v)
}

// nextObjectNumber is the first object number not used by the file.
// pdfcpu corrects a wrong trailer /Size to MaxObjNr+1 while reading.
func (d *pdfDoc) nextObjectNumber() int {
	n := d.xref.MaxObjNr + 1
	if d.xref.Size != nil && *d.xref.Size > n {
		n = *d.xref.Size
	}
	return n
}

// objectOffset is the byte offset of object objNr in the newest revision.
// For an object stored inside an object stream it is the stream's offset.
func (d *pdfDoc) objectOffset(objNr int) (int64, bool) {
	e, ok := d.xref.Table[objNr]
	if !ok || e == nil || e.Free {
		return 0, false
	}
	// pdfcpu doesn't always set Compressed for objects it loads lazily from
	// an object stream, but it always records which stream holds them.
	if e.ObjectStream != nil {
		if *e.ObjectStream == objNr {
			return 0, false
		}
		return d.objectOffset(*e.ObjectStream)
	}
	if e.Compressed {
		return 0, false
	}
	if e.Offset == nil {
		return 0, false
	}
	return *e.Offset, true
}

// sigField is one signature field that has a value (a signature).
type sigField struct {
	// ref is the signature dictionary's reference (the field's /V).
	ref types.IndirectRef
	// dict is the signature dictionary: /Filter, /ByteRange, /Contents, …
	dict types.Dict
}

// signatureFields walks the AcroForm field tree and returns every
// signature field with a value, in tree order. /FT is inheritable, so it is
// passed down to /Kids. Each signature dictionary is returned once, even if
// several fields point to it.
func (d *pdfDoc) signatureFields() ([]sigField, error) {
	cat, _, err := d.catalog()
	if err != nil {
		return nil, err
	}
	form, err := d.derefDict(cat["AcroForm"])
	if err != nil || form == nil {
		return nil, err
	}
	fields, err := d.derefArray(form["Fields"])
	if err != nil {
		return nil, err
	}

	w := fieldWalker{doc: d, visited: map[int]bool{}, seenSig: map[int]bool{}}
	for _, f := range fields {
		if err := w.walk(f, "", 0); err != nil {
			return nil, err
		}
	}
	return w.out, nil
}

type fieldWalker struct {
	doc     *pdfDoc
	visited map[int]bool // field objects already walked (cycle guard)
	seenSig map[int]bool // signature dictionaries already returned
	count   int
	out     []sigField
}

func (w *fieldWalker) walk(o types.Object, inheritedFT string, depth int) error {
	if depth > maxFieldDepth {
		return fmt.Errorf("%w: form fields nested too deeply", ErrUnsupportedPDF)
	}
	if w.count++; w.count > maxFields {
		return fmt.Errorf("%w: too many form fields", ErrUnsupportedPDF)
	}
	if ref, ok := o.(types.IndirectRef); ok {
		if w.visited[ref.ObjectNumber.Value()] {
			return nil
		}
		w.visited[ref.ObjectNumber.Value()] = true
	}
	field, err := w.doc.derefDict(o)
	if err != nil || field == nil {
		// A broken entry in someone else's form is skipped, not fatal.
		return nil
	}

	ft := inheritedFT
	if n, ok := field["FT"].(types.Name); ok {
		ft = string(n)
	}
	if ft == "Sig" {
		if v, ok := field["V"]; ok && v != nil {
			ref, isRef := v.(types.IndirectRef)
			sig, err := w.doc.derefDict(v)
			switch {
			case !isRef || err != nil || sig == nil:
				// A signature value must be an indirect dictionary (we need
				// its position in the file). Report it as a broken signature
				// rather than ignoring it.
				w.out = append(w.out, sigField{dict: nil})
			case !w.seenSig[ref.ObjectNumber.Value()]:
				w.seenSig[ref.ObjectNumber.Value()] = true
				w.out = append(w.out, sigField{ref: ref, dict: sig})
			}
		}
	}
	kids, err := w.doc.derefArray(field["Kids"])
	if err != nil {
		return nil // a malformed /Kids is skipped like a broken entry
	}
	for _, k := range kids {
		if err := w.walk(k, ft, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// errNoStartXRef means the file has no usable "startxref" pointer.
var errNoStartXRef = errors.New("pdfsign: no startxref")

// lastXRef finds the offset of the newest cross-reference section from the
// "startxref" line at the end of the file, and whether that section is a
// cross-reference stream (PDF 1.5+) rather than a classic "xref" table.
//
// We read it ourselves rather than from pdfcpu because our update must
// point /Prev at exactly this offset, and pdfcpu may repair a broken file
// silently; if the pointer is wrong we refuse to sign instead.
func lastXRef(raw []byte) (offset int64, isStream bool, err error) {
	tail := raw[max(0, len(raw)-tailWindow):]
	i := bytes.LastIndex(tail, []byte("startxref"))
	if i < 0 {
		return 0, false, errNoStartXRef
	}
	rest := tail[i+len("startxref"):]
	j := 0
	for j < len(rest) && isPDFWhitespace(rest[j]) {
		j++
	}
	k := j
	for k < len(rest) && k-j < 12 && rest[k] >= '0' && rest[k] <= '9' {
		k++
	}
	if k == j {
		return 0, false, errNoStartXRef
	}
	off, err := strconv.ParseInt(string(rest[j:k]), 10, 64)
	if err != nil || off <= 0 || off >= int64(len(raw)) {
		return 0, false, errNoStartXRef
	}

	at := raw[off:]
	if bytes.HasPrefix(at, []byte("xref")) {
		return off, false, nil
	}
	if looksLikeObjectHeader(at) {
		return off, true, nil
	}
	return 0, false, errNoStartXRef
}

// looksLikeObjectHeader reports whether b starts with "<int> <int> obj".
func looksLikeObjectHeader(b []byte) bool {
	i := 0
	for part := 0; part < 2; part++ {
		start := i
		for i < len(b) && i-start < 10 && b[i] >= '0' && b[i] <= '9' {
			i++
		}
		if i == start {
			return false
		}
		ws := i
		for i < len(b) && isPDFWhitespace(b[i]) {
			i++
		}
		if i == ws {
			return false
		}
	}
	return bytes.HasPrefix(b[i:], []byte("obj"))
}

// isPDFWhitespace is the PDF white-space set (ISO 32000-1, Table 1).
func isPDFWhitespace(c byte) bool {
	switch c {
	case 0x00, 0x09, 0x0A, 0x0C, 0x0D, 0x20:
		return true
	}
	return false
}
