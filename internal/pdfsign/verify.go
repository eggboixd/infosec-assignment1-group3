package pdfsign

// Verifying the signatures in a PDF (D50). For each signature dictionary
// found through the AcroForm, in this order:
//
//  1. /ByteRange is exactly four integers [0 a b c] with 0 < a < b and
//     b + c <= file size, so the signed bytes start at the beginning of the
//     file and the only unsigned part inside them is [a, b).
//  2. The hole [a, b) is exactly this dictionary's /Contents hex string: it
//     starts with '<', ends with '>', holds only hex digits, decodes to the
//     same bytes pdfcpu read as /Contents, and "/Contents" is the token right
//     before it in the dictionary, which itself starts in the signed bytes.
//     So nothing but the signature can hide in the hole (the "signature
//     wrapping" attacks of Mladenov et al. 2019 move the hole instead).
//  3. The format is ours (FormatInApp); others get ErrUnsupportedFormat.
//  4. The signer named in the PDF has a registered signing key, and its
//     fingerprint is the one in the PDF.
//  5. Our verifyDigest over SHA-256 of the two ranges, with that key.
//
// Then, for the whole document: does the newest signature reach the end of
// the file? Bytes after it are reported as StatusModified, because an
// appended update can change what a viewer shows while the old signature
// still verifies (the incremental saving attack).

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"

	"github.com/eggboixd/infosec-assignment1-group3/internal/keypair"
)

// keyDirectory looks up a user's registered signing key. *keypair.Service
// satisfies it (it checks the key's MAC first, D42).
type keyDirectory interface {
	PublicKey(ctx context.Context, userID bson.ObjectID, p keypair.Purpose) (*rsa.PublicKey, error)
}

// verifyPDF verifies every signature in raw. Problems with a signature are
// in the Report; an error means the file couldn't be checked at all.
func verifyPDF(ctx context.Context, raw []byte, keys keyDirectory) (*Report, error) {
	doc, err := readPDF(ctx, raw)
	if err != nil {
		return nil, err
	}
	fields, err := doc.signatureFields()
	if err != nil {
		return nil, err
	}
	if len(fields) > maxSignatures {
		return nil, ErrTooManySignatures
	}

	results := make([]SignatureResult, 0, len(fields))
	for _, f := range fields {
		res, err := verifyOne(ctx, doc, f, keys)
		if err != nil {
			return nil, err
		}
		results = append(results, res)
	}
	// Oldest first: a later revision ends later in the file. Signatures
	// without a usable ByteRange (RevisionEnd 0) come first.
	sort.SliceStable(results, func(i, j int) bool { return results[i].RevisionEnd < results[j].RevisionEnd })

	rep := &Report{Signatures: results, FileSize: int64(len(raw))}
	var newestEnd int64
	for i := range results {
		results[i].Index = i
		newestEnd = max(newestEnd, results[i].RevisionEnd)
		// A later valid signature whose first range reaches past this
		// revision's end signed everything this one did, and more.
		for j := i + 1; j < len(results); j++ {
			if results[j].Valid && results[i].RevisionEnd > 0 && results[j].ByteRange[1] >= results[i].RevisionEnd {
				results[i].CoveredByLater = true
			}
		}
	}

	switch {
	case len(results) == 0:
		rep.Status = StatusUnsigned
		return rep, nil
	case newestEnd > 0:
		rep.AppendedBytes = int64(len(raw)) - newestEnd
	}
	rep.Status = StatusValid
	for _, r := range results {
		if !r.Valid {
			rep.Status = StatusInvalid
			return rep, nil
		}
	}
	if rep.AppendedBytes > 0 {
		rep.Status = StatusModified
	}
	return rep, nil
}

// verifyOne checks one signature. It returns an error only when the key
// directory fails for a reason that says nothing about the PDF (for
// example, MongoDB is down).
func verifyOne(ctx context.Context, doc *pdfDoc, f sigField, keys keyDirectory) (SignatureResult, error) {
	var res SignatureResult
	d := f.dict
	if d == nil {
		res.Problem = ErrMalformedSignature
		return res, nil
	}

	// 1–2. Byte range and hole.
	br, contents, err := checkByteRange(doc, f)
	if br[1] > 0 {
		res.ByteRange = br
		res.RevisionEnd = br[2] + br[3]
		res.CoversWholeFile = res.RevisionEnd == int64(len(doc.raw))
	}
	if err != nil {
		res.Problem = err
		return res, nil
	}

	// 3. Format.
	filter, _ := d["Filter"].(types.Name)
	subFilter, _ := d["SubFilter"].(types.Name)
	switch {
	case filter == filterInApp && subFilter == subFilterInApp:
		res.Format = FormatInApp
	case subFilter == subFilterCMS:
		res.Format = FormatCMS
		res.Problem = ErrUnsupportedFormat
		return res, nil
	default:
		res.Problem = ErrUnsupportedFormat
		return res, nil
	}

	// 4. Signer and key.
	res.SignerName = cleanName(textString(d["Name"]))
	res.SignedAt = parsePDFDate(d["M"])
	fp := rawString(d[keyKeyFP])
	if len(fp) != 32 {
		res.Problem = ErrMalformedSignature
		return res, nil
	}
	res.Fingerprint = keypair.FormatFingerprint(fp)
	signerID, err := bson.ObjectIDFromHex(textString(d[keySigner]))
	if err != nil {
		res.Problem = ErrUnknownSigner
		return res, nil
	}
	res.SignerID = signerID

	pub, err := keys.PublicKey(ctx, signerID, keypair.Signing)
	switch {
	case errors.Is(err, keypair.ErrNoKeys):
		res.Problem = ErrUnknownSigner
		return res, nil
	case err != nil:
		return res, fmt.Errorf("pdfsign: signer's key: %w", err)
	}
	registered, err := keyFingerprint(pub)
	if err != nil {
		return res, fmt.Errorf("pdfsign: signer's key: %w", err)
	}
	if !bytes.Equal(registered, fp) {
		res.Problem = ErrKeyMismatch
		return res, nil
	}
	res.KeyMatches = true

	// 5. The signature itself: k bytes, then only zero padding.
	k := (pub.N.BitLen() + 7) / 8
	if len(contents) < k || !allZero(contents[k:]) {
		res.Problem = ErrMalformedSignature
		return res, nil
	}
	if err := verifyDigest(pub, signedDigest(doc.raw, br), contents[:k]); err != nil {
		if errors.Is(err, ErrBadSignature) {
			res.Problem = ErrBadSignature
		} else {
			res.Problem = ErrKeyMismatch // the registered key itself is unusable
		}
		return res, nil
	}
	res.Valid = true
	return res, nil
}

// checkByteRange validates f's /ByteRange against the file and returns it
// with the decoded /Contents. br is returned (with br[1] > 0) whenever the
// four numbers are in range, even if the hole check then fails, so the
// report can still show what the signature claimed to cover.
func checkByteRange(doc *pdfDoc, f sigField) (br [4]int64, contents []byte, err error) {
	raw := doc.raw
	size := int64(len(raw))
	arr, ok := f.dict["ByteRange"].(types.Array)
	if !ok || len(arr) != 4 {
		return br, nil, ErrByteRange
	}
	for i, o := range arr {
		n, ok := o.(types.Integer)
		if !ok || n < 0 {
			return [4]int64{}, nil, ErrByteRange
		}
		br[i] = int64(n)
	}
	// Each bound is checked on its own so that huge values can't overflow.
	if br[0] != 0 || br[1] <= 0 || br[2] <= br[1] || br[2] > size || br[3] > size-br[2] {
		return [4]int64{}, nil, ErrByteRange
	}

	hole := raw[br[1]:br[2]]
	if len(hole) < 2 || hole[0] != '<' || hole[len(hole)-1] != '>' || len(hole)%2 != 0 {
		return br, nil, ErrByteRange
	}
	contents = make([]byte, (len(hole)-2)/2)
	if _, err := hex.Decode(contents, hole[1:len(hole)-1]); err != nil {
		return br, nil, ErrByteRange
	}
	parsed, ok := f.dict["Contents"].(types.HexLiteral)
	if !ok {
		return br, nil, ErrByteRange
	}
	parsedBytes, err := parsed.Bytes()
	if err != nil || !bytes.Equal(parsedBytes, contents) {
		return br, nil, ErrByteRange
	}

	// The dictionary starts inside the first signed range, and the hole is
	// the value of its /Contents key.
	off, ok := doc.objectOffset(f.ref.ObjectNumber.Value())
	if !ok || off >= br[1] {
		return br, nil, ErrByteRange
	}
	before := bytes.TrimRight(raw[off:br[1]], "\x00\t\n\f\r ")
	if !bytes.HasSuffix(before, []byte("/Contents")) {
		return br, nil, ErrByteRange
	}
	return br, contents, nil
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
