package pdfsign

// The in-app signature format (D49). A signature dictionary looks like:
//
//	<</Type /Sig /Filter /SecureStore /SubFilter /SecureStore.rsa_sha256.v1
//	  /ByteRange [0 a b c]          the signed bytes: [0,a) and [b,b+c)
//	  /Contents <…hex…>             the hole: raw RSA signature, zero-padded
//	  /M (D:20261128093000Z)        claimed signing time
//	  /Name <FEFF…>                 signer's username (UTF-16BE text string)
//	  /SecureStore.Signer (…)       signer's user ID, 24 hex digits
//	  /SecureStore.KeyFP <…>        SHA-256 fingerprint of the signing key
//	>>
//
// Everything except /Contents lies inside the signed bytes, so the signer's
// identity, the key fingerprint and the time can't be changed without
// breaking the signature. The signature is over SHA-256 of the two ranges.

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
)

const (
	filterInApp    = "SecureStore"
	subFilterInApp = "SecureStore.rsa_sha256.v1"
	subFilterCMS   = "adbe.pkcs7.detached"
	keySigner      = "SecureStore.Signer"
	keyKeyFP       = "SecureStore.KeyFP"

	// inAppContentsSize is the space reserved in /Contents, in bytes. An
	// RSA-3072 signature is 384 bytes; 512 leaves room for RSA-4096.
	inAppContentsSize = 512

	// byteRangeWidth is the fixed width of the /ByteRange array text,
	// "[0 " + three 10-digit numbers + 2 spaces + "]". The real values are
	// written into it after layout, padded with spaces, so no offset moves.
	byteRangeWidth = 36

	// maxSignatures bounds the signatures we add to or check in one PDF.
	maxSignatures = 16

	// maxNameRunes bounds the signer name we write and display.
	maxNameRunes = 64

	// pdfDateLayout is a PDF date (ISO 32000-1 §7.9.4) in UTC.
	pdfDateLayout = "D:20060102150405Z"
)

// keyFingerprint is SHA-256 of the PKIX DER public key, the same value
// keypair stores and shows (D42).
func keyFingerprint(pub *rsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	fp := sha256.Sum256(der)
	return fp[:], nil
}

// encodeTextString encodes s as a PDF text string in UTF-16BE with a byte
// order mark, written as a hex string. That is valid for any Unicode name
// and needs no escaping.
func encodeTextString(s string) types.HexLiteral {
	units := utf16.Encode([]rune(s))
	b := make([]byte, 2, 2+2*len(units))
	b[0], b[1] = 0xFE, 0xFF
	for _, u := range units {
		b = append(b, byte(u>>8), byte(u))
	}
	return types.HexLiteral(strings.ToUpper(hex.EncodeToString(b)))
}

// cleanName prepares a name for writing or display: no control or invalid
// characters, at most maxNameRunes runes. The name is a label only.
func cleanName(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == utf8.RuneError || unicode.Is(unicode.Cf, r) {
			return -1 // also drops bidi overrides that could disguise a name
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > maxNameRunes {
		s = string(r[:maxNameRunes])
	}
	return s
}

// textString reads a PDF text string (literal or hex, PDFDocEncoding or
// UTF-16BE), or "" if o is not one.
func textString(o types.Object) string {
	s, err := types.StringOrHexLiteral(o)
	if err != nil || s == nil {
		return ""
	}
	return *s
}

// rawString returns the bytes of a literal or hex string, or nil.
func rawString(o types.Object) []byte {
	switch v := o.(type) {
	case types.HexLiteral:
		b, err := v.Bytes()
		if err != nil {
			return nil
		}
		return b
	case types.StringLiteral:
		b, err := types.Unescape(v.Value())
		if err != nil {
			return nil
		}
		return b
	}
	return nil
}

// parsePDFDate reads a /M date. A missing or malformed date is zero: the
// date is only the signer's claim and never affects validity.
func parsePDFDate(o types.Object) time.Time {
	s := textString(o)
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(pdfDateLayout, s); err == nil {
		return t
	}
	if t, ok := types.DateTime(s, true); ok {
		return t.UTC()
	}
	return time.Time{}
}
