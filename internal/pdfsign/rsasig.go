package pdfsign

// Our own RSASSA-PKCS1-v1_5 with SHA-256 (RFC 8017 §8.2 and §9.2).
//
// The assignment requires the signing and verification logic to be ours,
// so this file deliberately does not call rsa.SignPKCS1v15, VerifyPKCS1v15
// or SignPSS. The standard library still provides the key (internal/keypair,
// key generation is an allowed library use), SHA-256 (hashing), crypto/rand
// and math/big arithmetic. Tests cross-check our output against the
// standard library (D45, D46).

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"math/big"
)

// digestInfoSHA256 is the DER encoding of
//
//	DigestInfo ::= SEQUENCE {
//	    digestAlgorithm SEQUENCE { OID 2.16.840.1.101.3.4.2.1 (sha256), NULL },
//	    digest          OCTET STRING (32 bytes, appended after this prefix) }
//
// up to the digest itself. RFC 8017 §9.2, note 1, lists exactly these bytes.
// Hard-coding them, instead of encoding with encoding/asn1, means the
// verifier compares against one fixed byte string (no ASN.1 parsing during
// verification) and avoids the alternative "no NULL" encoding.
var digestInfoSHA256 = []byte{
	0x30, 0x31, // SEQUENCE, 49 bytes
	0x30, 0x0d, // SEQUENCE, 13 bytes (AlgorithmIdentifier)
	0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, // OID sha256
	0x05, 0x00, // NULL parameters
	0x04, 0x20, // OCTET STRING, 32 bytes
}

const (
	// minPadding is the shortest FF…FF run RFC 8017 allows (PS ≥ 8 bytes).
	minPadding = 8
	// minKeyBits is the smallest modulus we sign or verify with. Our own keys
	// are 3072 bits (D39); 2048 is the floor NIST SP 800-57 still accepts.
	minKeyBits = 2048
	// maxKeyBits bounds the work an untrusted key (the bonus format reads one
	// from a certificate) can cause during verification.
	maxKeyBits = 8192
)

var (
	errDigestSize = errors.New("pdfsign: digest must be 32 bytes (SHA-256)")
	errBadKey     = errors.New("pdfsign: RSA key not acceptable")
	// errSelfCheck means the signature we just computed did not verify. It is
	// never returned to users as a signature: a faulty RSA result can leak
	// the private key (Boneh, DeMillo and Lipton 1997), so it is discarded.
	errSelfCheck = errors.New("pdfsign: signature failed its own check")
)

// encodeEMSA returns EMSA-PKCS1-v1_5(digest) for a k-byte modulus:
//
//	EM = 0x00 ‖ 0x01 ‖ PS (0xFF repeated) ‖ 0x00 ‖ DigestInfo prefix ‖ digest
//
// The leading 0x00 makes EM numerically smaller than the modulus. 0x01
// marks a signature block. PS fills the block with a fixed value, so the
// encoding of a given digest is unique, which is what lets the verifier
// rebuild it and compare instead of parsing it (see verifyDigest).
func encodeEMSA(digest []byte, k int) ([]byte, error) {
	if len(digest) != sha256.Size {
		return nil, errDigestSize
	}
	tLen := len(digestInfoSHA256) + len(digest) // T = DigestInfo, 51 bytes
	if k < tLen+3+minPadding {
		return nil, fmt.Errorf("%w: modulus too short for the encoding", errBadKey)
	}
	em := make([]byte, k)
	em[0] = 0x00
	em[1] = 0x01
	psEnd := k - tLen - 1 // index of the 0x00 separator
	for i := 2; i < psEnd; i++ {
		em[i] = 0xFF
	}
	em[psEnd] = 0x00
	copy(em[psEnd+1:], digestInfoSHA256)
	copy(em[k-len(digest):], digest)
	return em, nil
}

// checkPublic rejects keys that would make a signature meaningless or
// verification too costly. e = 1 would make every message its own
// signature, and an even e is never a valid RSA exponent.
func checkPublic(pub *rsa.PublicKey) error {
	if pub == nil || pub.N == nil || pub.N.Sign() <= 0 {
		return fmt.Errorf("%w: missing modulus", errBadKey)
	}
	if bits := pub.N.BitLen(); bits < minKeyBits || bits > maxKeyBits {
		return fmt.Errorf("%w: %d-bit modulus", errBadKey, bits)
	}
	if pub.N.Bit(0) == 0 {
		return fmt.Errorf("%w: even modulus", errBadKey)
	}
	if pub.E < 3 || pub.E%2 == 0 {
		return fmt.Errorf("%w: public exponent %d", errBadKey, pub.E)
	}
	return nil
}

// signDigest signs a SHA-256 digest with priv: s = EM^d mod n.
//
// Steps, and why:
//  1. Encode the digest (encodeEMSA) and turn it into a number m (OS2IP).
//  2. Blind it: pick a random r coprime to n, compute m·r^e mod n. The slow
//     exponentiation then runs on a random-looking number, so its timing and
//     power use don't depend on m. math/big is not constant-time, and
//     blinding is the standard mitigation (Kocher 1996; it is what
//     crypto/rsa did before it switched to constant-time arithmetic).
//  3. s' = (m·r^e)^d = m^d·r mod n, then unblind: s = s'·r⁻¹ mod n.
//  4. Verify s with the public key before returning it, so a faulty
//     result (a bug, a bit flip) is never handed out (errSelfCheck).
//
// We use the plain exponent d rather than the faster CRT form: it is less
// code to defend, and CRT is exactly where a single fault leaks a prime
// factor. Signing is rare (one per user action), so speed doesn't matter.
func signDigest(priv *rsa.PrivateKey, digest []byte) ([]byte, error) {
	if priv == nil || priv.D == nil || priv.D.Sign() <= 0 {
		return nil, fmt.Errorf("%w: missing private exponent", errBadKey)
	}
	pub := &priv.PublicKey
	if err := checkPublic(pub); err != nil {
		return nil, err
	}
	n := pub.N
	k := (n.BitLen() + 7) / 8

	em, err := encodeEMSA(digest, k)
	if err != nil {
		return nil, err
	}
	defer clear(em)
	m := new(big.Int).SetBytes(em) // OS2IP
	if m.Cmp(n) >= 0 {
		// Can't happen: EM starts with 0x00 0x01, so m < 2^(8k-15) < n.
		return nil, fmt.Errorf("%w: message representative out of range", errBadKey)
	}

	r, rInv, err := blindingFactor(n)
	if err != nil {
		return nil, err
	}
	e := big.NewInt(int64(pub.E))
	blinded := new(big.Int).Exp(r, e, n) // r^e
	blinded.Mul(blinded, m).Mod(blinded, n)

	s := new(big.Int).Exp(blinded, priv.D, n) // (m·r^e)^d = m^d · r
	s.Mul(s, rInv).Mod(s, n)                  // remove r

	sig := s.FillBytes(make([]byte, k)) // I2OSP to exactly k bytes
	// Best effort: big.Int gives no way to wipe its memory (D13).
	m.SetInt64(0)
	blinded.SetInt64(0)
	r.SetInt64(0)
	rInv.SetInt64(0)

	if err := verifyDigest(pub, digest, sig); err != nil {
		return nil, errSelfCheck
	}
	return sig, nil
}

// blindingFactor returns a random r in [1, n) that has an inverse mod n,
// together with that inverse. For a real RSA modulus a random r is
// non-invertible with negligible probability, but we check anyway.
func blindingFactor(n *big.Int) (r, rInv *big.Int, err error) {
	for range 32 {
		r, err = rand.Int(rand.Reader, n)
		if err != nil {
			return nil, nil, fmt.Errorf("pdfsign: blinding: %w", err)
		}
		if r.Sign() == 0 {
			continue
		}
		if rInv = new(big.Int).ModInverse(r, n); rInv != nil {
			return r, rInv, nil
		}
	}
	return nil, nil, fmt.Errorf("%w: no invertible blinding factor", errBadKey)
}

// verifyDigest checks that sig is a valid signature of digest under pub:
//
//  1. sig must be exactly k bytes and, as a number s, satisfy 0 < s < n.
//     This rejects truncated, padded and non-canonical (s + n) signatures.
//  2. m = s^e mod n, written back as k bytes (I2OSP).
//  3. Build the encoding we EXPECT for digest (encodeEMSA) and compare all k
//     bytes with subtle.ConstantTimeCompare.
//
// Step 3 is the important one. We never parse the recovered block (skip
// 0xFF bytes, find 0x00, read the ASN.1 that follows). Verifiers that parse
// it can accept forgeries with garbage hidden after the hash (Bleichenbacher
// 2006, practical with e = 3). Comparing against the one correct encoding
// leaves nowhere to hide garbage. The constant-time compare doesn't reveal
// how many leading bytes matched.
func verifyDigest(pub *rsa.PublicKey, digest, sig []byte) error {
	if err := checkPublic(pub); err != nil {
		return err
	}
	if len(digest) != sha256.Size {
		return errDigestSize
	}
	n := pub.N
	k := (n.BitLen() + 7) / 8
	if len(sig) != k {
		return fmt.Errorf("%w: signature is %d bytes, want %d", ErrBadSignature, len(sig), k)
	}
	s := new(big.Int).SetBytes(sig)
	if s.Sign() == 0 || s.Cmp(n) >= 0 {
		return fmt.Errorf("%w: signature value out of range", ErrBadSignature)
	}

	m := new(big.Int).Exp(s, big.NewInt(int64(pub.E)), n)
	got := m.FillBytes(make([]byte, k)) // m < n, so it fits in k bytes

	want, err := encodeEMSA(digest, k)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrBadSignature
	}
	return nil
}

// rsaSigner adapts a private key to crypto.Signer using OUR signDigest, so
// that code which takes a crypto.Signer (x509.CreateCertificate, for the
// self-signed certificate of the Adobe-compatible format) signs with our
// logic rather than the standard library's.
type rsaSigner struct {
	priv *rsa.PrivateKey
}

// Public returns the signer's public key.
func (s rsaSigner) Public() crypto.PublicKey { return &s.priv.PublicKey }

// Sign signs a SHA-256 digest computed by the caller. Only PKCS #1 v1.5 with
// SHA-256 is supported: PSS options and other hashes are rejected rather
// than silently signed the wrong way. The random source is unused because
// v1.5 signatures are deterministic (blinding reads crypto/rand itself).
func (s rsaSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if _, ok := opts.(*rsa.PSSOptions); ok {
		return nil, errors.New("pdfsign: RSA-PSS is not supported")
	}
	if opts == nil || opts.HashFunc() != crypto.SHA256 {
		return nil, errors.New("pdfsign: only SHA-256 is supported")
	}
	return signDigest(s.priv, digest)
}
