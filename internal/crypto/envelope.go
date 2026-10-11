package crypto

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"time"
)

const (
	// macKeySize is the HMAC-SHA256 key length: the hash output size, which
	// RFC 2104 recommends as the minimum.
	macKeySize = 32
	// tagSize is the length of Meta.Tag (a full, untruncated HMAC-SHA256).
	tagSize = sha256.Size
	// chunkSize is how much is read, encrypted and written at a time, so a
	// file of any size uses a fixed amount of memory.
	chunkSize = 32 << 10
	// macLabel starts every MAC input. It names this format, so a tag made
	// for something else (or a future format version) can never verify here.
	macLabel = "securestore/v1"
)

// Envelope is the real Encryptor. It implements envelope encryption: every
// call generates fresh random data and MAC keys, uses them once, and stores
// them wrapped under the master key (KEK) in Meta.
//
// An Envelope is immutable after NewEnvelope and safe for concurrent use.
type Envelope struct {
	master []byte
}

var _ Encryptor = (*Envelope)(nil)

// NewEnvelope returns an Envelope that wraps keys under master, which must be
// MasterKeySize bytes. The key is copied, so the caller may clear its slice.
func NewEnvelope(master []byte) (*Envelope, error) {
	if len(master) != MasterKeySize {
		return nil, fmt.Errorf("crypto: master key must be %d bytes, got %d", MasterKeySize, len(master))
	}
	return &Envelope{master: bytes.Clone(master)}, nil
}

// Encrypt implements Encryptor.
func (e *Envelope) Encrypt(ctx context.Context, alg Algorithm, dst io.Writer, src io.Reader) (Meta, error) {
	return e.seal(ClockFrom(ctx), alg, dst, src)
}

// Decrypt implements Encryptor.
func (e *Envelope) Decrypt(ctx context.Context, alg Algorithm, meta Meta, dst io.Writer, src io.ReadSeeker) error {
	return e.open(ClockFrom(ctx), alg, meta, dst, src)
}

// EncryptField implements Encryptor. It runs the same code as Encrypt on an
// in-memory value, so files and fields are protected identically.
func (e *Envelope) EncryptField(alg Algorithm, plaintext []byte) ([]byte, Meta, error) {
	var ct bytes.Buffer
	ct.Grow(len(plaintext)) // CTR and RC4 ciphertext is exactly as long as the plaintext.
	meta, err := e.seal(nil, alg, &ct, bytes.NewReader(plaintext))
	if err != nil {
		return nil, Meta{}, err
	}
	return ct.Bytes(), meta, nil
}

// DecryptField implements Encryptor.
func (e *Envelope) DecryptField(alg Algorithm, meta Meta, ciphertext []byte) ([]byte, error) {
	var pt bytes.Buffer
	pt.Grow(len(ciphertext))
	if err := e.open(nil, alg, meta, &pt, bytes.NewReader(ciphertext)); err != nil {
		return nil, err
	}
	return pt.Bytes(), nil
}

// seal encrypts src into dst: generate keys, encrypt, then MAC the result.
func (e *Envelope) seal(clock *Clock, alg Algorithm, dst io.Writer, src io.Reader) (Meta, error) {
	if !alg.Valid() {
		return Meta{}, fmt.Errorf("%w: %q", ErrUnknownAlgorithm, alg)
	}

	// 1. Fresh randomness for every call. This is what makes CTR and RC4
	// safe here: a keystream is never used twice, and the same plaintext
	// encrypted twice gives unrelated ciphertexts.
	dek, err := randomBytes(dekSize(alg))
	if err != nil {
		return Meta{}, fmt.Errorf("encrypt %s: %w", alg, err)
	}
	defer clear(dek)
	macKey, err := randomBytes(macKeySize)
	if err != nil {
		return Meta{}, fmt.Errorf("encrypt %s: %w", alg, err)
	}
	defer clear(macKey)
	iv, err := randomBytes(alg.IVSize()) // nil for RC4
	if err != nil {
		return Meta{}, fmt.Errorf("encrypt %s: %w", alg, err)
	}

	// 2. Wrap both keys under the master key so they can be stored.
	wrappedDEK, err := WrapKey(e.master, dek)
	if err != nil {
		return Meta{}, fmt.Errorf("encrypt %s: %w", alg, err)
	}
	wrappedMACKey, err := WrapKey(e.master, macKey)
	if err != nil {
		return Meta{}, fmt.Errorf("encrypt %s: %w", alg, err)
	}
	meta := Meta{Algorithm: alg, IV: iv, WrappedDEK: wrappedDEK, WrappedMACKey: wrappedMACKey}

	// 3. Encrypt-then-MAC, one chunk at a time.
	start := time.Now()
	stream, err := newStream(alg, dek, iv)
	if err != nil {
		return Meta{}, fmt.Errorf("encrypt %s: %w", alg, err)
	}
	mac := newMAC(macKey, meta)
	clock.Add(time.Since(start))

	buf := make([]byte, chunkSize)
	defer clear(buf)
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			start := time.Now()
			stream.XORKeyStream(chunk, chunk) // in place: chunk now holds ciphertext
			mac.Write(chunk)                  // MAC the ciphertext, not the plaintext
			clock.Add(time.Since(start))
			if _, werr := dst.Write(chunk); werr != nil {
				return Meta{}, fmt.Errorf("encrypt %s: write: %w", alg, werr)
			}
		}
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			return Meta{}, fmt.Errorf("encrypt %s: read: %w", alg, rerr)
		}
	}

	start = time.Now()
	meta.Tag = mac.Sum(nil)
	clock.Add(time.Since(start))
	return meta, nil
}

// open verifies src against meta.Tag and only then decrypts it into dst.
func (e *Envelope) open(clock *Clock, alg Algorithm, meta Meta, dst io.Writer, src io.ReadSeeker) error {
	if !alg.Valid() {
		return fmt.Errorf("%w: %q", ErrUnknownAlgorithm, alg)
	}
	if meta.Algorithm != alg {
		return fmt.Errorf("decrypt: meta is for %q, not %q", meta.Algorithm, alg)
	}
	// Malformed metadata is treated like tampering: it can only come from a
	// bug or from someone editing the database.
	if len(meta.IV) != alg.IVSize() {
		return fmt.Errorf("decrypt %s: IV must be %d bytes, got %d: %w", alg, alg.IVSize(), len(meta.IV), ErrAuthentication)
	}
	if len(meta.Tag) != tagSize {
		return fmt.Errorf("decrypt %s: tag must be %d bytes, got %d: %w", alg, tagSize, len(meta.Tag), ErrAuthentication)
	}

	dek, err := UnwrapKey(e.master, meta.WrappedDEK)
	if err != nil {
		return fmt.Errorf("decrypt %s: data key: %w", alg, err)
	}
	defer clear(dek)
	macKey, err := UnwrapKey(e.master, meta.WrappedMACKey)
	if err != nil {
		return fmt.Errorf("decrypt %s: mac key: %w", alg, err)
	}
	defer clear(macKey)
	if len(dek) != dekSize(alg) || len(macKey) != macKeySize {
		return fmt.Errorf("decrypt %s: unwrapped key has wrong length: %w", alg, ErrAuthentication)
	}

	buf := make([]byte, chunkSize)
	defer clear(buf)

	// Pass 1: verify. Read the whole ciphertext and check the tag before a
	// single plaintext byte is produced. hmac.Equal takes the same time
	// wherever the first difference is, so timing reveals nothing about the
	// correct tag.
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("decrypt %s: seek: %w", alg, err)
	}
	start := time.Now()
	mac := newMAC(macKey, meta)
	clock.Add(time.Since(start))
	verified, err := macAll(clock, mac, src, buf)
	if err != nil {
		return fmt.Errorf("decrypt %s: verify: %w", alg, err)
	}
	if !hmac.Equal(mac.Sum(nil), meta.Tag) {
		return fmt.Errorf("decrypt %s: %w", alg, ErrAuthentication)
	}

	// Pass 2: decrypt. The keystream is regenerated from the same key and
	// IV; XORing it into the ciphertext gives back the plaintext.
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("decrypt %s: seek: %w", alg, err)
	}
	start = time.Now()
	stream, err := newStream(alg, dek, meta.IV)
	if err != nil {
		return fmt.Errorf("decrypt %s: %w", alg, err)
	}
	// The MAC is computed again in this pass. If the stored object changed
	// between the two passes, this is how we notice.
	mac = newMAC(macKey, meta)
	clock.Add(time.Since(start))

	var decrypted int64
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			start := time.Now()
			mac.Write(chunk)                  // MAC the ciphertext before it is overwritten
			stream.XORKeyStream(chunk, chunk) // in place: chunk now holds plaintext
			clock.Add(time.Since(start))
			decrypted += int64(n)
			if _, werr := dst.Write(chunk); werr != nil {
				return fmt.Errorf("decrypt %s: write: %w", alg, werr)
			}
		}
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			return fmt.Errorf("decrypt %s: read: %w", alg, rerr)
		}
	}
	if decrypted != verified || !hmac.Equal(mac.Sum(nil), meta.Tag) {
		return fmt.Errorf("decrypt %s: ciphertext changed during decryption: %w", alg, ErrAuthentication)
	}
	return nil
}

// macAll feeds all of src into mac and returns the number of bytes read.
func macAll(clock *Clock, mac hash.Hash, src io.Reader, buf []byte) (int64, error) {
	var total int64
	for {
		n, err := src.Read(buf)
		if n > 0 {
			start := time.Now()
			mac.Write(buf[:n])
			clock.Add(time.Since(start))
			total += int64(n)
		}
		if errors.Is(err, io.EOF) {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
}

// newMAC returns an HMAC-SHA256 that has already absorbed the header for
// meta. The header binds every Meta field except the tag itself (algorithm,
// IV and both wrapped keys) to the ciphertext, so none of them can be swapped
// or edited without the tag failing.
func newMAC(macKey []byte, meta Meta) hash.Hash {
	mac := hmac.New(sha256.New, macKey)
	mac.Write(macHeader(meta))
	return mac
}

// macHeader encodes the header as a sequence of length-prefixed fields. The
// length prefixes make the encoding unambiguous: without them, moving a byte
// from the end of one field to the start of the next would give the same
// bytes and so the same tag.
func macHeader(meta Meta) []byte {
	fields := [][]byte{
		[]byte(macLabel),
		[]byte(meta.Algorithm),
		meta.IV,
		meta.WrappedDEK,
		meta.WrappedMACKey,
	}
	var h []byte
	for _, f := range fields {
		if len(f) > math.MaxUint32 {
			// Unreachable: every field is at most 60 bytes. The check makes
			// the uint32 conversion below provably safe.
			panic("crypto: MAC header field too long")
		}
		h = binary.BigEndian.AppendUint32(h, uint32(len(f)))
		h = append(h, f...)
	}
	return h
}

// randomBytes returns n bytes from crypto/rand, or nil when n is 0.
func randomBytes(n int) ([]byte, error) {
	if n == 0 {
		return nil, nil
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("random: %w", err)
	}
	return b, nil
}
