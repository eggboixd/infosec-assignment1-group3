# Design decisions

Every non-obvious choice, with the alternatives we considered and why we picked what we did. This is the source for the
"justify your decisions" part of the report. Code comments point here by number (for example `D15`).

Format: **Decision** · Alternatives · Why · Trade-offs (where relevant).

---

## Cryptography (`feature/crypto-core`)

### D1. Every item is encrypted three times, once per algorithm

- **Decision:** each file and each private-data field is stored as three independent ciphertexts: one AES, one DES, one
  RC4. Each copy has its own keys and IV. The user picks which copy to decrypt on download.
- **Alternatives:**
  - *Cascade* (AES → DES → RC4 over the same bytes).
  - *User chooses one algorithm* at upload.
- **Why:** the assignment asks us to encrypt with AES, DES and RC4 and then *compare* them (running time, resulting
  ciphertext). Three independent copies of identical data make that comparison direct and fair. A cascade would only
  let us measure the sum of all three.
- **Trade-offs:** 3× storage and 3× encryption work per upload. If the TA wants a cascade or a single choice, only the
  `files` and `profile` services change; `internal/crypto` stays as it is.

### D2. Envelope encryption under one deployment master key

- **Decision:**
  - A 32-byte master key (KEK) is read from the `MASTER_KEY` environment variable.
  - Every encryption gets a fresh random data key (DEK) and MAC key.
  - Both keys are wrapped (encrypted) under the KEK and stored next to the ciphertext in `Meta`.
- **Alternatives:**
  1. *Password-derived keys:* derive each user's key from their login password (PBKDF2 or Argon2) and keep it only in
     the session.
  2. *Encrypt directly with the master key:* no per-object keys, only a per-object IV.
  3. *A KMS/HSM* (Vault, cloud KMS).
- **Why:**
  - *Over password-derived keys:*
    - a password reset would make all of that user's data unreadable, because there would be no way to recover the key
    - background work (benchmark runs, an admin export) would be impossible without the user present
    - a server restart would log everyone out *and* lock their data until they log in again
    - changing the password would mean re-encrypting every file
  - *Over using the master key directly:* RC4 and CTR break completely if a keystream is ever reused. With a fresh
    random DEK per object, a repeated key would need a 2^-256 accident. The master key also never touches user data
    itself; it only protects small keys. Rotating it later would mean re-wrapping a few dozen bytes per object, not
    re-encrypting files.
  - *Over a KMS:* not available in a student Docker Compose setup, and it adds infrastructure that isn't the point
    of the assignment.
- **Trade-offs:**
  - Anyone who has both the database/MinIO contents *and* `MASTER_KEY` can read everything. Protecting the
    environment of the `app` container is therefore critical.
  - With password-derived keys, a server compromise would only expose the data of users who log in while the
    attacker is present.
  - Stealing the database or bucket alone (backups, a leaked volume, a MinIO misconfiguration) exposes nothing,
    because the KEK isn't stored there.

### D3. CTR mode for AES and DES

- **Decision:** AES-256 and DES both run in counter (CTR) mode via `cipher.NewCTR`.
- **Alternatives:**
  - *ECB:* forbidden by the assignment, and identical plaintext blocks give identical ciphertext blocks.
  - *CBC:* allowed, and used by the TA's lab demo.
  - *CFB/OFB:* allowed by the assignment, but `cipher.NewCFB*` and `cipher.NewOFB` are deprecated since Go 1.24.
  - *GCM:* only defined for 128-bit block ciphers, so it couldn't be used for DES or RC4.
- **Why CTR satisfies "non-ECB":** CTR never puts the data through the block cipher. It encrypts a counter
  (IV, IV+1, IV+2, …) and XORs the result (the keystream) with the data. Every block position uses a different counter
  value, so identical plaintext blocks give different ciphertext. `TestEnvelopeSamePlaintextDiffers` checks this.
- **Why CTR over CBC:**
  1. No padding, so there are no padding bugs and no padding-oracle attacks, and 0-byte or odd-sized files need no
     special case.
  2. It turns AES and DES into stream ciphers. All three algorithms then share one streaming code path
     (`cipher.Stream`), so large videos never need to be in memory.
  3. All three algorithms produce ciphertext exactly as long as the plaintext, which keeps the size comparison fair.
- **Trade-offs:** CTR, like RC4, is catastrophic if a (key, IV) pair is reused: the XOR of two ciphertexts is the XOR
  of the two plaintexts. D2 and D6 make reuse practically impossible. CTR also provides no integrity on its own (a
  flipped ciphertext bit flips the same plaintext bit), which is why D7 adds a MAC.

### D4. Key sizes

| Algorithm | Key | Reason |
|---|---|---|
| AES | 256 bits | The largest AES key size; costs only ~40% more rounds than AES-128 and has the largest security margin. |
| DES | 64 bits (56 effective) | DES has only one key size. The 8 parity bits are ignored. We did **not** use 3DES: the assignment says DES, and 3DES would distort the comparison. |
| RC4 | 256 bits | RC4 accepts 8–2048-bit keys. 256 bits matches AES and rules out brute force; RC4's weaknesses are statistical, not key length. |
| HMAC | 256 bits | Equal to the SHA-256 output, as RFC 2104 recommends. |

### D5. RC4 is used as specified, with no keystream discard

- **Decision:** plain RC4 with a fresh random 256-bit key per object. We do not drop the first N keystream bytes.
- **Alternatives:**
  - *RC4-drop[N]* (discard the first 768–3072 bytes, as in RFC 4345).
  - *Not using RC4 at all.*
- **Why:**
  - The assignment requires RC4, and the comparison should measure RC4 as it's actually defined.
  - The famous practical attack (Fluhrer–Mantin–Shamir, which broke WEP) needs many *related* keys built as
    IV ‖ key. Our keys are independent random values, so it doesn't apply.
  - With no discard, our implementation also matches the RFC 6229 test vectors from offset 0.
- **Trade-offs:** RC4's keystream has known biases (for example, the second byte is biased towards 0). They leak
  information only when the same plaintext is encrypted many times under different keys. RFC 7465 prohibits RC4 in
  TLS for this reason. We use it only because the assignment requires it, and the report should say it's unsuitable
  for real systems.

### D6. A random IV and DEK per encryption, generated with `crypto/rand`

- **Decision:** every call to `Encrypt`/`EncryptField` draws a new DEK, MAC key and IV from `crypto/rand`. This
  includes re-uploads of the same file.
- **Alternatives:**
  - A counter-based IV stored in the database.
  - Deriving the IV from the content (deterministic encryption).
- **Why:**
  - A random IV needs no shared state, so it's safe across concurrent uploads and restarts.
  - Deterministic IVs would reveal when two users upload the same file.
  - Because every object also has its own key, IV uniqueness only matters *within* one object.
- **DES block-size note (Sweet32):** a 64-bit block cipher's keystream starts to risk repeating after about 2^32
  blocks (32 GiB) under one key. Our limit is per key, so per object. Uploads are at most `MAX_BODY_BYTES` = 2 GiB =
  2^28 DES blocks, far below the bound.

### D7. Encrypt-then-MAC with HMAC-SHA256 and a separate MAC key

- **Decision:** after encrypting, compute HMAC-SHA256 over the ciphertext with a second, independent random key.
  Store the full 32-byte tag. Compare tags with `hmac.Equal`.
- **Alternatives:**
  - *No integrity:* CTR and RC4 are malleable, so flipping a ciphertext bit flips the same plaintext bit, undetected.
  - *MAC-then-encrypt* or *encrypt-and-MAC:* both are known to be fragile; encrypt-then-MAC is the generically secure
    composition.
  - *An AEAD such as AES-GCM:* only for AES, so it couldn't protect the DES and RC4 copies in the same way.
  - *Reusing the DEK as the MAC key:* using one key for two different algorithms has no security proof.
- **Why:**
  - All three algorithms get identical integrity protection.
  - Tampering is detected *before* decryption.
  - `hmac.Equal` takes the same time no matter where the first difference is, so timing leaks nothing about the
    correct tag.

### D8. The MAC also covers the metadata (algorithm, IV, wrapped keys)

- **Decision:** the HMAC input is a header followed by the ciphertext. The header holds the length-prefixed fields
  `"securestore/v1"`, algorithm, IV, wrapped DEK and wrapped MAC key. Each length is 4 bytes, big-endian.
- **Alternative:** MAC over the ciphertext only, as the scaffold's first description said.
- **Why:** with a ciphertext-only MAC, someone who can edit MongoDB could put a *different* wrapped DEK, or a changed
  IV, into `Meta`. The tag would still verify, and the user would silently receive garbage instead of an error.
  Covering every `Meta` field except the tag closes that hole; `TestEnvelopeDetectsTampering` tests each case. The
  length prefixes make the encoding unambiguous, and the version label means a tag can never be confused with one
  from a future format.
- **Contract impact:** none on the `Encryptor` method signatures. Only the meaning of `Meta.Tag` became stronger.

### D9. Verify first, then decrypt, in two passes

- **Decision:** `Decrypt` works in two passes:
  1. Reads the whole stored object and checks the tag, without writing anything.
  2. Seeks back to the start, decrypts, and streams the plaintext out. It also recomputes the MAC and byte count, and
     fails if they differ from pass 1.
- **Alternatives:**
  - *Single pass* (decrypt and MAC together, check at the end): the plaintext would already be sent before tampering
    is discovered.
  - *Buffer the whole file:* not possible for multi-GB videos.
- **Why:** the user must never receive unauthenticated plaintext, and the handler must still be able to reply with an
  error status. The pass-2 re-check catches the object being replaced between the passes
  (`TestEnvelopeDetectsChangeBetweenPasses`).
- **Trade-offs:** downloads read the object twice and compute the MAC twice. Whatever the pass-2 check finds, some
  plaintext has already been streamed; the error still aborts the response. The benchmark numbers include this cost
  for all three algorithms equally.

### D10. Key wrapping with AES-256-GCM

- **Decision:** `WrapKey` encrypts a DEK or MAC key with AES-256-GCM, under the wrap key from D11, using
  `cipher.NewGCMWithRandomNonce`. The output is nonce (12 B) ‖ encrypted key ‖ tag (16 B). Any unwrap failure returns
  `ErrAuthentication`.
- **Alternatives:**
  - *AES Key Wrap (RFC 3394):* designed for this, but not in Go's standard library, and we must not write our own
    crypto.
  - *AES-CTR or AES-CBC:* no integrity, so a modified wrapped key would just unwrap to a wrong key.
  - *Same construction as the data (CTR + HMAC):* more code for no benefit.
- **Why:** GCM is authenticated encryption in the stdlib. `NewGCMWithRandomNonce` generates the nonce from
  `crypto/rand` and stores it with the ciphertext, so we can't get nonce handling wrong.
- **Limit:** a random 96-bit nonce is safe for up to 2^32 wraps per key. We do 12 wraps per file upload (6 for the
  three variants, 6 for the encrypted filename) and 36 per profile save (6 fields × 3 algorithms × 2 keys), so that's
  hundreds of millions of uploads away.
- **Note for the report:** every data key is wrapped with AES, including DES and RC4 keys. That's fine: the strength of
  each *copy* is still that of its own cipher (56-bit for DES). The wrap only protects keys at rest.

### D11. HKDF-SHA256 subkeys from the master key

- **Decision:** `DeriveKey(master, info)` is HKDF-SHA256 with no salt, `info` naming the purpose (`"key-wrap"`,
  `"nik-blind-index"`) and a 32-byte output.
- **Alternatives:**
  - *Use the master key directly for every purpose.*
  - *A separate environment variable per purpose.*
  - *A plain hash such as SHA-256(master ‖ purpose):* not a proper KDF.
- **Why:**
  - Each purpose gets an independent key, so a weakness or leak in one use (the NIK blind index is a deterministic
    HMAC) says nothing about the others.
  - There's still only one secret to manage.
  - A salt is only needed when the input key isn't already uniformly random. The master key is 32 random bytes, so
    RFC 5869 §3.1 allows omitting it.
  - `TestDeriveKeyMatchesRFC5869` recomputes HKDF by hand from the RFC's definition.

### D12. Errors: one "can't trust this data" error

- **Decision:** a wrong tag, a failed unwrap, a wrongly sized IV/tag/key in `Meta`, or a change between passes all
  return an error that wraps `ErrAuthentication`. An unknown algorithm returns `ErrUnknownAlgorithm`. A mismatch
  between the requested algorithm and `meta.Algorithm` is a plain error, because it's a caller bug.
- **Why:** callers need one rule: `errors.Is(err, crypto.ErrAuthentication)` means "stored data is damaged or
  tampered with; show a generic error (422) and use none of it". The detailed wrap text helps debugging but never
  contains key bytes.

### D13. Streaming in 32 KiB chunks; in-place XOR; best-effort key clearing

- **Decision:**
  - Data is processed in 32 KiB chunks, the same size `io.Copy` uses.
  - The XOR is done in place, so the buffer holds ciphertext immediately.
  - DEKs, MAC keys, derived wrap keys and buffers are `clear()`ed after use.
- **Why:**
  - Memory use is constant whatever the file size (the CONTRIBUTING rule: always stream).
  - In-place XOR avoids a second buffer.
  - Clearing shortens how long secrets sit in memory.
- **Trade-off:** in Go, clearing is best-effort. The garbage collector may already have copied a slice, and cipher
  objects keep their own expanded keys. It reduces exposure but doesn't guarantee it.

### D14. What the benchmark clock measures

- **Decision:** `crypto.Clock` gets the time spent creating the cipher (including the AES/DES key schedule and the
  RC4 key setup), in `XORKeyStream`, and in HMAC writes/sums. It does **not** get the time for `crypto/rand`, key
  wrapping/unwrapping, or I/O.
- **Why:** the report compares the *ciphers*. Random-number generation and GCM wrapping are a fixed per-object cost,
  identical for all three algorithms. I/O is measured separately as `TotalDuration` in `benchmark.Measure`.
- **Note:** the HMAC is identical for all three algorithms, so differences between algorithms come from the cipher.
  `BenchmarkKeystream` measures the bare cipher with no HMAC, for comparison.

### D15. gosec annotations on DES and RC4

- **Decision:** the `crypto/des` and `crypto/rc4` imports and the `des.NewCipher`/`rc4.NewCipher` calls in
  `internal/crypto/ciphers.go` carry `#nosec` comments for G502, G503 and G405, each with a reason.
- **Alternatives:**
  - *Exclude these rules in CI:* they would then also stop catching accidental DES/RC4 use anywhere else.
  - *Leave CI failing.*
- **Why:**
  - The assignment requires both ciphers.
  - Annotating only these lines keeps gosec watching the rest of the code.
  - `ciphers.go` is the only file that constructs them.
  - Running gosec with `-nosec` shows exactly these 4 findings and no others.

### D16. Where the test vectors come from

- **Decision:** known-answer values are copied from the published documents by script, never typed from memory:
  - **AES-256-CTR:** NIST SP 800-38A, Appendix F.5.5.
  - **RC4:** RFC 6229 §2, 256-bit key.
  - **DES:** NIST CAVP `KAT_TDES.zip` (`TECBvartext.rsp`, `TECBvarkey.rsp`, single-key rows). The `TECBvartext.rsp`
    rows match NIST SP 800-17 Appendix B Table 1. That PDF is a scanned image, so its text is unreliable OCR.
- **How DES gets tested through our CTR code:** no DES-CTR vectors are published. So each single-block vector is run
  through our CTR code with IV = the vector's plaintext and an all-zero data block. CTR then outputs exactly
  E_K(IV), the published ciphertext. `TestCTRCounterIncrement` then checks that later blocks are E_K(IV+1),
  E_K(IV+2), …, including the carry.
- **Not used:** the RFC 6229 40-bit and 128-bit RC4 keys, because `newStream` only accepts our 32-byte key. Testing
  them would only test Go's `rc4` package, not our code.

---

## Known limitations (crypto)

- **No binding to file or owner.** A complete variant (object + `Meta`) is valid wherever it's placed. An attacker who
  can write to *both* MongoDB and MinIO could move one user's variant into another record they control. Preventing
  this needs the record ID as associated data in the MAC, which means changing the shared `Encryptor` interface: a
  team decision.
- **No master-key rotation.** Rotating `MASTER_KEY` would need a job that unwraps and re-wraps every `Meta`. The data
  itself wouldn't need re-encrypting (D2).
- **DES and RC4 are insecure by today's standards.** DES has a 56-bit key, brute-forceable in hours, and a 64-bit
  block. RC4 has keystream biases and is prohibited by RFC 7465. We include them because the assignment compares
  them.
- **Memory clearing is best-effort** in a garbage-collected language (D13).
- **A change between the two download passes is detected after some plaintext was streamed** (D9).
