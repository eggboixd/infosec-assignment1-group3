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

---

## Private data (`feature/private-data`)

### D17. Which fields we store, and why they are personal data

- **Decision:** the profile holds six fields: full name, NIK, date of birth, address, phone number and email. All six
  are treated as personal data and encrypted.
- **Legal basis:**
  - *UU PDP No. 27/2022, Pasal 4(3):* general personal data includes full name and "data pribadi yang dikombinasikan
    untuk mengidentifikasi seseorang" (data that identifies a person when combined).
  - *GDPR Art. 4(1):* personal data is any information relating to an identifiable person, explicitly including a
    name, an identification number, location data and online identifiers.
  - The NIK is the most sensitive field: it is a lifelong national identifier and itself encodes the holder's region
    and date of birth. Address is location data; phone and email are contact/online identifiers.
- **Alternatives:** collecting more (gender, religion, marital status).
- **Why not:** *data minimisation*: GDPR Art. 5(1)(c), and UU PDP Pasal 16(2)(a) (processing must be "terbatas dan
  spesifik"). Six fields are enough to demonstrate field-level encryption, and we never collect *specific*
  personal data from Pasal 4(2) (health, biometric, genetic, criminal records, children's data, personal finances).

### D18. Field-level encryption, three independent copies per field

- **Decision:** each field is encrypted on its own with `Encryptor.EncryptField`, once per algorithm (applying D1),
  and stored as a `crypto.SealedSet`. One profile is 6 fields × 3 algorithms = 18 ciphertexts, each with its own DEK,
  MAC key and IV.
- **Alternatives:**
  - *Encrypt the whole document as one blob* (for example BSON → ciphertext).
  - *MongoDB's own Client-Side Field Level Encryption.*
- **Why:**
  - Per field mirrors the assignment ("store the user's private data in a DB, encrypted") and keeps the document
    shape readable for the report: `full_name.aes`, `full_name.des`, …
  - It reuses the exact code path the files use (D1–D9), so fields get the same IV/key freshness and
    encrypt-then-MAC integrity.
  - MongoDB CSFLE would replace our AES/DES/RC4 with AEAD_AES_256_CBC_HMAC_SHA_512 only, so it can't do the
    comparison, and it needs extra infrastructure.
- **Trade-off:** 18 key wraps per save. That is a few milliseconds, measured by D22.

### D19. NIK uniqueness through a keyed blind index (HMAC-SHA256)

- **Decision:** next to the encrypted NIK we store `nik_index = HMAC-SHA256(K_blind, NIK)`, where
  `K_blind = DeriveKey(MASTER_KEY, "nik-blind-index")` (D11). The key is derived at startup and never stored.
- **Problem it solves:** a NIK may belong to only one account, but the encrypted NIK uses a fresh key and IV every
  time (D6), so equal NIKs never have equal ciphertexts and the database can't compare them.
- **Alternatives:**
  1. *Plain SHA-256(NIK).*
  2. *Deterministic encryption* of the NIK (fixed key and IV).
  3. *Decrypt every stored NIK and compare* on each save.
  4. *No uniqueness check.*
- **Why HMAC:**
  - Against (1): NIKs are 16 digits but highly structured (6-digit region code, 6-digit date of birth with +40 for
    women, 4-digit serial). An attacker with a database copy could hash every plausible NIK for a region and reverse
    an unkeyed hash. With HMAC they also need `K_blind`, which is only derivable from `MASTER_KEY`.
  - Against (2): deterministic CTR/RC4 reuses a keystream (D3, D5), which is exactly what we must never do.
  - Against (3): O(number of users) decryptions per save, and still racy (see D20).
  - A separate key (not the master key, not a DEK) means the deterministic index tells nothing about other keys (D11).
- **Normalisation:** the NIK is trimmed and must be exactly 16 ASCII digits before hashing, so `" 3578…"` and
  `"3578…"` give the same index. `nikBlindIndex` refuses to run with a key that isn't 32 bytes, so a missing key can
  never silently produce an unkeyed hash.
- **Trade-off:** the index is deterministic, so whoever has `MASTER_KEY` (and the database) can test whether a given
  NIK is registered. That's inherent to any equality check and no worse than D2's existing assumption.

### D20. The database enforces uniqueness, not Go code

- **Decision:** a unique, sparse MongoDB index on `nik_index` (in the scaffold). A duplicate makes `Upsert` fail with
  a duplicate-key error, which the store maps to `ErrNIKTaken` → HTTP 409 "This NIK is already registered to another
  account."
- **Alternative:** check "does any other profile have this index?" in Go, then insert.
- **Why:** check-then-insert is a race: two simultaneous saves can both pass the check. The unique index makes the
  check and the write one atomic operation.
- **Privacy note:** the message does not say which account holds the NIK.

### D21. Validation twice: Gin binding tags, then the service

- **Decision:**
  - The handler binds the form with the scaffold's `binding` tags (first gate).
  - `Service.Save` trims every field and runs `validate`, which repeats those rules and adds: date of birth must be a
    real date, not in the future and not before 1900; no control characters in names (line breaks allowed only in the
    address); email must be a bare address (`net/mail` and nothing else, so `"Name <a@b.c>"` is rejected); NIK and
    phone must be ASCII digits only.
  - Messages are fixed, friendly sentences ("NIK must be exactly 16 digits."). They never contain the submitted value
    or Gin's internal text (`Key: 'PrivateData.NIK' Error: …`).
- **Alternatives:** binding tags only; or validation only in the service.
- **Why:**
  - The service must not trust its caller (defence in depth), and the tags can't express "not in the future".
  - Plain-Go validation is testable without Gin and keeps Gin out of the service (CONTRIBUTING).
  - Trimming first means `"   "` counts as empty and a pasted NIK with a trailing space still works.
  - Error text may end up in logs, and the values are personal data, so the messages never echo them.
- **Trade-off:** rules live in two places (tags and `validate`) plus the HTML `pattern`/`maxlength` attributes. The
  limits are named constants in `validate.go` next to a comment saying they must match.

### D22. Benchmarks: one record per profile operation per algorithm

- **Decision:** `Save` records three `benchmark.Record`s (`encrypt`, one per algorithm) and `Get` records one
  (`decrypt`, the chosen algorithm). Each covers the **whole profile** (all six fields); `Bytes` is the total
  plaintext size and `FileKind` is empty, as `Record` documents for field operations. Records are stored only when
  the operation succeeds, and a failure to store a record is logged but does not fail the user's request.
- **Alternatives:** one record per field; no records for profiles.
- **Why:** six ~20-byte samples per algorithm are mostly timer noise. One sample per profile is still small data, which
  is the point: next to multi-megabyte files it shows the **fixed per-item overhead** (random key generation, key
  wrapping, cipher set-up, HMAC) that dominates small inputs.
- **What `CryptoDuration` means here (differs from D14):** `EncryptField`/`DecryptField` take no `context`, so the
  `Envelope` can't add to the `crypto.Clock` itself. The profile service times each whole `EncryptField`/
  `DecryptField` call and adds that to the clock inside `benchmark.Measure`. So for profiles, `CryptoDuration`
  **includes** `crypto/rand` and key wrapping/unwrapping, which D14 excludes for files. The report must not compare
  file and profile `CryptoDuration` directly. Measuring exactly like D14 would mean adding a `context` parameter to
  `EncryptField`, which changes the shared `Encryptor` interface (a team decision).
- **Algorithm order:** to get one record per algorithm, `Save` loops algorithm-outer, field-inner. The scaffold's
  `sealAll` helper (field-outer) was therefore replaced by `sealField`/`openField`.

### D23. Fail closed when stored data doesn't verify

- **Decision:** if any field's copy for the chosen algorithm fails its MAC (`crypto.ErrAuthentication`) or is missing
  (`ErrCorrupt`), `Get` returns **no** data and the page shows `error.html` with 422 "Your stored data failed its
  integrity check". The log records user ID, algorithm and the error, never field values.
- **Alternative:** show the fields that did verify and blank the rest.
- **Why:** a partially tampered record can't be trusted as a whole (D12's rule: use none of it). The other
  algorithms' copies are independent, so the user can still pick one that verifies.

### D24. Post/Redirect/Get after saving

- **Decision:** a successful `POST /profile` answers `303 See Other` → `/profile?alg=aes`. Failed saves re-render the
  form (422 validation, 409 duplicate NIK, 500 other) with the submitted values and the messages, as `profile.html`
  expects.
- **Alternative:** re-render the page directly from the POST.
- **Why:** after the redirect, the page shows the data **decrypted back from MongoDB**, which is the real confirmation
  that the round trip works. Refreshing the page doesn't resubmit the form. A flash message ("Saved") needs sessions,
  which belong to `feature/auth`.
- **Note:** the form posts to `/profile` without the current `?alg=`, and templates are not changed in this branch,
  so the redirect always goes to the default (AES).

### D25. Updating keeps the original `_id` and `created_at`

- **Decision:** `Save` loads the existing profile first and copies its `_id` and `created_at` into the new document;
  `updated_at` is set to now.
- **Alternative:** change `Store.Upsert` to use `$set`/`$setOnInsert`.
- **Why:** `ReplaceOne` replaces the whole document, so without this `created_at` would be reset on every edit. Doing
  it in the service keeps the scaffold's store unchanged.

---

## Known limitations (private data)

- **No "delete my data".** UU PDP (Pasal 8) and GDPR (Art. 17) give the right to erasure. It isn't in this branch's
  scope; adding it would be a `DELETE`-style route plus `Store.DeleteByUserID`, scoped to the logged-in user.
- **Fields aren't bound to their owner or field name.** This is the crypto limitation "No binding to file or owner"
  applied to fields: someone who can *write* to MongoDB could copy another user's `nik` set into their own profile, or
  swap two fields, and it would still verify and decrypt. Fixing it needs associated data (user ID + field name) in
  the MAC, i.e. an `Encryptor` interface change.
- ~~**Until `feature/auth` lands, every request is the stub user `dev-user`.**~~ Resolved by `feature/auth`: each
  request now carries the logged-in user's ID, and isolation between two real accounts was checked end to end.
- **Any duplicate-key error from `Upsert` is reported as "NIK already registered"** (scaffold behaviour). The only other
  unique index is `user_id`, which can only collide if the same user's first two saves race; the user then sees a
  misleading message once and can save again.

---

## Authentication (`feature/auth`)

### D26. Passwords are hashed with Argon2id, never encrypted

- **Decision:** passwords are hashed with Argon2id (`golang.org/x/crypto/argon2`), t=3, m=64 MiB, p=2, a 16-byte
  random salt and a 32-byte output, stored as a PHC string (`$argon2id$v=19$m=65536,t=3,p=2$salt$hash`).
  Verification uses `crypto/subtle.ConstantTimeCompare`. At most 4 hashes run at once.
- **Alternatives:** encrypting passwords with AES/DES/RC4 like the private data; bcrypt; PBKDF2; scrypt.
- **Why:**
  - Login only needs "does it match?", and a hash answers that without ever being reversible. Encrypted passwords
    could all be decrypted by anyone holding the master key.
  - Argon2id is memory-hard (each guess needs 64 MiB), which makes GPU and ASIC cracking expensive. It won the
    Password Hashing Competition and is the first choice in RFC 9106 and the OWASP Password Storage Cheat Sheet.
  - The parameters are RFC 9106's second recommended option (t=3, 64 MiB) with 2 lanes instead of 4 for a small
    container. Measured in the Docker app: about 95 ms per login.
  - The cost is read from each stored hash, so the parameters can be raised later without breaking old accounts.
- **Trade-offs:** 64 MiB per hash means a burst of logins could exhaust memory. The 4-slot semaphore caps it at
  256 MiB; extra requests wait (or give up when the client disconnects).

### D27. Server-side sessions in MongoDB, written in-house

- **Decision:** on login the server makes a 32-byte random token (`crypto/rand`) and sends it in the `session`
  cookie. MongoDB stores only `HMAC-SHA256(SESSION_SECRET, token)` as the session `_id`, plus the user ID, username
  and `expires_at`. Sessions last 8 hours from login (absolute, not extended by activity). A TTL index deletes
  expired documents, and lookups also check `expires_at`, because the TTL monitor only runs every minute. Every login
  deletes the previous session and issues a new token; logout deletes the session server-side.
- **Alternatives:**
  1. *`gin-contrib/sessions` with a custom MongoDB store* (our original plan, since its own MongoDB store needs the v1
     driver).
  2. *Signed cookie sessions* (all state in the cookie).
  3. *JWTs.*
- **Why:**
  - Option 1 adds three dependencies (`gin-contrib/sessions`, `gorilla/sessions`, `gorilla/securecookie`) plus the
    archived `gorilla/context`, and its API has no way to rotate the session ID at login. The store adapter would
    have been about as much code as the whole session layer here (about 300 lines including the flash
    cookie, standard library only).
  - Options 2 and 3 can't be revoked: a stolen cookie or token stays valid until it expires, even after logout.
    Server-side sessions end the moment the document is deleted.
  - Storing only the HMAC means someone who can read the database cannot turn the stored IDs into working cookies.
- **Trade-offs:** one MongoDB lookup per request. No "remember me" and no idle timeout, only the 8-hour lifetime.

### D28. CSRF protection: Go's `CrossOriginProtection` plus SameSite=Strict cookies

- **Decision:** every state-changing request (POST, PUT, PATCH, DELETE) passes through
  `net/http.CrossOriginProtection`. It refuses the request when the browser's `Sec-Fetch-Site` header says another
  site sent it, or (older browsers) when the `Origin` header names another host. Session and flash cookies are
  `HttpOnly` and `SameSite=Strict`. `Secure` is set when `COOKIE_SECURE=true`.
- **Alternatives:** synchronizer tokens (a hidden token in every form); double-submit cookies; SameSite alone.
- **Why:**
  - It's in the standard library (Go 1.25+), needs no per-form changes, and covers htmx requests too.
  - Fetch metadata and `Origin` are sent by every current browser, and a page on another site can't forge them.
  - SameSite=Strict is a second layer: browsers don't attach the session cookie to cross-site requests at all.
  - `Secure` is configurable because the Docker setup serves plain HTTP. Chrome and Firefox accept Secure cookies on
    `http://localhost`, but no browser does over a LAN IP, where login would silently fail. gosec's G124 is
    annotated for this reason.
- **Trade-offs:** requests with neither header (curl, Postman) are allowed, since they are not from a browser and
  carry no ambient cookies unless the user adds them. SameSite=Strict means following a link to the app from
  another site shows the logged-out view until the next click.

### D29. Login and registration are rate limited per IP

- **Decision:** at most 10 login attempts and 5 registrations per client IP per minute. Over the limit the form is
  shown again with HTTP 429 and `Retry-After`. The limiter is in memory and tracks at most 10,000 IPs.
- **Alternatives:** per-username lockout; CAPTCHA; a shared limiter in MongoDB.
- **Why:** it slows online password guessing to 10 per minute per IP on top of the Argon2id cost, with no extra
  service. Per-username lockout would let anyone lock a victim out by typing their username wrongly 10 times.
- **Trade-offs:** it resets on restart and isn't shared between replicas (we run one). Many IPs (a botnet) are not
  stopped by a per-IP limit; long passwords and Argon2id are the defence there.

### D30. Login failures are indistinguishable

- **Decision:** a wrong password, an unknown username and an empty form all return the same 401 page ("Wrong username
  or password."). For an unknown username the password is still verified against a dummy hash made with the same
  parameters. Usernames are lower-cased, so `Budi` and `budi` are one account.
- **Why:** different messages or response times would tell an attacker which usernames exist. Measured in the Docker
  app over 4 attempts each: 95 ms for a wrong password and 98 ms for an unknown user.
- **Trade-offs:** registration still says "That username is already taken", so usernames can be enumerated there
  (rate limited to 5 per minute). Hiding it would need email verification, which this app doesn't have.

### D31. Form bodies are capped at 64 KiB

- **Decision:** every request body is capped at 64 KiB, except `POST /files`, which keeps `MAX_BODY_BYTES` (2 GiB)
  for video uploads.
- **Why:** login, register and profile forms are a few hundred bytes. Without the cap, a large multipart body sent to
  any form would be spooled to disk by Gin's form parser, up to 2 GiB per request.

---

## Known limitations (auth)

- **No password change or reset.** Changing a password would be a protected form that verifies the old password and
  stores a new hash; a reset needs a verified email address, which accounts don't have.
- **Sessions aren't revoked when an account changes.** There is no account deletion or password change yet; when one
  is added, it should delete that user's sessions (`sessions.deleteMany({user_id})`).
- **No multi-factor authentication.**
- **Rate limits are per process** (D29) and reset when the app restarts.

