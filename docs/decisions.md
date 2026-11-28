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
  stores a new hash; a reset needs a verified email address, which accounts don't have. A password change must also call
  `keypair.Service.Rewrap`, or the user's private keys stay locked under the old password (D44).
- **Sessions aren't revoked when an account changes.** There is no account deletion or password change yet; when one
  is added, it should delete that user's sessions (`sessions.deleteMany({user_id})`).
- **No multi-factor authentication.**
- **Rate limits are per process** (D29) and reset when the app restarts.


## File storage (`feature/file-storage`)

### D32. Uploads are read once and fanned out to three encrypting streams

- **Decision:** the handler reads the multipart body with `Request.MultipartReader()`. The plaintext is copied once
  through `io.MultiWriter` into one `io.Pipe` per algorithm. For each algorithm, one goroutine encrypts from its pipe
  into a second pipe, and another streams that ciphertext to MinIO (`PutObject` with unknown size, so minio-go uses
  a multipart upload). The metadata record, with the filename encrypted by each algorithm, is inserted only after all
  three objects are stored. Object keys are `<owner id>/<file id>/<alg>`, so they reveal nothing about the file.
- **Alternatives:** buffer the file in memory or a temporary file and encrypt it three times; upload the plaintext
  once and encrypt it in a background job.
- **Why:** nothing larger than the pipe buffers is held in memory, so a 2 GiB video needs no more memory than an ID
  card. Measured in the Docker app: a 300 MiB video uploads in about 30 s with a peak app memory of 124 MiB. No
  plaintext ever touches the disk or MinIO.
- **Failure handling:** any error closes every pipe with that error, so all goroutines stop. The objects already
  written are then deleted and no record is inserted. `Put` runs on a context detached from the request
  (`context.WithoutCancel`): when the client disconnects, net/http cancels the request context, and minio-go aborts
  the failed multipart upload with `Put`'s context, so a cancelled one would leave the incomplete upload in MinIO.
  Benchmark records are saved the same way, with a 5 s timeout, because a client that closes the connection as soon
  as it has the last byte also cancels the request.
- **Trade-offs:** the slowest cipher (DES) sets the upload speed, because the copy waits for all three pipes. One
  upload runs six goroutines.
- **Downloads:** verify-then-decrypt (D9). Headers are prepared first, but nothing is sent until the HMAC has been
  checked, so a tampered object returns 422 with no file bytes. Downloads are always `Content-Disposition:
  attachment` with `Cache-Control: no-store`, and the filename is escaped by `mime.FormatMediaType`.

### D33. File type is detected from the extension and the content, with a size limit per kind

- **Decision:** the browser's `Content-Type` is ignored. An upload is accepted only if its extension is allowed for
  its kind *and* its first 512 bytes match that extension: `http.DetectContentType` for JPEG, PNG, PDF, MP4 and WebM;
  the ZIP signature for DOCX/XLSX; the OLE2 signature for DOC/XLS. Size limits are 10 MiB for an ID card, 50 MiB for a
  document and 2 GiB for a video. A larger file returns 413 and is cleaned up like any other failure.
- **Alternatives:** trust the browser type; sniff the content only; parse each format fully.
- **Why:** the browser type and the extension are both chosen by the uploader. Sniffing alone cannot tell DOCX from
  XLSX (both are ZIP) or DOC from XLS (both are OLE2). Requiring both to agree rejects a PDF renamed to `.png` and
  random bytes named `.docx`.
- **Trade-offs:** a magic-byte check is not validation. Any ZIP named `.docx` is accepted. This is acceptable because
  files are only ever returned as downloads to their owner, never rendered inline.

### D37. An upload records which application slot it fills

- **Decision:** `FileRecord` gets an optional `Slot` (`ktp`, `cv`, `transcript`, `recommendation`, `salary`,
  `intro_video`). The upload form sends a `slot` part before `file`; the kind comes from a slot table and the extension
  must also be one the slot accepts (a salary slip must be XLS/XLSX, not a PDF). The old `kind` part still works.
  Records without a slot (uploaded earlier) still load and show as "other files".
- **Alternatives:** no backend change (the UI could only group by kind: CV, transcript, recommendation letter and
  salary slip are all `document`); put a slot tag in the encrypted filename (breaks the plain form and mangles names).
- **Why:** the scholarship checklist needs to know which of four document slots a file fills. A plain optional field is
  the smallest change. It is not private data, so it is stored unencrypted, like `kind`. The `Encryptor` interface and
  the stored crypto format are unchanged.
- **Trade-offs:** the slot is only a label. Uploading a second file to the same slot adds another file (the UI offers
  the upload button only for empty slots, and delete frees the slot).

---

## Known limitations (file storage)

- **No resumable uploads.** An interrupted upload is discarded and must be restarted.
- **A crash mid-upload can leave orphaned objects.** The cleanup runs in the request, so if the app process dies
  between storing the objects and inserting the record, those objects stay in MinIO with no record. A periodic job
  could delete objects whose file id has no record.
- **Deleting is not atomic.** Objects are deleted before the record. If one object delete fails, the record is kept so
  the user can retry, but the other copies may already be gone, and downloading them returns an error.
- **The list decrypts every filename on each page load.** This is fine for tens of files per user; there is no
  pagination.

## Benchmarks (`feature/benchmark`)

### D34. One shared benchmark page, summarised in Go, filtered by time

- **Decision:** `/benchmarks` shows every record, not only the logged-in user's. Records are grouped by operation,
  data kind, size class (≤ 1 KiB, 1–64 KiB, 64 KiB–1 MiB, 1–16 MiB, 16–128 MiB, > 128 MiB) and algorithm. Each group
  shows its run count, mean ± sample standard deviation and minimum crypto time, mean total time, and throughput
  (total bytes over total time). The latest 100 raw records are listed below. `?since=<RFC 3339 time>` limits both
  the page and the CSV export to one run; old records are never deleted. The export streams every matching record,
  oldest first, with the header `created_at,algorithm,operation,file_kind,bytes,crypto_ns,total_ns`.
- **Alternatives:** per-user records (would need a `user_id` on `Record`); a MongoDB aggregation pipeline; a "clear
  all" button.
- **Why:** the page is a measurement tool for the report, and records hold only an algorithm, operation, file kind,
  size and timings, with no user, file id or name. The summary is computed in Go from a cursor
  (`Summarizer`, constant memory per group), so the same code serves the page, the benchmark runner and the tests;
  an aggregation pipeline could only be tested against a real MongoDB. Size classes stop a 1 KiB file and a 100 MiB
  video from being averaged together. A time filter keeps every past run reproducible, where a delete button would
  let one user wipe everyone's data.
- **Trade-offs:** any logged-in user can see when others uploaded or downloaded files and roughly how large they
  were. The page reads every matching record on each load; with tens of thousands of records, use `?since=`.

### D35. Controlled runs: `scripts/bench` repeats uploads and downloads one file at a time

- **Decision:** `go run ./scripts/bench` registers a throwaway account and does a warm-up. Then, for each size
  (default 1 KiB, 64 KiB, 1 MiB, 16 MiB), it uploads a fake video `-uploads` times (default 5) and downloads it `-n`
  times per algorithm (default 10), one request at a time, rotating which algorithm goes first in each round. Every
  download is compared with the SHA-256 of what was uploaded. It saves `/benchmarks/export.csv?since=<start of run>`
  and fails if the server did not record exactly the run's operations.
- **Why:** the warm-up keeps connection set-up and cold caches out of the results. Repeating uploads gives encrypt
  timings a mean and a spread; the first version uploaded each size once, and one sample per algorithm varied by up to
  39% between two runs. The record-count check catches lost records and other clients using the app during the run.
  The fake files are an MP4 header plus `crypto/rand` bytes, so the content cannot favour any cipher and no real data
  is used.
- **Upload contention is small but real.** The three encryptions of an upload run in parallel (D32). Comparing the
  cipher time inside uploads with `go test -bench` encrypting alone (docs/benchmark/README.md): +2% to +5% on a 2-vCPU
  VM (Intel Core Ultra 7 255HX), and +5% to +26% for DES and RC4 on a 4-core Ryzen 5 3550H (AES moved ±16% in both
  directions, which is run-to-run noise at 11 ms). So encrypt records are usable for the cipher comparison, but
  decrypt records, where one algorithm runs alone, are the cleaner one. What parallel encryption does change is the
  **whole upload**, which waits for the slowest cipher (DES).
- **Measured:** full results for both machines and all methods are in `docs/benchmark/README.md`. On the Ryzen, at 10
  MiB, the app's decrypt cipher time (with MinIO and MongoDB running) is within 7% of `go test -bench` for AES and DES
  and 26% slower for RC4. AES is fastest because Go uses the CPU's AES instructions; DES is slowest because it is a
  64-bit block cipher implemented in software with 16 rounds per block. Absolute numbers depend on the machine and
  even on the session (the same laptop measured 20–30% slower than 35 minutes earlier), so the report must
  take all its numbers from one session and name the machine.

### D36. Nested measurements share crypto time

- **Decision:** `crypto.WithClock` links the new Clock to any Clock already in the context, and `Clock.Add` adds to
  both. The download record (`OpDownload`, the whole request) contains the decrypt record (`OpDecrypt`), so both now
  carry the same crypto time.
- **Why:** before this, the inner `benchmark.Measure` replaced the clock, and every download record had a crypto time
  of 0. Found by the first benchmark run.

---

## Known limitations (benchmarks)

- **Upload encrypt times include some contention** between the three parallel encryptions: up to about +25% over
  a cipher running alone (D35).
- **Private-data crypto time is measured differently** from file crypto time (D22): it includes key generation and
  wrapping. Compare files with files and fields with fields.
- **Timings come from one machine and one run.** Report the mean ± standard deviation, the run count, and the hardware.

---

## Scholarship applications (`feature/scholarship-portal`)

### D38. An application stores which scholarship, encrypted with every algorithm, unique through a blind index

- **Decision:** `internal/applications` holds a fixed catalogue of two fictional scholarships and one `applications`
  document per student and scholarship: `user_id`, `scholarship` (the scholarship ID, a `SealedSet` from
  `EncryptField` with AES, DES and RC4), `index` and `submitted_at`. `index` is HMAC-SHA256 over the user ID and the
  scholarship ID, keyed with `DeriveKey(MASTER_KEY, "application-blind-index")`; a unique index on it allows one
  application per student and scholarship. Submitting is refused on the server unless the scholarship is open, the
  student has no application to it yet, a profile exists and all six document slots are filled. Reading an
  application decrypts the AES copy and recomputes the index from the decrypted ID; a mismatch is reported as an
  integrity error. Login now lands on `/`, which shows each scholarship with the student's status.
- **Alternatives:** store the scholarship ID in plaintext (simplest, and enough for a unique index); a computed
  "ready" status with no stored record; scholarships in a database collection.
- **Why:**
  - **The choice is private data.** Applying to the need-based scholarship says the family has a low income, which is
    personal financial information (UU PDP Pasal 4(2)). The brief requires everything private to be protected with all
    three ciphers, so it is sealed like the profile fields.
  - **A blind index, as for the NIK (D19).** The ciphertext changes on every encryption, so MongoDB cannot enforce
    uniqueness on it. An unkeyed hash of two possible IDs could be reversed by trying both; with the HMAC key it
    cannot. The user ID is part of the input, so two students who apply to the same scholarship have unrelated
    indexes, and the index does not reveal which students chose the same scholarship.
  - **Binding the record to its owner.** The field HMAC proves a ciphertext is genuine, not that it belongs to this
    record: someone with database access could copy another valid ciphertext in. Recomputing the index from the
    decrypted ID catches that (`TestSubmittedFailsClosedOnTampering`).
  - **Checks on the server.** A disabled button is only a hint; `Submit` checks readiness itself
    (`TestApplyNotReady`).
  - **No benchmark records** from this feature: the value is a few bytes, and the home page reads it on every view,
    which would flood the private-data measurements (like `files.List`, which records none either).
- **Trade-offs:** the number of applications per student is visible in the database (one document each), though not
  which scholarships. Readiness checks the profile and documents exist, not their content. The catalogue lives in
  code, so changing a scholarship is a code change.

---

## Known limitations (scholarship applications)

- **No reviewer side.** There is no admin, review or acceptance workflow, and a student cannot withdraw an application.
- **Documents are shared, not frozen.** Both scholarships use the same documents, and a student can still replace them
  after submitting; the application records only which scholarship and when.

---

## Key pairs (`feature/keypairs`)

Foundation for Assignment 2 (sharing: the owner encrypts a share key with the requester's public key, RSA-OAEP-SHA256)
and Assignment 3 (signing uploaded PDFs). This branch only creates, stores and unlocks keys; it neither shares nor
signs. How teammates call it: [keypairs.md](keypairs.md).

### D39. Two RSA-3072 key pairs per user, one per purpose

- **Decision:** every user gets two independent key pairs from `rsa.GenerateKey(crypto/rand, 3072)` (e = 65537): an
  **encryption** pair (others encrypt share keys to it) and a **signing** pair. Public keys are stored as PKIX
  (SubjectPublicKeyInfo) DER, private keys as PKCS#8 DER (encrypted, D40–D41).
- **Alternatives:**
  - *One pair for both purposes.*
  - *RSA-2048 or RSA-4096.*
  - *Elliptic curves (ECDSA/Ed25519, X25519).*
  - *PKCS#1 encoding* (`RSA PUBLIC KEY` / `RSA PRIVATE KEY`).
- **Why:**
  - *Two pairs:* NIST SP 800-57 Part 1 §5.2 says a key should be used for one purpose only. With one RSA key for
    both, decrypting and signing are the same private-key operation (m^d mod n), so a bug or a careless API in one
    feature (for example, "decrypt this value for me") could produce a signature on data the user never signed. With
    separate keys, a problem in sharing can't forge a signature and vice versa. It also lets the two be handled
    differently later (a lost encryption key and a lost signing key have different consequences).
  - *3072 bits:* SP 800-57 Part 1 Table 2 rates RSA-2048 at 112-bit security (acceptable only until 2030) and
    RSA-3072 at 128 bits, the same level as AES-128 and the level recommended beyond 2030. RSA-4096 isn't in that
    table; common estimates put it only around 140 bits, for much slower key generation and private-key operations.
  - *RSA, not curves:* the A2 design names RSA-OAEP for sharing, and Assignment 3 requires our own signing logic
    on top of library primitives. With RSA, that logic is hashing, padding and one modular exponentiation, which
    `math/big` provides; with ECDSA we would also have to hand-write curve arithmetic.
  - *PKIX and PKCS#8:* they record the algorithm inside the bytes, are what `x509.MarshalPKIXPublicKey` and
    `MarshalPKCS8PrivateKey` produce, and are what OpenSSL and most tools read as `PUBLIC KEY` / `PRIVATE KEY`.
- **Trade-offs:** generating one 3072-bit key took 0.17–1.6 s (mean 0.67 s, 10 runs) on the developer's Windows
  laptop, because it searches for random primes. Two keys are made once per user, at the first register or login.
  Key generation is one of the uses the assignment allows a library for, so we call `crypto/rsa` directly.

### D40. Private keys are encrypted under a key derived from the user's password, not the master key

- **Decision:** each user's private keys are encrypted (AES-256-GCM, D41) under a key-encryption key (KEK) derived
  from **their password** with Argon2id. The KEK is recomputed when needed and never stored.
- **Alternatives:**
  1. *Wrap them under `MASTER_KEY`*, like every file and field key (D2).
  2. *Browser-held keys:* generate and keep the private keys in the browser (WebCrypto), so the server never sees
     them.
- **Why not (1):** whoever has `MASTER_KEY` and a copy of the database (a server admin, or anyone who gets the
  `.env` and a backup) could unlock every private key and **sign as any user** or read any share key. A signature
  would then prove "the server signed this", not "this user signed this", which defeats the point of Assignment 3.
- **Why not (2):** it is the strongest model on paper, but:
  - the key is lost when the browser storage is cleared or the user switches devices;
  - our own signing logic (Assignment 3) would have to be rewritten in JavaScript, which this app has none of
    beyond small UI helpers;
  - the server delivers that JavaScript, so a malicious server could still serve code that steals the key;
  - the brief says *the app* generates a key pair when the user has none.
- **Why the password-derived KEK:** to use someone's private key, an attacker needs the database **and** that user's
  password. `MASTER_KEY` and the database together are not enough. Guessing the password from a stolen `keypairs`
  document costs one 64 MiB Argon2id run per guess, the same as attacking the password hash.
- **Why this differs from D2:** D2 rejected password-derived keys for *files and fields*, because a password reset
  would lose the data and background work (benchmarks, an export) needs the data without the user present. Neither
  applies here: nothing should ever sign or decrypt a share key on a user's behalf while they are away. Needing the
  user is the point.
- **Trade-offs and limits (say these to the TA):**
  - It protects against a stolen backup, a leaked `.env`, or a curious admin reading the database. It does **not**
    protect against someone who changes the running server: they could record the password the next time the user
    types it. Only browser-held keys (2) defend against that.
  - A forgotten password means the private keys are lost (D44).
  - Every action that needs a private key must ask for the password again (D44).

### D41. Argon2id KEK with its own salt; AES-256-GCM with associated data

- **Decision:**
  - KEK = `argon2.IDKey(password, salt, t=3, m=64 MiB, p=2, 32 bytes)`, the same cost as the password hash (D26), with
    a **separate** 16-byte `crypto/rand` salt stored in the `keypairs` document as `kdf`. The parameters are stored
    with the salt, like a PHC string, so the cost can be raised later. Stored parameters are bounds-checked (the same
    limits as `auth.parseHash`) before Argon2id runs.
  - Each PKCS#8 key is encrypted with AES-256-GCM (`cipher.NewGCMWithRandomNonce`, as in D10): nonce (12 B) ‖
    ciphertext ‖ tag (16 B). One KEK per user encrypts both keys.
  - The GCM **associated data** is the length-prefixed (D8 encoding) `"securestore/keypair/v1"` ‖ user ID ‖ purpose ‖
    public-key fingerprint.
- **Alternatives:** reuse the password hash's salt; PBKDF2 or scrypt; `crypto.WrapKey` (D10); CTR + HMAC like the
  data (D7); no associated data; a separate KEK per key.
- **Why:**
  - *Its own salt:* the password hash is also Argon2id of the password. With the same salt and parameters the KEK
    would be **byte-for-byte the hash stored in `users.password_hash`**, so the database would contain the key to
    every private key. A different random salt makes the two outputs unrelated (`TestDeriveKEK`).
  - *Argon2id:* the reasons of D26 (memory-hard, RFC 9106, OWASP). Using the same cost means the private keys are
    exactly as hard to attack offline as the login, and there is one set of parameters to defend.
  - *GCM:* authenticated encryption from the standard library, so a modified blob fails instead of decrypting to a
    wrong key. `crypto.WrapKey` can't be reused: it derives its key from `MASTER_KEY` and takes no associated data.
  - *Associated data:* GCM checks it without encrypting it. A blob copied to another account, swapped between the
    encryption and signing slots, or left next to a replaced public key fails to open
    (`TestUnwrapRejectsOtherContext`, `TestUnlockDetectsTampering`). The fingerprint also ties each private key to
    the public key everyone else sees; `Unlock` additionally checks `priv.PublicKey.Equal(pub)`.
  - *One KEK for both keys:* one Argon2id run per action. The associated data already separates the two blobs, and a
    random 96-bit nonce is safe for 2^32 encryptions under one key; we make two per password.
- **Trade-offs:** Argon2id costs 64 MiB per run. The keypair service has its own 2 slots (auth has 4), so the worst
  case for both is 6 × 64 MiB = 384 MiB.

### D42. Public keys are stored with a fingerprint and authenticated with an HMAC

- **Decision:** each pair stores `public_der`, `fingerprint` = SHA-256(`public_der`), `created_at` (millisecond
  precision, as MongoDB stores dates) and `public_mac` = HMAC-SHA256 under
  `DeriveKey(MASTER_KEY, "keypair-public-mac")` (D11) over the length-prefixed label, user ID, purpose, DER,
  fingerprint and `created_at`. `PublicKey`, `Info` and `Unlock` verify it before using anything. The logged-in user
  can download their own public keys as PEM at `/keys/encryption|signing/public.pem`; there is no route for private
  keys.
- **Alternatives:** store the public key without integrity protection; protect it only with the associated data of
  D41; certificates signed by an in-app CA.
- **Why:**
  - `PublicKey()` is called *without* the key owner's password: Assignment 2 encrypts a share key with the
    *requester's* encryption key. If someone who can write to MongoDB replaced that public key with their own, the
    owner would encrypt the secret for the attacker. D41's associated data is only checked when the *owner* unlocks,
    which is too late. The HMAC catches the swap at lookup time, following D2's rule that the database alone is not
    enough.
  - The user ID and purpose in the MAC stop a valid pair being moved to another account or slot; `created_at` in the
    MAC stops the date shown being changed.
  - The `MASTER_KEY` subkey only **authenticates** public keys; it can't decrypt a private key.
  - The fingerprint is a short, comparable identity for a key. Users can read it out over WhatsApp to check they
    have the right key, and it is what D41 binds the private key to. It is plain SHA-256 of the DER, so
    `sha256sum` of the decoded PEM gives the same value.
  - A CA with certificates would be the "real-world" answer but adds X.509 issuing and revocation, which is outside
    the assignment.
- **Trade-offs:** someone with `MASTER_KEY` **and** database write access can replace a public key and recompute the
  MAC. The server is the trusted directory of public keys, like a CA. Users who compare fingerprints out of band
  (the share key goes over WhatsApp/email anyway) can detect this.

### D43. Keys are created right after register and login (`EnsureKeys`), idempotently

- **Decision:** `keypair.Service.EnsureKeys(ctx, userID, password)` creates both pairs if the user has none, and
  otherwise does nothing (without even checking the password). `auth.Handler` calls it through a small `KeyEnsurer`
  interface, set with `WithKeys`, after a successful `Register` and after a successful `Login`. All key pairs of a
  user are one `keypairs` document with a unique index on `user_id`. If `EnsureKeys` fails, the error is logged
  (user ID and error only) and the login continues.
- **Alternatives:** generate keys in `auth.Service.Register` only; a "Generate my keys" button; a migration job for
  existing users; fail the login when key creation fails.
- **Why:**
  - Register and login are the **only** moments the server has the plaintext password, which D40 needs. A migration
    job can't create keys for existing users, because it has no passwords; with the login hook, existing accounts get
    keys at their next login, which is the brief's "if the user has no key pair, the app generates one".
  - *Idempotent:* logging in a hundred times leaves the same keys. After the first time, the check is one MongoDB
    lookup with no Argon2id.
  - *Race-safe:* two simultaneous first logins can both generate keys, but the unique index accepts only one insert;
    the other gets a duplicate-key error, which `EnsureKeys` treats as success (`TestEnsureKeysConcurrent`).
  - *Don't block the login:* logging in doesn't need the keys, and the next login retries. Locking a user out because
    MongoDB hiccuped during key generation would be worse than a delay in getting keys.
  - *Smallest change to `auth`:* an interface, a field, a setter and two calls, all added; no existing line changed.
    `NewHandler`'s signature and every existing test stay as they were. `auth` doesn't import `keypair`.
- **Trade-offs:** the first login after this feature takes about 1–3 s longer (two key generations, D39, plus one
  Argon2id). Registration does the same work, but behind its 5-per-minute rate limit (D29).

### D44. Unlock asks for the password every time; forgotten password = lost keys; `Rewrap` for password changes

- **Decision:**
  - `Unlock(ctx, userID, password, purpose)` returns the `*rsa.PrivateKey` for one action. Callers (sharing,
    signing) ask the user for their password again. The decrypted key and the KEK are never put in a session, cookie,
    log or the database, and are cleared (best effort, D13) after use.
  - A wrong password and a modified encrypted key both return `ErrUnlock`. Public-part failures return `ErrCorrupt`.
  - `Rewrap(ctx, userID, old, new)` re-encrypts both keys under a new password with a fresh salt; the key pairs and
    fingerprints stay the same. It is written only if the stored salt is still the one it read, so of two concurrent
    password changes only one wins.
- **Alternatives:** cache the unlocked key or the KEK in the session for its 8 hours; keep a recovery copy wrapped
  under `MASTER_KEY`; a "check value" to tell a wrong password from a tampered key.
- **Why:**
  - *No caching:* sessions are stored in MongoDB (D27), so a cached KEK would sit next to the encrypted keys, which is
    D40's rejected option (1) again. Caching in server memory would expose every logged-in user's key to a memory
    dump for hours. Re-typing a password costs one Argon2id run (about 0.1 s) per action, and it also confirms that
    *the user* wants to sign or decrypt now.
  - *One error:* GCM can't tell a wrong key from modified data; both are a tag mismatch. A separate check value would
    give an attacker nothing new (it is as good a guessing target as the blob), so it isn't worth adding. The UI
    should say "wrong password". Unlock attempts are an online password guess, so the sharing and signing branches
    should rate-limit them like logins (D29).
  - *No recovery copy:* any copy the server can open without the password brings back D40's option (1).
- **Forgotten password = lost keys:** nobody, including the admin, can recover a key that only the user's password
  unlocks. This is the accepted price of D40. Old signatures can still be **verified**, because the public keys stay
  in the database; the user just can't make new signatures or open share keys encrypted to the old key. A future
  "reset password" would therefore have to give the user new key pairs and keep the old public keys for
  verification.
- **Change password:** this app has none yet (see "Known limitations (auth)"). Whoever adds one must call `Rewrap`
  with the old and new password **before** storing the new password hash, in the same request; otherwise the keys
  stay locked under a password the user no longer has.

---

## Known limitations (key pairs)

- **No protection against a modified running server.** It could capture passwords as they are typed (D40).
- **A forgotten password loses the private keys** (D44). There is no password reset yet, and a future one must
  issue new key pairs.
- **No change-password flow yet.** `Rewrap` exists and is tested but has no caller (D44).
- **Public keys are trusted on the server's word.** Someone with `MASTER_KEY` and database write access can replace
  one (D42). Comparing fingerprints out of band defends against it.
- **No key rotation or revocation.** A user can't replace a compromised key pair; that needs keeping the old public
  key for verifying old signatures, plus a way to mark it revoked.
- **Unlock attempts are not rate limited in this branch**, because nothing calls `Unlock` yet. The sharing and
  signing branches must add a limit (D44).
- **Memory clearing is best effort** (D13). Go strings (the password from the form) can't be cleared at all, and
  `rsa.PrivateKey` keeps its values in `big.Int`s.

## Share requests (`feature/share-requests`)

Assignment 2, part 1: a user can request to see another user's private data, and the owner decides. The share key
itself (generating it, re-wrapping DEKs, RSA-OAEP to the requester, storing it) is `feature/share-keys`; the two meet
at the `Granter` interface and `Service.Active` ([sharing.md](sharing.md)). Full design:
[superpowers/specs/2026-11-28-share-requests-design.md](superpowers/specs/2026-11-28-share-requests-design.md).

### D53. One request covers all of the owner's private data

- **Decision:** a request names only the owner (by username). Approving it shares the applicant data and every
  uploaded file. There is no per-field or per-file choice.
- **Alternatives:** the requester picks fields and files; the owner picks what to include when approving.
- **Why:** the brief asks for "the private data of other users (including the images and documents)", which is all of
  it. One scope keeps the request record, the approve form and the share-key re-wrapping simple, and leaves no
  "partly shared" state to get wrong.
- **Trade-offs:** an owner who would share only their CV has to share everything or nothing.

### D54. Expiry is decided by time on every read, not by a background job

- **Decision:** every request has `expires_at`: `created_at + 7 days` while pending, `decided_at + 1/7/30 days`
  (owner's choice) once approved. A pending or approved request with `now >= expires_at` is *effectively* expired
  everywhere (`Request.EffectiveStatus`), whatever the stored status says. The stored status is updated to `expired`
  lazily, when the pair gets a new request or a page lists it; for an approved request that also calls
  `Granter.Destroy`. Records are never deleted.
- **Alternatives:** a TTL index (deletes the record); a periodic sweeper goroutine; checking expiry only when shared
  data is opened.
- **Why:** access must end at the exact second, not when a job next runs (the TTL monitor runs about once a minute and
  would also erase the history the report needs). Computing it on read needs no extra process and can't be forgotten:
  `Active`, approve, reject, revoke and cancel all go through the same check.
- **Trade-offs:** share material of an expired approval stays stored until the request is next touched. It's unusable
  in that window, because `Active` refuses it, but it isn't deleted yet. If `Destroy` fails (it is logged and runs
  detached from the request with a 10-second timeout), nothing retries it, and the unusable material stays stored.

### D55. Compare-and-set transitions, and Grant before approve

- **Decision:** every status change is one conditional `UpdateOne` on `_id`, the acting user's field (`owner_id` or
  `requester_id`) and the expected status; user actions (approve, reject, revoke, cancel) also require
  `expires_at > now`, while marking a lapsed request `expired` doesn't. Approve calls `Granter.Grant` first and
  changes the status second. If that change loses a race **or fails**, the request is re-read, and the new material
  is destroyed only if the re-read succeeds and shows the request isn't approved: a concurrent approve (a double
  click) may have won, and a failed write may still have been applied. `Grant` is create-if-absent per request, so
  the losing approve can't replace the winner's key. Revoke changes the status first, which cuts access, then
  destroys, detached from the request's cancellation.
- **Alternatives:** read-modify-write; a MongoDB transaction around the request and the share material; approve first
  and grant second.
- **Why:** two clicks, or an approve racing a cancel, can't both win, and an action on a request that just expired
  fails cleanly. Granting first means a request shown as approved always has a share key; the opposite order would
  leave "approved, but no key" whenever Grant fails. Transactions need a replica set, which our Compose stack doesn't
  run. Material created by a losing approve is harmless, because `Active` gates every use of it.
- **Trade-offs:** Grant's work is wasted when the approve loses a race. When the re-read fails, material may be left
  on a request that isn't approved; `Active` refuses it, but it isn't deleted.

### D56. At most one open request per pair, enforced by a partial unique index

- **Decision:** the `share_requests` index `open_pair_unique` is unique on `{requester_id, owner_id}` for documents
  whose status is `pending` or `approved`. Before inserting, `Send` marks the pair's lapsed-but-stored-open requests as
  `expired`. A duplicate-key error is `ErrAlreadyOpen` (409). Rejected, cancelled, revoked and expired requests don't
  block asking again.
- **Alternatives:** check-then-insert in Go only; one document per pair that is reused.
- **Why:** a Go check alone has a race (two sends at once). The index makes the database the referee, the same pattern
  as D38 and D43. Keeping one document per request keeps the history.
- **Trade-offs:** an approval that expired but hasn't been marked yet would block a new request if `Send` didn't mark
  it first, so `Send` does one extra query per call.

### D57. Requests are scoped to the acting user; usernames can be discovered

- **Decision:** every lookup filters on the request ID **and** the acting user's side: owner for approve, reject and
  revoke; requester for cancel and `Active`. An unknown ID, a malformed ID and someone else's request all return the
  same 404. Sending to a username that doesn't exist says so ("No user with that username."). Sending is limited to 10
  per requester per hour (in memory, like D29) and 20 open pending requests.
- **Alternatives:** check ownership after loading (403 for someone else's request); a generic "if that user exists,
  they'll see your request" message.
- **Why:** a 403 would confirm that a request ID exists. The generic message wouldn't hide anything, because the
  sender's own list shows each request with its recipient. So we name the error and bound probing with the rate limit
  instead.
- **Trade-offs:** a logged-in user can learn whether up to 10 usernames per hour exist. Usernames aren't private data
  in this app (they're shown in the nav and to the people you share with).

## Known limitations (share requests)

- **No owner password on approve.** The share key is encrypted to the requester's *public* key and the DEKs are
  unwrapped with the master key, so approving needs no private key of the owner's. If `feature/share-keys` needs one,
  the approve form gains a password field and a rate limit.
- **Files uploaded after approval** are shared only if `feature/share-keys` re-wraps them; that is its decision.
- **The send rate limit is in memory** (resets on restart, not shared between replicas), as D29.

## Share keys (`feature/share-keys`)

Assignment 2, part 2: the requested user's share key, its delivery to the requester and how it is stored. How it works
step by step: [sharekeys.md](sharekeys.md).

### D58. A fresh share key per request re-wraps the owner's DEKs; the data isn't re-encrypted

- **Decision:** `Grant` generates a 256-bit key K with `crypto/rand` for each approved request. For every profile
  field and every file, in all three algorithms, it unwraps the DEK and MAC key with the master key and stores them
  again wrapped under K (`crypto.WrapKey(K, …)`, AES-256-GCM). The ciphertext isn't touched.
- **Alternatives:** decrypt everything and encrypt it again under K; share the owner's DEKs as they are (wrapped under
  the master key); one long-lived share key per owner.
- **Why:** re-wrapping is a few hundred bytes of work per item, while re-encrypting would copy every file, including
  2 GiB videos. Sharing the master-wrapped keys would make K meaningless. A key per request means revoking one
  requester destroys only their K, and two requesters never hold the same key.
- **Trade-offs:** the server unwraps the owner's DEKs at approval, so it must be trusted at that moment. That was
  already true: the server holds the master key that wraps every DEK (D2).

### D59. RSA-OAEP-SHA256 to the requester's encryption key, with the request ID in the label

- **Decision:** K is encrypted with RSA-OAEP, SHA-256, to the requester's `keypair.Encryption` public key, with the
  label `securestore/share-key/v1:<request id>`. The owner copies the base64 ciphertext from the "Show encrypted key"
  page into WhatsApp or email, next to the requester's key fingerprint. `key_check = HMAC-SHA256(K, request id)` is
  stored so import can recognise the right K.
- **Alternatives:** PKCS #1 v1.5 encryption; no label; checking K by trying to decrypt a field.
- **Why:** OAEP is the padding RSA encryption should use today; v1.5 has padding-oracle attacks (Bleichenbacher).
  The label binds the ciphertext to one request, so a key sent for one request can't be imported into another, even
  by the same requester. The HMAC check works even when the owner had no data, and gives one clear "wrong key" error.
- **Trade-offs:** the fingerprint check is manual. If both users skip it, a server that served a wrong public key
  would go unnoticed (D42 trade-offs).

### D60. Import once: K is stored only after the requester decrypts it

- **Decision:** until import, the server holds K only as the RSA ciphertext. On import the requester pastes it and
  types their password; the app unlocks their private key, decrypts K, checks `key_check`, and stores K under
  AES-256-GCM with `DeriveKey(master, "share-key-import")`, the request ID as associated data. Later opens and
  downloads need no password. Import attempts are limited to 10 per user per 15 minutes.
- **Alternatives:** paste the key and password on every view and download; keep K in the session; store K under the
  master key at grant time.
- **Why:** asking for the password on every download would make a share of six files six password prompts. Sessions
  hold no feature data in this app (D27). Storing K at grant time would make the WhatsApp step decoration; with
  import, the data can't be opened until the requester proves they hold the private key. The associated data stops a
  stored K being copied to another request.
- **Trade-offs:** after import, K is protected by the master key, like every DEK. Someone with the master key and the
  database could open an imported share, as they could already open the owner's data directly.

### D61. The share is a snapshot taken at approval

- **Decision:** profile ciphertexts are copied into the share; files are referenced by object key with their keys
  re-wrapped. Files uploaded after approval are not shared.
- **Alternatives:** look up the owner's current data on every open and re-wrap it then.
- **Why:** re-wrapping on open would need the master key at open time and would make K pointless. A snapshot also
  matches what the owner agreed to when they approved. Copying the profile keeps the share working after the owner
  edits it (an edit replaces the document and its DEKs).
- **Trade-offs:** the requester sees the data as it was at approval. A file the owner deletes afterwards can't be
  downloaded (its object is gone); the owner has to approve a new request to share new files.

### D62. `sharing.Active` gates every open, not only import

- **Decision:** the import, open and download handlers call `Active` first, in the same HTTP request. The service
  methods take the `*sharing.Request` it returns. `Destroy` deletes the share document on revoke and expiry.
- **Alternatives:** check only at import; rely on `Destroy` alone.
- **Why:** revoke and expiry must take effect at once (D54). `Destroy` runs detached and its failure is only logged
  (D55), so it can't be the security check.
- **Trade-offs:** one extra MongoDB read per download.

### D63. `crypto.DecryptWithKeys`: decrypt with keys that are already unwrapped

- **Decision:** `internal/crypto` gains `DecryptWithKeys(ctx, alg, meta, dek, macKey, dst, src)`. `Envelope.open` now
  unwraps and calls the same internal function, so both paths verify the HMAC before writing plaintext.
- **Alternatives:** store a new `Meta` with K-wrapped keys; copy the stream and MAC code into `sharekey`.
- **Why:** the MAC header covers `meta.WrappedDEK` and `meta.WrappedMACKey` (D8), so swapping in K-wrapped keys would
  break every tag. Copying the code would mean two implementations of verify-then-decrypt to keep in step.
- **Trade-offs:** a change to the shared crypto contract, additive only: `Encryptor` is unchanged.

## Known limitations (share keys)

- **Snapshot** (D61): later uploads and edits aren't shared; files deleted after approval can't be downloaded.
- **The import rate limit is in memory** (resets on restart), as D29.
- **No change-password flow re-encrypts pending share keys.** `encrypted_key` is tied to the requester's public key,
  which `keypair.Rewrap` doesn't change, so a password change doesn't break it.
