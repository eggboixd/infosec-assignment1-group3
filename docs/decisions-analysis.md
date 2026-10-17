# Design decisions: ciphertext analysis (`feature/ciphertext-analysis`)

Kept in its own file, numbered A1, A2, … so it does not clash with `docs/decisions.md` (D1–D25) or other branches.
Format: **Decision** · Alternatives · Why · Trade-offs.

---

### A1. What we measure, and why these metrics

- **Decision:** for every sample file × algorithm we report: plaintext vs ciphertext size and stored metadata size, Shannon
  entropy, byte-histogram chi-square against uniform, the share of bytes that differ between two encryptions of the same
  file, the first 32 bytes, how many ciphertext bits change when one plaintext bit changes, and whether a flipped stored bit
  is rejected by `Decrypt`.
- **Alternatives:** NIST SP 800-22 / dieharder statistical suites; only eyeballing hex.
- **Why:**
  - The assignment asks to compare "the resulting ciphertext". Entropy and chi-square are the two standard, easy-to-explain
    randomness checks; both can be computed with the standard library and checked by hand in a test (all-zero input has entropy
    0, every byte value equally often has entropy 8 and chi-square 0).
  - "Two encryptions differ" shows that a fresh key and IV per call (D6) really gives unrelated ciphertext.
  - The one-bit test shows the real structural difference between stream-style modes and block-chaining modes: CTR and RC4
    have no diffusion, which is why D7 adds a MAC.
  - Full test suites need megabytes of data per run and extra tooling; they would add nothing visible at our file sizes.
- **Trade-offs:**
  - Chi-square needs at least about 5 expected bytes per value, so files under 1280 bytes are flagged and their numbers should
    not be interpreted. Entropy of a short file is capped at log2(length).
  - At these sizes all three ciphers pass. RC4's keystream biases need millions of samples under many keys to show up, so
    "all three look random" is an honest result, not a weak test. The report says the ciphers differ in security (key size,
    known attacks), not in what one ciphertext looks like.
  - Keys are fresh each run, so numbers vary slightly between runs; about 1 in 20 chi-square values exceeds the 5% critical value
    by chance alone.

### A2. The analysis encrypts through the real `crypto.Envelope`

- **Decision:** every sample is encrypted with `crypto.Envelope.Encrypt` (random per-run master key from `crypto/rand`), and
  "tamper" uses the real `Decrypt`, expecting `crypto.ErrAuthentication` and an empty output buffer.
- **Alternative:** re-implement the ciphers in the analysis tool.
- **Why:** the report must be about the code we actually ship. Using `Envelope` also exercises key and IV freshness, the MAC
  header (D8) and verify-before-decrypt (D9) for free.
- **Trade-off:** samples are held in memory (CONTRIBUTING says uploads must stream; this is an offline tool over files of at
  most 16 MiB, and it needs the whole ciphertext for its histograms). The tool refuses larger files.

### A3. Demo-only fixed-key ciphers in `internal/cipheranalysis/demo.go`  (Amends D15)

- **Decision:** two experiments cannot run through `Envelope`, because it never reuses a key or IV: the one-bit-flip test
  (encrypt two plaintexts under the **same** key and IV) and the ECB picture. `demo.go` builds AES-256-CTR, DES-CTR and RC4 with
  stdlib primitives under fixed, public, non-secret keys derived from the algorithm name, and AES-256-ECB as a loop over
  `cipher.Block`. It works on in-memory slices only.
- **Amends D15:** D15 says `ciphers.go` is the only file that constructs DES and RC4. `demo.go` is now a second one, with the
  same `#nosec` G502/G503/G405 comments, each pointing here. It is confined to the analysis package, which no application
  package imports.
- **Alternatives:**
  - *Export `newStream` from `internal/crypto`:* cleaner reuse but widens the shared package API, which needs a team discussion
    (CLAUDE.md, CONTRIBUTING).
  - *Drop the one-bit test and ECB picture:* loses the clearest "why CTR, why a MAC, why not ECB" evidence for the report.
- **Why this is safe:** a repeated key+IV is exactly the mistake the app must never make, so it is quarantined: fixed demo values
  (nothing secret to leak), never written next to real data, never stored in MongoDB or MinIO, and `ECB` is named and commented
  as forbidden. A test (`TestDemoCTRFirstBlockIsEncryptedIV`) checks the demo CTR matches the CTR definition (first keystream
  block = E_K(IV)).

### A4. "Why not ECB" picture

- **Decision:** `pattern.bmp` (flat disc, ring and square on a flat background, uncompressed 24-bit) has its pixel bytes
  encrypted with AES-ECB (demo) and with AES, DES and RC4 through `Envelope`; the 54-byte header is copied unchanged so each result still opens as an image.
  We save PNGs (converted with `image/png`) and count how many 16-byte blocks exactly repeat an earlier block.
- **Alternatives:** a photo (too noisy for ECB to show), a PNG/JPEG (already compressed, so few repeating blocks).
- **Why:** an uncompressed flat image makes the leak visible and measurable. Repeated-block counts give a number to quote next to the picture.
- **Note:** the vertical stripes in the ECB picture come from 16-byte blocks not lining up with 3-byte pixels; the outline of the shapes is still plainly visible.

### A5. SVG charts instead of PNG

- **Decision:** charts are generated as SVG with plain string building from the standard library.
- **Alternatives:** PNG with `golang.org/x/image/font/basicfont` for labels (one new dependency); unlabelled PNG bars.
- **Why:** the standard library cannot draw text into a PNG. SVG gives fully labelled, sharp charts and needs no dependency (CLAUDE.md: don't add dependencies without a branch reason). Browsers, Markdown viewers and Word can show or convert SVG.
- **Accessibility:** a colour-blind-safe palette (Okabe–Ito) and direct labels; every bar has a `<title>` tooltip with its value.

### A6. Sample data is fake, generated and deterministic

- **Decision:** `scripts/gentestdata` writes all samples except the MP4 from stdlib only. The ID card is a drawn layout with no text, documents state they are fake, and noise comes from a SHA-256 counter stream (no `math/rand`, which is banned even in tests).
  `scripts/testdata/.gitattributes` sets `-text` so `core.autocrlf` can't change bytes (a converted PDF would have wrong xref offsets).
- **Alternatives:** download public sample files (licensing, unknown provenance); use real ID cards (forbidden).
- **Why:** committed samples can be re-generated and compared byte for byte, anyone can reproduce the report, and no real personal data enters the repository.
- **MP4:** Go's standard library cannot encode video, so a small real clip is added by hand (README in `scripts/testdata`). A synthetic container with random payload was rejected because its "video" entropy would be fake.

### A7. Output location

- **Decision:** everything the tool writes goes to `docs/analysis/` (`report.md`, `results.csv`, SVG charts, ECB PNGs). The main `docs/report.md` and `docs/decisions.md` are not edited in this branch; the report owner links to `docs/analysis/report.md` later.
- **Why:** other branches edit those two files, so touching them here would cause merge conflicts.
- **Trade-off:** the report is regenerated with new random keys on each run, so re-running changes the numbers slightly and shows up as a diff. Commit a run only when the report is meant to change.

## Known limitations (ciphertext analysis)

- Statistics describe one ciphertext at a time. They cannot show weaknesses that need many ciphertexts (RC4 biases) or a key search (DES).
- Small samples (under 1280 bytes) give unreliable chi-square values; they are marked with `*`.
- The one-bit test is a property of the construction (XOR with a keystream), measured on a demo key; it is not a statement about `Envelope` keys, which are random per call.
