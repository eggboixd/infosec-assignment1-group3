# PDF signing: how to use `internal/pdfsign`

For `feature/pdf-signing-ui` (handlers, templates, sign button, verify page). The reasons behind every choice are in
[decisions.md](decisions.md), from D45. Keys come from [keypairs.md](keypairs.md).

> **Status:** the exported API below is fixed. In the first commit the three service methods return a temporary
> "not implemented" error; their bodies land in the next commits of `feature/pdf-sign-core` without changing any
> signature. You can build and test your handlers against it now, with a fake (see [Testing](#testing-your-handlers)).

## What it does

- **Sign:** the owner picks one of their stored PDFs and re-enters their password. The app decrypts the PDF,
  signs it with the owner's **signing** key (`keypair.Signing`), and stores the signed copy as a **new file**,
  `<name>-signed.pdf`, in the **same application slot** as the original. In the checklist the signed copy becomes the
  slot's file, and the original moves to "Other files", where it can still be deleted. The signature is embedded in
  the PDF, so a downloaded signed PDF carries its own proof.
- **Verify:** for a stored file (`VerifyFile`) or any uploaded PDF (`VerifyUpload`, nothing stored). The result says
  whether each signature is valid, who signed and with which key fingerprint, whether the signature covers the whole
  file, and whether anything was added after signing.

## The API

```go
import "github.com/eggboixd/infosec-assignment1-group3/internal/pdfsign"

func NewService(files fileStore, keys signingKeys) *Service // pdfsign.NewService(filesSvc, keySvc)

type Identity struct {
	UserID   bson.ObjectID
	Username string
}

// Sign the owner's stored PDF. password is what the user just typed. Returns the NEW file's record
// (rec.ID for a redirect or flash message). Takes about 1–2 s (Argon2id + RSA-3072).
func (s *Service) SignFile(ctx context.Context, signer Identity, fileID bson.ObjectID, password string) (*files.FileRecord, error)

// Verify the owner's stored PDF. Another user's file ID is files.ErrNotFound.
func (s *Service) VerifyFile(ctx context.Context, ownerID, fileID bson.ObjectID) (*Report, error)

// Verify a PDF read from r (an upload on the verify page). Nothing is stored.
func (s *Service) VerifyUpload(ctx context.Context, r io.Reader) (*Report, error)

const MaxSize = 50 << 20 // largest PDF signed or verified (same as the files document limit)
```

Signing as the logged-in user: `pdfsign.Identity{UserID: user.ID, Username: user.Username}` from
`auth.CurrentUser(c)`. **Never take the signer from the form.** The service signs `fileID` only if `signer.UserID`
owns it.

### The report

```go
type Report struct {
	Status        Status            // the verdict on the whole document, show it first
	Signatures    []SignatureResult // oldest first
	FileSize      int64
	AppendedBytes int64             // bytes after the newest signature (> 0 only when Modified)
}

type SignatureResult struct {
	Index           int
	Format          Format    // FormatInApp ("securestore"), FormatCMS ("adbe.pkcs7.detached"), FormatUnknown ("")
	SignerID        bson.ObjectID
	SignerName      string    // username written in the PDF: a label, not proof
	Fingerprint     string    // "1a2b 3c4d …", same format as the profile's "My keys"
	KeyMatches      bool      // that fingerprint is the signer's registered signing key
	SignedAt        time.Time // the signer's claimed time (/M), not a trusted timestamp
	ByteRange       [4]int64
	RevisionEnd     int64
	CoversWholeFile bool
	CoveredByLater  bool      // the document was signed again later, and that signature covers this one
	Valid           bool
	Problem         error     // nil when Valid; see the table below
}
```

| `Status` | Meaning | Suggested text |
|---|---|---|
| `StatusValid` | Every signature verified with its signer's registered key, and the newest covers the whole file. | "Signed by *name* and not modified since." |
| `StatusModified` | Every signature verified, but `AppendedBytes` bytes were added after the newest one. Those bytes can change what a PDF viewer shows. | "The signature is valid for an earlier version, but the file was changed after signing." (warning colour, not green) |
| `StatusInvalid` | At least one signature failed or couldn't be checked. | "Signature not valid: *problem*." (error colour) |
| `StatusUnsigned` | No signatures. | "This PDF is not signed." |

For each signature, show **SignerName, Fingerprint, SignedAt (as "claimed signing time"), Valid and Problem**. For an
older signature with `CoveredByLater`, say "the document was signed again after this signature", which is normal
when two people sign.

`SignatureResult.Problem` values (compare with `errors.Is`):

| Problem | Meaning | Suggested text |
|---|---|---|
| `ErrBadSignature` | The signature doesn't match the signed bytes. | "The document was changed after signing, or the signature is forged." |
| `ErrByteRange` | The signed range is malformed or doesn't exclude exactly the signature. | "The signature doesn't cover the document properly." |
| `ErrMalformedSignature` | The signature data can't be parsed. | "The signature is damaged." |
| `ErrUnsupportedFormat` | Signed by another program in a format we don't check. | "Signed with a format this app can't verify." |
| `ErrUnknownSigner` | The signer isn't a user of this app, or has no signing key. | "Signer unknown." |
| `ErrKeyMismatch` | The key in the PDF isn't the signer's registered key. | "Signed with a key that doesn't belong to *name*." |

### Errors from the methods

These mean the call failed and there is no report. Compare with `errors.Is`. Error texts never contain keys,
passwords or file content, so they are safe to log next to a user ID and file ID.

| Error | From | Meaning | Status / text |
|---|---|---|---|
| `files.ErrNotFound` | SignFile, VerifyFile | No such file, **or another user's file** (deliberately the same). | 404 "File not found." |
| `keypair.ErrUnlock` | SignFile | Wrong password (or a damaged encrypted key; they can't be told apart, D44). | 401/422 "Wrong password." |
| `pdfsign.ErrRateLimited` | SignFile | Too many attempts. `errors.As(err, &rlErr)` gives `*RateLimitError` with `RetryAfter`. | 429 + `Retry-After` header, "Too many attempts, try again in N s." |
| `keypair.ErrNoKeys` | SignFile | The user has no keys yet. | 409 "Your keys are created at your next login." |
| `pdfsign.ErrNotPDF` | all | Not a PDF, empty, or unreadable (also a stored DOC/XLS). | 422 "This file is not a readable PDF." |
| `pdfsign.ErrEncrypted` | all | Password-protected PDF. | 422 "Password-protected PDFs can't be signed or verified." |
| `pdfsign.ErrUnsupportedPDF` | SignFile | Readable, but its structure can't be signed safely. | 422 "This PDF can't be signed. Try re-saving it (Print → Save as PDF)." |
| `pdfsign.ErrTooLarge` | all | Over `MaxSize` (or the signed copy would be). | 413 "PDF too large (max 50 MB)." |
| `pdfsign.ErrExistingSignatureInvalid` | SignFile | The PDF already has a signature that doesn't verify; we won't add ours to it. | 409 "This PDF has an invalid signature. Verify it to see why." |
| `pdfsign.ErrTooManySignatures` | SignFile | Already at the maximum number of signatures. | 409 "This PDF has too many signatures." |
| `files.ErrMIMENotAllowed` / `files.ErrTooLarge` | SignFile | Storing the signed copy failed the upload checks (should not happen for a valid PDF). | 422 / 413 |
| `crypto.ErrAuthentication`, `files.ErrCorrupt` | SignFile, VerifyFile | The stored encrypted file failed its integrity check (D9). | 422 "The stored file failed its integrity check." |
| `context.Canceled` / anything else | all | Client gone, MongoDB/MinIO error. | 500 generic, log it |

## Wiring it in

Declare the interface you need in **your** handler (CONTRIBUTING: consumers declare interfaces), so your tests can
use a fake:

```go
// in your handlers.go
type signer interface {
	SignFile(ctx context.Context, signer pdfsign.Identity, fileID bson.ObjectID, password string) (*files.FileRecord, error)
	VerifyFile(ctx context.Context, ownerID, fileID bson.ObjectID) (*pdfsign.Report, error)
	VerifyUpload(ctx context.Context, r io.Reader) (*pdfsign.Report, error)
}
```

In `cmd/server/main.go` (your branch adds this, so we don't both edit the file):

```go
pdfSignSvc := pdfsign.NewService(filesSvc, keySvc)
// ...Features: append yourpkg.NewHandler(pdfSignSvc)
```

`NewService` compiles only with the real `*files.Service` and `*keypair.Service` (a compile-time check in
`service.go`), so if it builds, the wiring is right.

## Rules for the UI (please don't break these)

1. **Ask for the password on every sign**, in a POST form, and pass it straight to `SignFile`. Don't store it, or
   anything derived from it, in the session, a cookie, a hidden field, a log or a variable that outlives the request
   (D44). Clear the field when the page is shown again.
2. **The signer is always the logged-in user** (`auth.CurrentUser`). File IDs come from the URL; `SignFile` and
   `VerifyFile` already scope them to that user. Don't add a "sign as" or "owner" field.
3. **Rate limits:** `SignFile` already limits each *user* (5 attempts per 5 minutes) and returns `ErrRateLimited`.
   A per-IP limit in the handler, like auth's (D29), is welcome on top but not required.
4. **Only offer "Sign" for PDFs** (`rec.MIMEType == "application/pdf"` / a `.pdf` name). The service rejects
   anything else with `ErrNotPDF` anyway.
5. **Show `Status` first, and never show green for `StatusModified`.** A valid signature over an *earlier* version
   is the incremental-saving attack: the old signature still checks out, but the viewer shows the added content.
6. **Trust only `Valid` and `KeyMatches`, never `SignerName` alone.** Show the fingerprint, so users can compare it
   with the signer's profile ("My keys") or a fingerprint sent over WhatsApp.
7. **Call `SignedAt` "claimed signing time".** It comes from the signer's clock; there is no trusted timestamp.
8. **Verify page uploads:** read the multipart file and pass its reader to `VerifyUpload`. Don't save it, and don't
   render the uploaded PDF inline in our origin (downloads stay `Content-Disposition: attachment`). The global body
   limit `MAX_BODY_BYTES` still applies; `MaxSize` is the PDF limit.
9. **Never log** passwords, PDF contents or report text that came from the PDF (`SignerName` is user-chosen). Log
   user IDs, file IDs and error values.

## Recipes

### Sign button

```go
user, _ := auth.CurrentUser(c)
id, err := bson.ObjectIDFromHex(c.Param("id"))   // 404 on error
var form struct {
	Password string `form:"password" binding:"required,max=256"`
}
// bind form → 422 on error
rec, err := h.svc.SignFile(c.Request.Context(), pdfsign.Identity{UserID: user.ID, Username: user.Username}, id, form.Password)
switch {
case err == nil:              // redirect (PRG, D24) to the file list, flash "Signed: saved as a new file"
case errors.Is(err, keypair.ErrUnlock):        // 422 "Wrong password."
case errors.Is(err, pdfsign.ErrRateLimited):   // 429, see RetryAfter
// ... the table above
}
```

### Verify a stored file

```go
rep, err := h.svc.VerifyFile(c.Request.Context(), user.ID, id)
// err: the table above. Otherwise render rep.Status, then one row per rep.Signatures.
```

## Testing your handlers

You don't need MongoDB, MinIO or real keys: implement your `signer` interface with a fake that returns a canned
`*pdfsign.Report` or one of the exported errors. To test error mapping, wrap them as the service does, for example
`fmt.Errorf("pdfsign: %w", keypair.ErrUnlock)` and `&pdfsign.RateLimitError{RetryAfter: time.Minute}`.
