# Key pairs: how to use `internal/keypair`

For the branches that build on `feature/keypairs`: `feature/share-requests`, `feature/share-keys`,
`feature/pdf-sign-core` and `feature/pdf-signing-ui`. The reasons behind every choice are in
[decisions.md](decisions.md) D39–D44.

## What every user has

| | Encryption pair | Signing pair |
|---|---|---|
| Purpose constant | `keypair.Encryption` (`"encryption"`) | `keypair.Signing` (`"signing"`) |
| Used for | others encrypt a share key **to** this user (A2) | this user signs PDFs (A3) |
| Algorithm | RSA-3072, e = 65537 | RSA-3072, e = 65537 |
| Public key | `PublicKey(ctx, userID, keypair.Encryption)`, no password | `PublicKey(ctx, userID, keypair.Signing)`, no password |
| Private key | `Unlock(ctx, userID, password, keypair.Encryption)` | `Unlock(ctx, userID, password, keypair.Signing)` |

The two pairs are independent keys. **Never use one for the other's job**: don't sign with the encryption key, and
don't encrypt to the signing key.

Keys are created automatically after register and after every login if the user has none (D43), so any user who has
logged in since this branch was merged has both. A user who hasn't gives `ErrNoKeys`.

## The API

```go
import "github.com/eggboixd/infosec-assignment1-group3/internal/keypair"

// Public key of any user, for one purpose. No password needed. The MAC on the
// stored key is checked first, so a key swapped in the database is refused.
func (s *Service) PublicKey(ctx context.Context, userID bson.ObjectID, p Purpose) (*rsa.PublicKey, error)

// The user's own private key, decrypted with their password, for ONE action.
func (s *Service) Unlock(ctx context.Context, userID bson.ObjectID, password string, p Purpose) (*rsa.PrivateKey, error)

// Public description (purpose, bits, formatted fingerprint, created_at) for display.
func (s *Service) Info(ctx context.Context, userID bson.ObjectID) ([]Info, error)

// Creates both pairs if missing. Already wired into login/register; you shouldn't need it.
func (s *Service) EnsureKeys(ctx context.Context, userID bson.ObjectID, password string) error

// Re-encrypts the private keys under a new password. Call it from a change-password flow.
func (s *Service) Rewrap(ctx context.Context, userID bson.ObjectID, oldPassword, newPassword string) error

// Helpers
func ParsePurpose(s string) (Purpose, error)          // "encryption" | "signing", exact match
func PublicKeyPEM(pub *rsa.PublicKey) ([]byte, error) // PKIX "PUBLIC KEY" PEM
func FormatFingerprint(fp []byte) string              // "1a2b 3c4d …" (SHA-256, hex in groups of 4)
const KeyBits = 3072
```

### Errors

| Error | Meaning | What to show |
|---|---|---|
| `keypair.ErrNoKeys` | The user has no key pairs yet. **Also what you get for a user ID that isn't theirs to see**, since every lookup is by the ID you pass. | "This user has no keys yet; they are created at their next login." (404 or 409) |
| `keypair.ErrUnlock` | Wrong password, **or** the encrypted private key was modified. AES-GCM can't tell these apart. | "Wrong password." (401/422) |
| `keypair.ErrCorrupt` | Stored public key, fingerprint, KDF parameters or key size failed a check. Don't use anything from it. | Generic integrity error (422), log the user ID |
| `keypair.ErrUnknownPurpose` | A `Purpose` other than the two constants. | 404 / caller bug |

Check them with `errors.Is`. Error texts never contain key material, so they are safe to log next to a user ID.

## Wiring it into your feature

Declare the small interface you need in **your** package (CONTRIBUTING: consumers declare interfaces), and take it
in your constructor or a `WithKeys` setter, like `auth` and `profile` do:

```go
// in internal/share (example)
type publicKeys interface {
	PublicKey(ctx context.Context, userID bson.ObjectID, p keypair.Purpose) (*rsa.PublicKey, error)
}
```

`cmd/server/main.go` already builds the service as `keySvc`. Pass it to your constructor there. In tests, use a fake
that implements your interface; you don't need MongoDB or real keys.

## Rules (please don't break these)

1. **Ask for the password for every action that needs a private key**, and call `Unlock` in that request. Don't
   store the password, the unlocked key or anything derived from them in the session, a cookie, a hidden form field,
   a log, the database or a package-level variable. Use the key, then let it go (D44).
2. **Rate-limit your password forms.** Each unlock attempt is a password guess. Reuse the idea of auth's per-IP
   limiter (D29).
3. **Use the right purpose.** OAEP encryption: `Encryption`. Signatures: `Signing`.
4. **Always look keys up by user ID through the service.** Never read the `keypairs` collection directly: the service
   checks the public-key MAC (D42), and that check is what stops a swapped key.
5. **Never log** keys, PEMs of private keys, passwords or share keys. Log user IDs and purposes.
6. **Show fingerprints**, so users can compare them over WhatsApp or email when they exchange share keys. That is the
   defence against the server itself serving a wrong public key (D42 trade-offs).

## Recipes

### A2: encrypt a share key to the requester (`feature/share-keys`)

```go
pub, err := keys.PublicKey(ctx, requesterID, keypair.Encryption)
if err != nil { /* ErrNoKeys: requester has no keys yet */ }
ct, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, shareKey, []byte("securestore/share-key/v1"))
```

- A 3072-bit key with SHA-256 OAEP takes at most 384 − 2·32 − 2 = **318 bytes** of plaintext. A 32-byte AES key
  fits easily.
- The label (last argument) is optional. If you use one, pick a fixed string for your feature and use the same one
  when decrypting. It stops a ciphertext made for another purpose being accepted.
- Decrypting on the requester's side:
  `priv, err := keys.Unlock(ctx, me.ID, passwordFromForm, keypair.Encryption)`, then
  `rsa.DecryptOAEP(sha256.New(), nil, priv, ct, label)`.

### A3: sign and verify a PDF (`feature/pdf-sign-core`)

```go
priv, err := keys.Unlock(ctx, me.ID, passwordFromForm, keypair.Signing)   // signer
pub,  err := keys.PublicKey(ctx, signerID, keypair.Signing)              // verifier, no password
```

The signing and verification logic itself must be our own (assignment rule): the library may only do key
generation, hashing, raw encryption and PDF reading/writing. This package deliberately has no `Sign`/`Verify`.
`priv.N`, `priv.D` and `pub.N`, `pub.E` are what your own code works with.

### Show or export a public key

`Info(ctx, userID)` gives display data. `GET /keys/encryption/public.pem` and `GET /keys/signing/public.pem` already
download the **logged-in user's** own public key. For another user's key, call `PublicKey` and then
`keypair.PublicKeyPEM`.

### Change password (whoever adds it)

In the same request, after verifying the old password and **before** storing the new hash:

```go
if err := keys.Rewrap(ctx, user.ID, oldPassword, newPassword); err != nil { /* don't change the password */ }
```

If the user has no keys yet (`ErrNoKeys`), just change the password; their keys will be created at the next login.
A forgotten password can't be recovered: the private keys are lost with it (D44).

## Stored format (for the report and for debugging)

One document per user in the `keypairs` collection (unique `user_id`):

```text
{ _id, user_id, version: 1, created_at,
  kdf:        { alg: "argon2id", v: 19, t: 3, m: 65536, p: 2, salt: <16 B, not the password-hash salt> },
  encryption: { public_der: <PKIX DER>, fingerprint: <SHA-256(public_der)>, created_at,
                public_mac: <HMAC-SHA256 under DeriveKey(MASTER_KEY, "keypair-public-mac")>,
                wrapped_private: <nonce 12 B || AES-256-GCM(KEK, PKCS#8 DER) || tag 16 B> },
  signing:    { …same… } }

KEK = Argon2id(password, kdf.salt, t, m, p, 32 B)            never stored
GCM associated data = len‖"securestore/keypair/v1" ‖ len‖user_id ‖ len‖purpose ‖ len‖fingerprint
```

How to inspect it in the running app: [api.md](api.md) §5.7.
