# Share requests: how `feature/share-keys` plugs into `internal/sharing`

For `feature/share-keys` (Kenzie). `internal/sharing` decides **who may see whose data, and until when**. Your
branch decides **how the data is opened**. The reasons behind every choice are in [decisions.md](decisions.md)
D53–D57, and the full design is in
[superpowers/specs/2026-11-28-share-requests-design.md](superpowers/specs/2026-11-28-share-requests-design.md).

## The flow

```text
requester (alice)                 owner (bob)                         your package
─────────────────                 ───────────                         ────────────
POST /shares/requests  ──pending──▶ sees it in "Requests to you"
                                    checks alice's fingerprint
                                    POST …/approve (1/7/30 days) ──▶ Granter.Grant(...)   make share key,
                                                                                        re-wrap DEKs, RSA-OAEP
                                                                                        to alice's public key
                                  ◀── status becomes approved ──────  (only if Grant succeeded)
                                    sends the encrypted share key
                                    to alice over WhatsApp/email
alice imports the key and opens bob's data ─────────────────────────▶ your handler calls
                                                                      sharing.Service.Active(...) FIRST
                                    POST …/revoke, or it expires ──▶ Granter.Destroy(requestID)
```

## What you implement: `sharing.Granter`

```go
type Granter interface {
	Grant(ctx context.Context, g sharing.Grant) error
	Destroy(ctx context.Context, requestID bson.ObjectID) error
}

type Grant struct {
	RequestID   bson.ObjectID // key your stored material by this
	OwnerID     bson.ObjectID // whose data: their profile and all their files
	RequesterID bson.ObjectID // whose public encryption key to encrypt the share key to
	ExpiresAt   time.Time     // when access ends; you may store it, but Active is the authority
}
```

- **`Grant`** is called when the owner clicks Approve, **before** the status changes. Return an error and the
  request stays pending, and the owner sees "Couldn't create the share key. Please try again." It must be
  **idempotent per `RequestID`**: a retry replaces or reuses the earlier material and never leaves two.
- **No password is passed.** Encrypting to the requester's public key (`keypair.Service.PublicKey(ctx, RequesterID,
  keypair.Encryption)`) and unwrapping the owner's DEKs with the master key need no private key of the owner's. If
  your design needs the owner's password, tell Vinno: the approve form and `Grant` change together.
- **`Destroy`** deletes everything you stored for that request. Deleting nothing is not an error. It's called after
  revoke, when an approved request is found expired, and when an approve loses a race to a cancel or reject. A
  failure is only logged, so don't rely on it for security: rely on `Active`.

## What you call: `sharing.Service.Active`

```go
req, err := shareSvc.Active(ctx, requestID, me.ID) // me = the logged-in requester
switch {
case err == nil:                           // approved and unexpired right now: open req.OwnerID's data
case errors.Is(err, sharing.ErrNotFound):  // unknown ID, or not this user's request → 404
case errors.Is(err, sharing.ErrExpired):   // → 403/409 "This access has expired."
case errors.Is(err, sharing.ErrNotApproved): // pending, rejected, cancelled or revoked → 403/409
}
```

**Call it on every request that opens or downloads shared data**, not only at import. That check is what makes
revoke and expiry take effect immediately. Declare a small interface for it in your package (CONTRIBUTING).

## Wiring

In `cmd/server/main.go`, replace the stub:

```go
// TODO(feature/share-keys): pass the real Granter instead of the stub.
shareSvc := sharing.NewService(sharing.NewStore(…), users, keySvc, sharing.StubGranter{})
```

with your `Granter`, pass `shareSvc` (as your `Active` interface) to your handler, and delete
`internal/sharing/stub.go`.

## Where your links go

`internal/web/templates/shares.html` has two places for your UI:

- **Owner, "Requests to you", approved rows:** add a "Show encrypted key" link next to Revoke, so the owner can
  copy the share key into WhatsApp.
- **Requester, "Your requests", approved rows:** add an "Import key / open data" link.

Each row is a `sharing.View`: `.ID.Hex` is the request ID, and `.Status` is the effective status (`"approved"` only
while access is valid).

## Rules

1. Never open shared data without a successful `Active` in the same HTTP request.
2. Never log share keys, DEKs or the request's `Reason` (user text). Log request and user IDs.
3. Show the requester's encryption-key fingerprint wherever the key changes hands; the inbox already shows it before
   approval.
