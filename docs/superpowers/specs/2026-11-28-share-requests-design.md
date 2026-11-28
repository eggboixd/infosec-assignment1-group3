# Share requests (`feature/share-requests`): design

Status: draft for approval · Owner: Vinno · Date: 2026-11-28 · Deadline: 2026-12-02

## 1. Intent

Assignment 2 (Key Management) requires:

1. A user can request to see the private data of other users (including the images and documents).
2. The requested user generates a symmetric key to share the data with the requesting user.
3. The symmetric key is distributed to the requester by other means (email, WhatsApp), encrypted with asymmetric
   encryption.
4. The symmetric keys are stored securely in the system.

The team split this work into two branches:

- **`feature/share-requests` (this design, Vinno):** requirement 1, plus the lifecycle around access: sending a
  request, the owner's inbox, approving and rejecting, expiry and revoking.
- **`feature/share-keys` (Kenzie):** requirements 2–4: generating the share key, re-wrapping the owner's DEKs under it,
  encrypting the share key with the requester's public encryption key (`keypair.Encryption`, RSA-OAEP-SHA256), storing
  it securely, the requester importing it to open the data, and the A2 report.

This branch decides **who may see whose data, and until when**. Kenzie's branch decides **how the data is
cryptographically opened**. They meet at the contract in §6.

## 2. Goals, non-goals, anti-goals

**Goals**

- A logged-in user (the *requester*) can ask another user (the *owner*) for access to the owner's private data,
  identified by the owner's username.
- One request always covers **all** of the owner's private data: the applicant data (`internal/profile`, six encrypted
  fields) and every uploaded file (`internal/files`: KTP image, documents, video). This follows the brief ("including the
  images and documents").
- The owner sees incoming requests and approves or rejects each one. Approving creates the share key in the same step
  (decision: option (a), see §4).
- Access has an expiry chosen by the owner at approval. Pending requests also expire if nobody answers them.
- The owner can revoke approved access at any time. The requester can cancel a request that is still pending.
- Kenzie's code has one call to ask "is this access valid right now?" and gets a definite answer.

**Non-goals (not in this branch)**

- Any cryptography for the share key: generating it, re-wrapping DEKs, RSA-OAEP, storing it, importing it, opening
  the data. All of that is in `feature/share-keys`.
- Sending email or WhatsApp messages from the app. The owner sends the encrypted share key by hand (brief, requirement 3).
- Partial sharing (choosing fields or files). Not asked for by the brief.
- Notifications, a badge with the pending count in the nav, or editing a request after sending it.
- Admin or committee roles. Every user is equal.
- A change-password flow.

**Anti-goals (would be a failure even if everything else works)**

- Anyone sees an owner's data without the owner approving a request from that exact requester.
- Access keeps working after it expired, was revoked, or was rejected.
- One user can approve, reject, revoke or cancel a request that isn't theirs to act on. This includes guessing request
  IDs.
- A request is shown as approved but no share key exists for it.
- Plaintext private data, share keys or passwords appear in this collection, in logs, or in URLs.

## 3. Constraints from the repo

- Go, Gin, `html/template` + htmx, MongoDB (driver v2). Follow CONTRIBUTING: organise by feature, consumers declare
  small interfaces, Gin only in `handlers.go`/`routes.go`, thin handlers, table-driven tests that also cover failures,
  `make test` and `make lint` (gofmt, vet, `-race`, gosec) pass, no `math/rand`.
- CSRF is already handled globally by `crossOriginProtection` in `internal/web/middleware.go`. Forms need no token.
- Users are identified by `username` (normalised with `auth.NormalizeUsername`). `auth.Store` has `FindByUsername` and
  `FindByID`. There is no user search and none will be added.
- Every user has both key pairs once they've logged in since `feature/keypairs` (D43). `keypair.Service.Info` returns
  the fingerprint of a user's public encryption key without a password.
- Decision numbers: D45–D51 are taken by `feature/pdf-sign-core` and D52 is reserved for its CMS bonus. **This branch
  takes D53–D57.** Tell the team in the group chat so Kenzie and Rayen start after D57.

## 4. Approaches considered

**(a) Approving creates the share key in the same step. CHOSEN.** `sharing.Service.Approve` calls a `Granter`
interface that Kenzie's package implements. `Revoke` (and expiry clean-up) calls `Granter.Destroy`.

- For: the owner clicks once. "Approved" can never exist without a share key. The lifecycle stays in one place.
- Against: Vinno and Kenzie must agree on two method signatures (§6) before both branches can be finished. Until
  Kenzie's branch is merged, `main.go` wires a stub granter (§6.4).

**(b) Separate steps.** Approve only changes the status. The owner then clicks "Create share key" on Kenzie's page.

- For: the two branches are fully independent.
- Against: an extra click, and a request can be approved with no key yet. That state has to be shown and handled
  everywhere. Rejected for that reason.

**(c) Grant a share key on request, with no approval step.** Rejected: the brief says the *requested user* generates
the key, which implies their consent.

Vinno picked (a) on 2026-11-28.

## 5. The design

### 5.1 Package and collection

- New package **`internal/sharing`**: `request.go` (model, status, errors), `store.go`, `service.go`, `handlers.go`,
  `routes.go`, `ratelimit.go`, plus tests. Kenzie's package should use another name (for example `internal/sharekey`)
  so the two don't collide.
- New collection **`share_requests`**, added to `internal/platform/mongodb/indexes.go` as `ShareRequestsCollection`.

### 5.2 The stored request

```go
type Request struct {
    ID          bson.ObjectID `bson:"_id,omitempty"`
    RequesterID bson.ObjectID `bson:"requester_id"`
    OwnerID     bson.ObjectID `bson:"owner_id"`
    // Usernames are copied in for display. They can't change (there is no rename).
    RequesterName string `bson:"requester_name"`
    OwnerName     string `bson:"owner_name"`
    // Reason is optional free text from the requester, max 200 runes, shown to the owner.
    // It's not private data, so it's stored in plaintext. Rendered with html/template escaping.
    Reason    string     `bson:"reason,omitempty"`
    Status    Status     `bson:"status"`     // see 5.3
    CreatedAt time.Time  `bson:"created_at"`
    DecidedAt *time.Time `bson:"decided_at,omitempty"` // approve or reject
    // ExpiresAt is when a pending request lapses (CreatedAt + 7 days), or,
    // once approved, when access ends (DecidedAt + the chosen duration).
    ExpiresAt time.Time  `bson:"expires_at"`
    EndedAt   *time.Time `bson:"ended_at,omitempty"` // revoked, cancelled or marked expired
}
```

Nothing secret is stored here: no share key, no DEK, no private data.

### 5.3 States

Stored status values: `pending`, `approved`, `rejected`, `cancelled`, `revoked`, `expired`.

```
            send
             │
          pending ──reject (owner)──▶ rejected
          │  │  └──cancel (requester)─▶ cancelled
          │  └──now ≥ expires_at──────▶ expired
   approve (owner, Grant ok)
          │
          ▼
        approved ──revoke (owner)─────▶ revoked
          └──now ≥ expires_at─────────▶ expired
```

- **Expiry is decided by time, not by a background job.** Every read computes the *effective* status:
  `pending` or `approved` with `now >= ExpiresAt` is treated as `expired`, even if the stored value still says
  otherwise. So access ends at the exact second, with no lag.
- Stored statuses are then updated lazily to `expired`, with `EndedAt = ExpiresAt`, when the service next touches
  that pair. For approved requests it also calls `Granter.Destroy`.
- Every transition is one conditional `UpdateOne` (compare-and-set on `_id`, the acting user's ID field, the expected
  stored status and `expires_at > now`). Two concurrent clicks can't both win, and an action on a request that just
  expired fails cleanly.
- Records are never deleted. They are the access history for the report.

### 5.4 Rules

| Rule | Value | Why |
|---|---|---|
| Who can be asked | Any existing user except yourself | brief |
| Open requests per pair | At most one `pending` or unexpired `approved` per (requester, owner) | no duplicate inbox entries, no two live share keys for the same pair |
| Pending lifetime | 7 days | inbox doesn't fill with stale requests |
| Access durations the owner can pick | 1 day, 7 days, 30 days (allowlist, default 7) | bounded access; the brief's "securely" |
| Outgoing pending per requester | at most 20 | spam bound |
| Send rate limit | 10 sends per requester per hour, in memory, same design as auth's limiter (D29) | spam and username-probing bound |
| Reason | optional, ≤ 200 runes, trimmed | owner knows who and why |

The one-open-per-pair rule is enforced by a **partial unique index** on `{requester_id, owner_id}` with
`partialFilterExpression: {status: {$in: ["pending","approved"]}}`. Before inserting, `Send` lazily marks any
expired-but-still-stored request for that pair as `expired`, so an old approval that lapsed doesn't block a new
request. A duplicate-key error becomes `ErrAlreadyOpen`.

Other indexes: `{owner_id, created_at: -1}` (inbox) and `{requester_id, created_at: -1}` (sent list).

### 5.5 Service API (plain Go types, no Gin)

```go
func (s *Service) Send(ctx, requester *auth.User, ownerUsername, reason string) (*Request, error)
func (s *Service) Inbox(ctx, ownerID bson.ObjectID) ([]View, error)   // newest first, effective status
func (s *Service) Sent(ctx, requesterID bson.ObjectID) ([]View, error)
func (s *Service) Approve(ctx, ownerID, requestID bson.ObjectID, d Duration) (*Request, error)
func (s *Service) Reject(ctx, ownerID, requestID bson.ObjectID) error
func (s *Service) Revoke(ctx, ownerID, requestID bson.ObjectID) error
func (s *Service) Cancel(ctx, requesterID, requestID bson.ObjectID) error
// For feature/share-keys, see §6.
func (s *Service) Active(ctx, requestID, requesterID bson.ObjectID) (*Request, error)
```

`View` adds the effective status, and in the inbox, the requester's **encryption-key fingerprint** from
`keypair.Service.Info`. The owner can compare it over WhatsApp before approving (keypairs.md rule 6). If the
requester's keys fail their integrity check (`keypair.ErrCorrupt`), the inbox shows a warning, and Approve refuses
with `ErrRequesterKeys`.

Errors (checked with `errors.Is`): `ErrUserNotFound`, `ErrSelfRequest`, `ErrAlreadyOpen`, `ErrTooManyPending`,
`ErrRateLimited`, `ErrNotFound`, `ErrNotPending`, `ErrNotApproved`, `ErrExpired`, `ErrBadDuration`,
`ErrRequesterKeys`.

- **`ErrNotFound` is returned both for an unknown request ID and for a request the caller isn't party to in that
  role.** So request IDs reveal nothing. Each query filters on `_id` **and** the acting user's field (`owner_id` for
  approve, reject and revoke; `requester_id` for cancel and Active).
- **Usernames can be discovered.** "No user with that name" tells a requester that a username doesn't exist. This is
  accepted: the outbox would show it anyway, and the send rate limit bounds probing. It's recorded as a trade-off in
  the decision note.

### 5.6 Pages and routes

One page, **`/shares`** ("Data sharing"), linked in the top nav after "My application". All routes are on the
`protected` group.

```
Data sharing
┌──────────────────────────────────────────────────────────────────────┐
│ Request access to someone's data                                     │
│ Username [__________]  Reason (optional) [____________]  [Send]      │
├──────────────────────────────────────────────────────────────────────┤
│ Requests to you                                                      │
│ rayen · "for the committee review" · 2 days ago · pending            │
│   Their key fingerprint: 1a2b 3c4d … (compare over WhatsApp)         │
│   Access for [7 days ▾]  [Approve]  [Reject]                         │
│ kenzie · approved · expires 5 Dec 14:00              [Revoke]        │
├──────────────────────────────────────────────────────────────────────┤
│ Your requests                                                        │
│ palpal · pending · lapses 5 Dec               [Cancel]               │
│ vinno2 · approved · expires 1 Dec  → (Kenzie's "Open data" link)     │
└──────────────────────────────────────────────────────────────────────┘
```

| Method & path | Who | Effect |
|---|---|---|
| `GET /shares` | any user | the page above |
| `POST /shares/requests` | requester | `Send` (`username`, `reason`) |
| `POST /shares/requests/:id/approve` | owner | `Approve` (`duration` = `1d`/`7d`/`30d`) |
| `POST /shares/requests/:id/reject` | owner | `Reject` |
| `POST /shares/requests/:id/revoke` | owner | `Revoke` |
| `POST /shares/requests/:id/cancel` | requester | `Cancel` |

- Forms POST normally. Success redirects 303 to `/shares` with a flash message, using the existing flash pattern in
  `internal/auth/flash.go` or an equivalent.
- Errors re-render `/shares` with a fixed user-facing message and the right status: 400 bad input, 404 not found,
  409 conflict, 429 rate limited.
- `:id` that isn't a valid ObjectID gives 404.
- htmx is optional. Plain forms are enough for the deadline.
- Revoke and reject ask for confirmation with a plain `confirm` step in the form, implemented by the builder, CSP
  permitting.
- On an approved row, the requester sees a link that Kenzie's branch provides. Until then the row only shows the
  expiry.

### 5.7 Logging

Log request IDs, user IDs, status transitions and error kinds. Never log reasons (user text), share keys or passwords.

## 6. Contract with `feature/share-keys` (agree with Kenzie before coding)

### 6.1 What sharing calls, and Kenzie implements

```go
// Declared in internal/sharing (consumers declare interfaces).
type Granter interface {
    // Grant generates the share key for an approved request, re-wraps the
    // owner's DEKs under it, encrypts it to the requester's public
    // encryption key, and stores what it needs, keyed by g.RequestID.
    // It must be idempotent per RequestID: a retry after a failure replaces
    // or reuses the earlier material, never leaves two.
    Grant(ctx context.Context, g Grant) error
    // Destroy deletes all share material for requestID. Deleting nothing is
    // not an error.
    Destroy(ctx context.Context, requestID bson.ObjectID) error
}

type Grant struct {
    RequestID   bson.ObjectID
    OwnerID     bson.ObjectID
    RequesterID bson.ObjectID
    ExpiresAt   time.Time
}
```

No password is passed. Generating the share key, re-wrapping DEKs (master key, server side) and encrypting to the
requester's *public* key need no private key of the owner's. If Kenzie's design does need the owner's password, the
approve form gains a password field and `Grant` gains `OwnerPassword string`. **Confirm with Kenzie first**, because
it changes the form and the rate limiting.

How Kenzie's code then shows the encrypted share key to the owner, so they can copy it into WhatsApp, is Kenzie's
part. Approve redirects to `/shares`, and Kenzie can add a "Show encrypted key" link on approved inbox rows.

### 6.2 Ordering, so "approved" always has a key

**Approve:**

1. Load the request with `_id` and `owner_id`, effective status `pending`. Otherwise fail.
2. Check that the requester's keys pass `Info`.
3. `Granter.Grant(...)`. If it fails, the request stays `pending` and the owner sees "Couldn't create the share key,
   try again."
4. Compare-and-set `pending → approved` with `DecidedAt` and the new `ExpiresAt`.
5. If step 4 loses, re-read the request. If it is now `approved` (a concurrent approve, such as a double click,
   won), return `ErrNotPending` and **don't** call `Destroy`: that material belongs to the winner, because Grant is
   keyed by request ID. Otherwise (cancelled, rejected or expired in between), call `Granter.Destroy` and return the
   conflict.

Stray material from steps 3–5 is harmless, because Kenzie's open path must also call `Active` (§6.3).

**Revoke:** compare-and-set `approved → revoked` first, which cuts access immediately, then `Destroy`. If `Destroy`
fails, log it. Access is already blocked by `Active`.

**Expiry of an approved request:** `Destroy` is called when the request is lazily marked expired (§5.3). Until then
`Active` already denies it.

### 6.3 What Kenzie calls, and sharing implements

```go
// Active returns the request if requesterID is its requester and it is
// approved and unexpired at this moment. Otherwise ErrNotFound, ErrNotApproved
// or ErrExpired. Call it on EVERY request that opens shared data, not only at
// import time.
func (s *Service) Active(ctx context.Context, requestID, requesterID bson.ObjectID) (*Request, error)
```

Kenzie's import and open handlers must refuse to decrypt anything unless `Active` succeeds. This is the anti-goal
"access keeps working after it expired or was revoked".

### 6.4 Until `feature/share-keys` is merged

`main.go` wires a stub `Granter` that does nothing and logs `"sharing: share-keys not wired yet"`. It's marked
`TODO(feature/share-keys)`, so the whole lifecycle can be demoed and merged. Kenzie's PR replaces that one line.

## 7. Testing

- **Service, table-driven with a fake store, a fake granter, a fake clock and a fake key-info source:** every
  transition and every illegal one, including approve after expiry, revoke of pending, cancel by the owner, and acting
  on someone else's request returning `ErrNotFound`. Also: self-request, unknown user, duplicate open request, a new
  request allowed after the old one expired, Grant failure leaving the request pending, a lost compare-and-set calling
  Destroy, a revoke whose Destroy fails still counting as revoked, a bad duration, the pending cap, the rate limit,
  effective status flipping at exactly `ExpiresAt`, and `Active` for each state.
- **Store:** the compare-and-set filters and the duplicate-key mapping. Use fakes like the other packages. Whether to
  add a Mongo integration test is the builder's call.
- **Handlers (httptest):** auth is required, a bad ObjectID gives 404, status codes per error, redirects, and the page
  renders inbox and sent lists with escaping of `reason`.
- **Templates:** add `/shares` to `internal/web/templates_test.go` like the other pages.

## 8. Docs to update in this branch

- `docs/decisions.md`: a "Share requests" section with D53–D57: one request covers all data; lazy, time-based
  expiry; compare-and-set transitions and the Grant-before-approve ordering; one open request per pair (partial unique
  index); ID-scoped 404s and the accepted username-existence trade-off.
- `docs/api.md`: the six routes and their test cases.
- `docs/sharing.md`: a short guide for Kenzie like `docs/keypairs.md`, covering §6 with examples.
- `README.md`: status line and code layout entry.

## 9. Left to the builder

- Exact template markup and CSS, within the existing pastel style.
- Flash mechanism reuse versus a small local one.
- Whether `Inbox` and `Sent` cap the list length. A cap of 100 with newest first is fine.
- Whether lazy expiry marking happens on page load too, or only in `Send`, `Approve` and `Revoke`.
- Integration test against real MongoDB, or fakes only.
