# Share Requests Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a user request access to another user's private data, and let the owner approve (creating the share
key through a `Granter`), reject, revoke or let it expire. This is Assignment 2, part 1.

**Architecture:** New feature package `internal/sharing` (model → store → service → handlers) with a new
`share_requests` collection. Status transitions are conditional MongoDB updates (compare-and-set), and expiry is
computed from `expires_at` on every read. Share-key crypto lives behind the `Granter` interface, which Kenzie's
`feature/share-keys` implements. Until then `main.go` wires a stub.

**Tech Stack:** Go 1.27, Gin, `html/template` + htmx, MongoDB Go driver v2.

**Spec:** `docs/superpowers/specs/2026-11-28-share-requests-design.md`. Read it first. §6 is the contract with Kenzie.

## Global Constraints

- CONTRIBUTING.md applies: Gin only in `handlers.go`/`routes.go`, consumers declare small unexported interfaces,
  thin handlers, table-driven tests covering failure paths, no `math/rand`, never log user text, keys or passwords.
- Every query that loads a request filters on `_id` **and** the acting user's field. Not party = `ErrNotFound` (404).
- Constants (exact): `PendingLifetime = 7 * 24 * time.Hour`; durations allowlist `"1d"`, `"7d"`, `"30d"`, default
  `"7d"`; `MaxPendingOutgoing = 20`; send limit 10 per requester per hour; `MaxReasonRunes = 200`;
  `ListLimit = 100`.
- Stored statuses (exact strings): `pending`, `approved`, `rejected`, `cancelled`, `revoked`, `expired`.
- Collection name `share_requests`, constant `mongodb.ShareRequestsCollection`.
- Decision numbers D53–D57 only.
- Commit messages: Conventional Commits, `feat(sharing): …`, `docs(sharing): …`. Stage files by path, never
  `git add .`. End each message with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Before each commit: `gofmt -l .` prints nothing, and `go vet ./...` and `go test -race ./internal/sharing/...` pass.

## Review Focus

1. **Approve clicked after the request lapsed** (page open for days): returns `ErrExpired` → 409, and no share
   material is left behind. Test: `TestApproveExpiredBetweenLoadAndClick` (Task 3).
2. **Double-clicked Approve:** one succeeds, the other gets `ErrNotPending`, and the winner's material is **not**
   destroyed. Test: `TestApproveLostRaceToApproveKeepsMaterial` (Task 3).
3. **Username typed as `"  Rayen "`**, or your own name in another case: it is normalised with
   `auth.NormalizeUsername`, so it finds `rayen`, and the self-request check also uses the normalised name. Test:
   rows in `TestSend` (Task 2).
4. **Asking again after a rejection, cancellation or expiry** is allowed. Only `pending` or unexpired `approved` block
   a new request. Test: rows in `TestSend` (Task 2).
5. **A reason containing `<script>`** is shown escaped in the inbox. Test: `TestSharesTemplate` (Task 4).

---

### Task 0: Go toolchain

Go isn't installed in this WSL distro. Needs the user's OK, because it downloads from go.dev.

- [ ] **Step 1:** Install Go 1.27.1 for the user only: download `go1.27.1.linux-amd64.tar.gz` from
  `https://go.dev/dl/`, check its SHA-256 against the value on that page, extract to `~/sdk/go1.27.1`, and put
  `~/sdk/go1.27.1/bin` on `PATH` for this session.
- [ ] **Step 2:** Baseline on the untouched branch: `go vet ./... && go test -race ./...`. Expected: all `ok`. If
  anything fails here, stop and report it, because it's not ours.

### Task 1: Model, statuses, durations, errors

**Files:**
- Create: `internal/sharing/request.go`, `internal/sharing/errors.go`
- Test: `internal/sharing/request_test.go`

**Interfaces:**
- Produces:
  - `type Status string` with constants `StatusPending`, `StatusApproved`, `StatusRejected`, `StatusCancelled`,
    `StatusRevoked`, `StatusExpired`.
  - `type Request struct`, exactly the fields and bson tags in spec §5.2.
  - `func (r *Request) EffectiveStatus(now time.Time) Status`: `pending`/`approved` with `!now.Before(r.ExpiresAt)`
    → `StatusExpired`. Otherwise it returns the stored status.
  - `func (r *Request) Open(now time.Time) bool`: effective status is pending or approved.
  - `func ParseDuration(s string) (time.Duration, error)`: `"1d"`→24h, `"7d"` or `""`→168h, `"30d"`→720h.
    Anything else gives `ErrBadDuration`.
  - The constants from Global Constraints.
  - Exported errors in `errors.go`: `ErrUserNotFound`, `ErrSelfRequest`, `ErrAlreadyOpen`, `ErrTooManyPending`,
    `ErrRateLimited`, `ErrNotFound`, `ErrNotPending`, `ErrNotApproved`, `ErrExpired`, `ErrBadDuration`,
    `ErrRequesterKeys`, `ErrReasonTooLong`, `ErrGrant`. Texts are prefixed `"sharing: "`.

- [ ] **Step 1: Write the failing tests:**
  - `TestEffectiveStatus` (table): pending at `ExpiresAt-1ns` → pending; pending at exactly `ExpiresAt` → expired;
    approved at `ExpiresAt+1s` → expired; rejected/cancelled/revoked/expired past `ExpiresAt` → unchanged.
  - `TestParseDuration` (table): `"1d"`, `"7d"`, `"30d"` and `""` map as above; `"2d"`, `"7D"`, `"-1d"` and `"7d "`
    give `ErrBadDuration` (`errors.Is`).
- [ ] **Step 2:** `go test ./internal/sharing/ -run 'TestEffectiveStatus|TestParseDuration'`. Expected: FAIL (no
  package).
- [ ] **Step 3:** Implement `request.go` and `errors.go` as in Interfaces.
- [ ] **Step 4:** Same command. Expected: PASS.
- [ ] **Step 5:** Commit `feat(sharing): add share request model, statuses and durations`.

### Task 2: Store, index and service part 1 (send, lists, lazy expiry, rate limit)

**Files:**
- Create: `internal/sharing/store.go`, `internal/sharing/service.go`, `internal/sharing/ratelimit.go`,
  `internal/sharing/export_test.go`, `internal/sharing/fakes_test.go`
- Modify: `internal/platform/mongodb/indexes.go` (constant + 3 indexes)
- Test: `internal/sharing/service_test.go`

**Interfaces:**
- Consumes: everything from Task 1.
- Produces:
  - `type transition struct { ID, ActorID bson.ObjectID; Actor string /* "owner_id" | "requester_id" */; From, To Status; Now time.Time; RequireUnexpired bool; DecidedAt, ExpiresAt, EndedAt *time.Time }`
  - `requestStore` interface (in `service.go`), implemented by `*Store` (`store.go`) and by `memStore`
    (`fakes_test.go`):
    - `Insert(ctx, *Request) error`: duplicate key on `open_pair_unique` → `ErrAlreadyOpen`. Sets `r.ID`.
    - `Find(ctx, id bson.ObjectID, actor string, actorID bson.ObjectID) (*Request, error)` → `ErrNotFound`.
    - `List(ctx, actor string, actorID bson.ObjectID, limit int) ([]Request, error)`: newest `created_at` first.
    - `CountPending(ctx, requesterID bson.ObjectID, now time.Time) (int, error)`: `status=pending`,
      `expires_at>now`.
    - `ListLapsed(ctx, requesterID, ownerID bson.ObjectID, now time.Time) ([]Request, error)`: status
      pending/approved and `expires_at<=now`, for that pair.
    - `Transition(ctx, transition) (bool, error)`: one `UpdateOne`. The filter is `_id`, `Actor`=`ActorID` and
      `status`=`From`, plus `expires_at > Now` when `RequireUnexpired`. It `$set`s `status` and the non-nil time
      fields. Returns whether it matched.
  - `NewStore(coll *mongo.Collection) *Store`.
  - `type Granter interface { Grant(ctx context.Context, g Grant) error; Destroy(ctx context.Context, requestID bson.ObjectID) error }`
    and `type Grant struct { RequestID, OwnerID, RequesterID bson.ObjectID; ExpiresAt time.Time }`, exported (spec
    §6.1).
  - `userLookup` interface: `FindByUsername(ctx, username string) (*auth.User, error)`. `auth.ErrUserNotFound` →
    `ErrUserNotFound`.
  - `keyInfo` interface: `Info(ctx, userID bson.ObjectID) ([]keypair.Info, error)`.
  - `func NewService(store requestStore, users userLookup, keys keyInfo, g Granter) *Service`. `now` defaults to
    `time.Now`, and the limiter is 10 per hour keyed by requester ID hex.
  - `type View struct { Request; Status Status /* effective */; Fingerprint string; KeyProblem bool }`
  - `func (s *Service) Send(ctx, requester *auth.User, ownerUsername, reason string) (*Request, error)`
  - `func (s *Service) Inbox(ctx, ownerID bson.ObjectID) ([]View, error)`: fills `Fingerprint` from the requester's
    `keypair.Encryption` Info for rows whose effective status is pending. Any Info error sets `KeyProblem`.
  - `func (s *Service) Sent(ctx, requesterID bson.ObjectID) ([]View, error)`
  - `export_test.go`: `func (s *Service) SetClock(f func() time.Time)`.

**Order of checks in `Send` (it determines the tests):** trim the reason and check it's at most 200 runes
(`ErrReasonTooLong`) → normalise the username, and if it's empty → `ErrUserNotFound` → self (normalised name equal to
`requester.Username`, or equal ID) → `ErrSelfRequest` → rate limiter → `ErrRateLimited` → lookup →
`CountPending >= 20` → `ErrTooManyPending` → `expireLapsed(pair)` → Insert with
`ExpiresAt = now + PendingLifetime` → `ErrAlreadyOpen` on a duplicate.

**`expireLapsed`:** for each lapsed request, `Transition` it to `expired` (`From` = its stored status,
`EndedAt = &r.ExpiresAt`, `Actor` `"owner_id"`). If it was approved and the transition matched, call
`Granter.Destroy`. Errors are logged with the request ID and never returned. `Inbox` runs the same marking on its
loaded rows whose stored status is open but whose effective status is expired.

**`memStore`** enforces the open-pair uniqueness the same way the partial index does: no two pending/approved rows
with the same pair, regardless of expiry, like MongoDB.

**Indexes** to add under `ShareRequestsCollection`:
- `open_pair_unique`: `{requester_id:1, owner_id:1}`, unique, with
  `SetPartialFilterExpression(bson.D{{"status", bson.D{{"$in", bson.A{"pending","approved"}}}}})`
- `owner_created`: `{owner_id:1, created_at:-1}`
- `requester_created`: `{requester_id:1, created_at:-1}`

- [ ] **Step 1: Write the failing tests** in `service_test.go`, with `memStore`, a fake `userLookup` (users
  `vinno`, `rayen`, `kenzie`), a fake `keyInfo` and a recording fake `Granter`:
  - `TestSend` (table, each row says which `errors.Is` it expects, or success):
    - `"rayen"` OK: status pending, `ExpiresAt == now+168h`, reason stored trimmed.
    - `"  Rayen "` OK, with `OwnerName=="rayen"`.
    - `"vinno"` and `"VINNO"` from vinno → `ErrSelfRequest`.
    - `"nobody"` → `ErrUserNotFound`. `""` → `ErrUserNotFound`.
    - Reason of 201 runes (`strings.Repeat("é", 201)`) → `ErrReasonTooLong`. 200 runes OK.
    - A second send to rayen while the first is pending → `ErrAlreadyOpen`.
    - A send after the earlier one was rejected, cancelled, or approved-but-expired → OK. In the expired-approved
      case, the old row is now stored `expired` and `Destroy` was called once with its ID.
  - `TestSendPendingCap`: 20 pending to 20 distinct users is OK, and the 21st → `ErrTooManyPending`. (Raise the
    limiter in the test via the clock: advance by 1h every 10 sends.)
  - `TestSendRateLimit`: the 11th send within an hour → `ErrRateLimited`, and after advancing the clock 1h it's OK.
  - `TestInboxAndSent`: owner sees only rows where they're the owner, requester only theirs, newest first. A pending
    row shows the fingerprint, and a fake Info error gives `KeyProblem==true` and an empty fingerprint. A stored
    approved row past expiry shows `Status==StatusExpired`, is stored `expired` afterwards, and Destroy was called.
- [ ] **Step 2:** `go test ./internal/sharing/`. Expected: FAIL (undefined: `NewService`, …).
- [ ] **Step 3:** Implement `store.go`, `service.go` (`NewService`, `Send`, `Inbox`, `Sent`, `expireLapsed`),
  `ratelimit.go` (copy auth's fixed-window limiter, `internal/auth/ratelimit.go`, with its own `now`) and the index
  entries.
- [ ] **Step 4:** `go test -race ./internal/sharing/ && go vet ./...`. Expected: PASS.
- [ ] **Step 5:** Commit `feat(sharing): send share requests and list inbox and sent requests`.

### Task 3: Service part 2: approve, reject, revoke, cancel, Active

**Files:**
- Create: `internal/sharing/decide.go`
- Test: `internal/sharing/decide_test.go`

**Interfaces:**
- Consumes: Task 2's store, `Granter` and `Service`.
- Produces:
  - `func (s *Service) Approve(ctx, ownerID, requestID bson.ObjectID, duration string) (*Request, error)`
  - `func (s *Service) Reject(ctx, ownerID, requestID bson.ObjectID) error`
  - `func (s *Service) Revoke(ctx, ownerID, requestID bson.ObjectID) error`
  - `func (s *Service) Cancel(ctx, requesterID, requestID bson.ObjectID) error`
  - `func (s *Service) Active(ctx, requestID, requesterID bson.ObjectID) (*Request, error)`

**Rules:**
- Load with `Find` using the actor's field. If the effective status is expired → `ErrExpired`. If it's the wrong
  state → `ErrNotPending` (approve, reject, cancel) or `ErrNotApproved` (revoke, Active).
- **Approve:** `ParseDuration` first (`ErrBadDuration`). Then `keys.Info(requesterID)` errors → `ErrRequesterKeys`.
  `exp := now+d`. `Grant` error → `fmt.Errorf("%w: %v", ErrGrant, err)` and the request stays pending.
  `Transition(pending→approved, RequireUnexpired, DecidedAt=now, ExpiresAt=exp)`. If it doesn't match, re-`Find`.
  If the request is now approved → `ErrNotPending` with **no** Destroy. Otherwise Destroy, then `ErrExpired` if its
  effective status is expired, else `ErrNotPending`.
- **Reject:** pending→rejected, `DecidedAt=now`, `RequireUnexpired`. **Cancel:** pending→cancelled, actor
  `requester_id`, `EndedAt=now`, `RequireUnexpired`.
- **Revoke:** approved→revoked, `EndedAt=now`, `RequireUnexpired`. Then Destroy. A Destroy error is logged, and
  Revoke still returns nil.
- A transition that doesn't match in reject, cancel or revoke → re-`Find` and return `ErrExpired` or the wrong-state
  error to match.

- [ ] **Step 1: Write the failing tests** (table-driven where the shape repeats):
  - `TestApprove`: OK gives stored approved, `ExpiresAt==now+24h` for `"1d"`, Grant called once with the right IDs
    and expiry, and no Destroy. `"2d"` → `ErrBadDuration` with no Grant. Info error → `ErrRequesterKeys` with no
    Grant. Grant error → `ErrGrant` and still pending. Not the owner (requester's ID, a stranger's ID, an unknown
    request ID) → `ErrNotFound`. Already rejected → `ErrNotPending`.
  - `TestApproveExpiredBetweenLoadAndClick`: memStore hook advances the clock past `ExpiresAt` between `Find` and
    `Transition` → `ErrExpired`, Destroy called once, stored status not approved.
  - `TestApproveLostRaceToApproveKeepsMaterial`: hook flips the stored row to approved before `Transition` →
    `ErrNotPending`, Destroy **not** called.
  - `TestApproveLostRaceToCancel`: hook sets it to cancelled → `ErrNotPending`, Destroy called once.
  - `TestReject`, `TestCancel`: OK; wrong actor → `ErrNotFound`; approved → `ErrNotPending`; lapsed → `ErrExpired`.
  - `TestRevoke`: OK, then Destroy called; Destroy error still gives nil and stored revoked; pending →
    `ErrNotApproved`; requester tries → `ErrNotFound`.
  - `TestActive` (table): approved+unexpired → returns it; approved at exactly `ExpiresAt` → `ErrExpired`;
    pending/rejected/revoked/cancelled → `ErrNotApproved`; owner's ID as requester → `ErrNotFound`.
- [ ] **Step 2:** `go test ./internal/sharing/ -run 'TestApprove|TestReject|TestCancel|TestRevoke|TestActive'`.
  Expected: FAIL.
- [ ] **Step 3:** Implement `decide.go` per Rules. Add the before-`Transition` hook to `memStore` (test-only field).
- [ ] **Step 4:** `go test -race ./internal/sharing/`. Expected: PASS.
- [ ] **Step 5:** Commit `feat(sharing): approve, reject, revoke and cancel with compare-and-set transitions`.

### Task 4: Handlers, routes, page and nav link

**Files:**
- Create: `internal/sharing/handlers.go`, `internal/sharing/routes.go`, `internal/web/templates/shares.html`
- Modify: `internal/web/templates/layout.html:36-38` (nav: add `<a href="/shares">Data sharing</a>` after "My
  application"), `internal/web/templates_test.go` (add `TestSharesTemplate`, register page in the CSP-safety list if
  it enumerates pages)
- Test: `internal/sharing/handlers_test.go` (package `sharing_test`, engine built like
  `internal/profile/handlers_test.go:85-97`)

**Interfaces:**
- Consumes: the service methods from Tasks 2–3.
- Produces: `func NewHandler(svc *Service) *Handler`, and `RegisterRoutes(_, protected *gin.RouterGroup)` with the
  six routes in spec §5.6.

**Behaviour:**
- `:id` is parsed with `bson.ObjectIDFromHex`. A parse failure → 404 page.
- On success, redirect 303 to `/shares?done=<code>`, with `<code>` one of `sent`, `approved`, `rejected`, `revoked`,
  `cancelled`. `GET /shares` maps the code through a fixed map to a success `auth.Flash`. Unknown codes are ignored.
  The same idea as `auth/flash.go`, where a forged value can only show fixed text.
- Errors re-render `shares.html` with the inbox and sent lists and an error flash. Status and message per error:

| Error | Status | Message |
|---|---|---|
| `ErrUserNotFound` | 404 | "No user with that username." |
| `ErrSelfRequest` | 400 | "You can't request your own data." |
| `ErrReasonTooLong` | 400 | "Keep the reason under 200 characters." |
| `ErrBadDuration` | 400 | "Choose 1, 7 or 30 days." |
| `ErrAlreadyOpen` | 409 | "You already have an open request to this user." |
| `ErrTooManyPending` | 409 | "You have 20 pending requests. Wait for answers or cancel some." |
| `ErrNotPending`, `ErrNotApproved` | 409 | "That request has already been answered." |
| `ErrExpired` | 409 | "That request has expired." |
| `ErrRequesterKeys` | 409 | "The requester's public key couldn't be verified, so no share key was made." |
| `ErrGrant` | 500 | "Couldn't create the share key. Please try again." |
| `ErrRateLimited` | 429 | "Too many requests. Try again in an hour." |
| `ErrNotFound` | 404 | "We couldn't find that request." |
| other | 500 | "Something went wrong on our side. Please try again." |

- Template data keys: `Title` ("Data sharing"), `User`, `Flash`, `Inbox []sharing.View`, `Sent []sharing.View`,
  `Durations` (ordered `[]struct{Value, Label string}` for 1/7/30 days, 7 selected), plus `JustLoggedIn` like the
  other pages.
- Page layout as in spec §5.6. Approve, Reject and Revoke forms are shown only on rows whose effective status allows
  them, and Cancel only on pending sent rows. Reject and Revoke get `hx-post` + `hx-confirm` (the pattern in
  `files.html:52`). For `HX-Request: true`, the handler answers 204 with `HX-Redirect: /shares?done=…` instead of
  303. Show times as `02 Jan 2006 15:04`.

- [ ] **Step 1: Write the failing tests:**
  - `TestSharesRoutes` (table over method, path and form → status and `Location`). Cases: GET `/shares` 200;
    POST send OK → 303 `/shares?done=sent`; unknown user → 404 with the message in the body; approve with
    `duration=2d` → 400; approve by non-owner → 404; `/shares/requests/nothex/approve` → 404; reject with
    `HX-Request: true` → 204 + `HX-Redirect`; `?done=bogus` shows no flash.
  - `TestSharesTemplate` (in `internal/web/templates_test.go`, `pageCase` style): an inbox row with reason
    `<script>x</script>` renders `&lt;script&gt;`, the fingerprint is shown, the approve form has a
    `name="duration"` select with `7d` selected, and the sent approved row shows the expiry and no Cancel.
- [ ] **Step 2:** `go test ./internal/sharing/ ./internal/web/`. Expected: FAIL.
- [ ] **Step 3:** Implement the handlers, routes, template and nav link.
- [ ] **Step 4:** `go test -race ./internal/sharing/ ./internal/web/ && gofmt -l .`. Expected: PASS and no output.
- [ ] **Step 5:** Commit `feat(sharing): data sharing page with request, approve, reject, revoke and cancel`.

### Task 5: Wiring in `main.go`

**Files:**
- Modify: `cmd/server/main.go` (after `keySvc` and `authSvc` are built, and in `Features`)
- Create: `internal/sharing/stub.go`

**Interfaces:**
- Produces: `type StubGranter struct{}` with `Grant`/`Destroy` returning nil after
  `slog.Warn("sharing: share-keys not wired yet", "request_id", …)`, marked `// TODO(feature/share-keys): replace
  with the real Granter.`

- [ ] **Step 1:** Wire `shareSvc := sharing.NewService(sharing.NewStore(db.Collection(mongodb.ShareRequestsCollection)), auth.NewStore(db.Collection(mongodb.UsersCollection)), keySvc, sharing.StubGranter{})`,
  reusing the existing users store variable if you can hoist one, and add `sharing.NewHandler(shareSvc)` to
  `Features`.
- [ ] **Step 2:** `go build ./... && go vet ./... && go test -race ./...`. Expected: all pass.
- [ ] **Step 3: Smoke test** (needs Docker Desktop's WSL integration on; if it's off, say so and skip): `make up`,
  register `alice` and `bob` in two browsers, alice requests bob, bob sees the fingerprint and approves for 1 day,
  alice sees approved with an expiry, bob revokes, and alice sees revoked. Check
  `docker compose logs app | grep share-keys` shows the stub warnings and no reason text.
- [ ] **Step 4:** Commit `feat(sharing): wire share requests into the server with a stub granter`.

### Task 6: Docs

**Files:**
- Modify: `docs/decisions.md` (new section "Share requests (`feature/share-requests`)" with D53–D57 in the existing
  Decision/Alternatives/Why/Trade-offs shape: D53 one request covers all data; D54 time-based lazy expiry; D55
  compare-and-set and Grant-before-approve, including the double-click rule; D56 one open request per pair through a
  partial unique index; D57 ID-scoped 404s and the accepted username-existence trade-off), `docs/api.md` (the six
  routes with their test cases, in that file's existing format), `README.md` (status line, plus
  `internal/sharing/` in the code layout and the branches table)
- Create: `docs/sharing.md`, a guide for Kenzie in the style of `docs/keypairs.md`: what `Granter` must do and its
  idempotency, when `Grant`/`Destroy` are called (spec §6.2), "call `Active` on every open", how to swap the stub in
  `main.go`, and where the "Open data" and "Show encrypted key" links go in `shares.html`.

- [ ] **Step 1:** Write the docs. Every claim must match the code as merged: names, constants, status codes.
- [ ] **Step 2:** `grep -n 'D5[3-7]' docs/decisions.md` shows five headings, and every route in `routes.go` appears
  in `docs/api.md`.
- [ ] **Step 3:** Commit `docs(sharing): decisions D53–D57, API routes and a guide for share-keys`, including the
  spec and this plan.
