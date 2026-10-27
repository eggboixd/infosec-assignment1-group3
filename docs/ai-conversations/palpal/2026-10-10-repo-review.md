# Repo review and planning

- Session: `0b67aedb-53e6-47c4-a681-a044a410ef97`
- Started: 2026-10-10 00:08 (WIB, UTC+7)
- Git branch when started: `main`
- Export notes: prompts and replies are verbatim (system reminders and hook context stripped); tool calls are one-line summaries; tool output and hidden reasoning are omitted; secrets are replaced with [REDACTED].

---

_(slash command: `/model`)_

_(slash command: `/model`)_

_(slash command: `/effort`)_

## ðŸ§‘ User

Read CLAUDE.md first, then README.md, CONTRIBUTING.md, everything in docs/, the Makefile,
docker-compose.yml, .env.example, and every package under cmd/ and internal/.
Don't change any files yet. Then explain to me, simply:
1. What this scaffold already does and what is still a stub, folder by folder.
2. Exactly how to run it on my Windows laptop (PowerShell commands, step by step), including the .env setup,
   starting MongoDB + MinIO + the server with Docker, and how to check it's working (health check URL,
   MinIO console URL).
3. Anything in the scaffold that conflicts with CLAUDE.md.
4. The git workflow from CONTRIBUTING.md (branch names, commit style, PR rules).

## ðŸ¤– Claude

I'll start by mapping the repo, then read everything you listed.


- _tool:_ **Bash** List tracked and all files in repo â€” `cd "C:/Users/ASUS/Desktop/kuliah/sem5/tkti/groupassignment1" && git ls-files && echo "--- untracked/`
## ðŸ¤– Claude

The repo is small enough to read in full. Docs and build config first.


- _tool:_ **Bash** Print README, CONTRIBUTING, and docs â€” `cd "C:/Users/ASUS/Desktop/kuliah/sem5/tkti/groupassignment1" && for f in README.md CONTRIBUTING.md d`
- _tool:_ **Bash** Print build, Docker, env, CI config files â€” `cd "C:/Users/ASUS/Desktop/kuliah/sem5/tkti/groupassignment1" && for f in Makefile docker-compose.yml`
## ðŸ¤– Claude

Already seeing a big design difference between the README and CLAUDE.md. Now the Go code: cmd, config, crypto, web.


- _tool:_ **Bash** Print main, config, crypto, platform code â€” `cd "C:/Users/ASUS/Desktop/kuliah/sem5/tkti/groupassignment1" && for f in cmd/server/main.go internal`
- _tool:_ **Bash** Print web and auth package code â€” `cd "C:/Users/ASUS/Desktop/kuliah/sem5/tkti/groupassignment1" && for f in internal/web/*.go internal/`
- _tool:_ **Bash** Print profile, files, benchmark code â€” `cd "C:/Users/ASUS/Desktop/kuliah/sem5/tkti/groupassignment1" && for f in internal/profile/*.go inter`
- _tool:_ **Bash** Print HTML templates â€” `cd "C:/Users/ASUS/Desktop/kuliah/sem5/tkti/groupassignment1" && for f in internal/web/templates/*.ht`
## ðŸ¤– Claude

The first file batch was cut off. Reading it directly.


- _tool:_ **Read** C:\Users\ASUS\.claude\projects\C--Users-ASUS-Desktop-kuliah-sem5-tkti-groupassignment1\0b67aedb-53e6-47c4-a681-a044a410ef97\tool-results\b5u4pisj8.txt
## ðŸ¤– Claude

I've read all of it. Quick read-only check of which tools your laptop already has, so the run steps fit your machine:


- _tool:_ **PowerShell** Check which dev tools are installed â€” `foreach ($t in 'docker','go','make','git','openssl') { $c = Get-Command $t -ErrorAction SilentlyCont`
- _tool:_ **Bash** Check line-ending config and remote â€” `cd "C:/Users/ASUS/Desktop/kuliah/sem5/tkti/groupassignment1" && git config --get core.autocrlf; file`
## ðŸ¤– Claude

Before writing up, I'll confirm the scaffold builds and its tests pass on your machine, and check the line-ending issue I suspect. None of these commands modify files.


- _tool:_ **PowerShell** Run vet, tests, gofmt check, race probe â€” `go vet ./... ; "vet exit: $LASTEXITCODE"; go test ./... ; "test exit: $LASTEXITCODE"; $f = gofmt -l `
## ðŸ¤– Claude

I've read every file you listed. Nothing in the repo was changed. The only things I ran were `go vet` and `go test`, which download modules into Go's cache and don't touch the repo.

**Your machine:** Docker 29.3, Compose v5.1, Go 1.27.2 and git are installed. `make` and `openssl` are not, so I give plain PowerShell commands below. `go vet ./...` and `go test ./...` both pass.

---

## 1. What the scaffold does, and what is still a stub

The app starts, connects to MongoDB and MinIO, and serves a health check. Every other route returns **501 Not Implemented**. Each unfinished piece is marked `TODO(<branch>)`.

| Folder | Already working | Still a stub |
|---|---|---|
| `cmd/server` | Loads config, connects to Mongo (creates indexes) and MinIO (creates bucket), wires all features, shuts down cleanly | Uses `PassthroughEncryptor`, which **does not encrypt**. The NIK blind-index key is `nil` |
| `internal/config` | Reads env vars, collects all errors, refuses to start if any are missing. Requires `MASTER_KEY` (base64, 32 B) and `SESSION_SECRET` (≥32 chars). Secrets are redacted when printed. Tested | — |
| `internal/crypto` | Algorithm names (`aes`/`des`/`rc4`), IV sizes, the `Encryptor` interface, `Meta` / `Sealed` / `SealedSet` types, a `Clock` for timing, `LoadMasterKey` | **The real cipher is missing.** `WrapKey`, `UnwrapKey` and `DeriveKey` return "not implemented". Passthrough copies bytes unchanged |
| `internal/auth` | `User` model, Mongo store with a unique-username error, form validation tags | Register, login, logout, Argon2id hashing and sessions. ⚠️ `RequireAuth` lets **everyone** in as a fake `dev-user` |
| `internal/profile` | `PrivateData` form (6 fields), `Profile` doc with one `SealedSet` per field, Mongo upsert/find | Save/Get, per-field encryption, NIK blind index |
| `internal/files` | 3 kinds (`idcard`/`document`/`video`) with MIME allowlists, `FileRecord`/`Variant` models, Mongo store scoped by owner (IDOR-safe), `ObjectStore` interface | Upload (streaming 3-way encryption), download (verify then decrypt), list, delete. The handler comments sketch the streaming approach |
| `internal/benchmark` | `Record` model, a `Measure()` timer that separates crypto time from total time, Mongo store. Tested | `/benchmarks` page and the CSV export |
| `internal/platform` | Real MinIO client (streamed `Put` with 16 MiB parts, seekable `Get`, `Delete`, `Ping`), Mongo client and indexes (including a TTL index for a `sessions` collection) | — |
| `internal/web` | Gin engine, security headers (CSP, nosniff, DENY framing), body-size limit, embedded templates and static files, `/healthz`. Tested | Templates are bare forms with no data, errors or file list |
| `scripts/bench` | — | README only |
| `docs/` | `architecture.md` with full diagrams of the scaffold's design | `report.md` is headings only. **`docs/decisions.md` does not exist yet** |
| Docker | `app` (distroless, non-root), `mongo:8.0`, `minio` built from source, `minio-init` (creates the bucket). Only the app publishes a port | — |
| CI | On every PR to `main`: gofmt, vet, `test -race`, build, gosec | — |

---

## 2. Running it on your Windows laptop (PowerShell)

I didn't run these, because they need a `.env` file and you asked for no changes.

**Step 1: Start Docker Desktop** and wait until it says "running". Then open PowerShell:
```powershell
cd C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1
```

**Step 2: Create `.env`**
```powershell
Copy-Item .env.example .env
```

**Step 3: Generate two random keys.** This replaces `make gen-key` and uses a secure random generator:
```powershell
function New-Key { $b = New-Object byte[] 32; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); [Convert]::ToBase64String($b) }
New-Key   # copy into MASTER_KEY
New-Key   # copy into SESSION_SECRET
```

**Step 4: Edit `.env`** with `notepad .env` or `code .env`:
- Paste the two keys over the `REPLACE_ME` values.
- Change `MONGO_ROOT_PASSWORD`. Use only letters and digits, because it goes inside a URL.
- Change `MINIO_ROOT_PASSWORD` (at least 8 characters).
- Copy the same passwords into `MONGO_URI` and `MINIO_SECRET_KEY` at the bottom. Those two lines only matter when running Go outside Docker, but keep them in sync.

**Step 5 (optional, needed for the MinIO console):** expose Mongo and MinIO on `127.0.0.1`:
```powershell
Copy-Item docker-compose.override.yml.example docker-compose.override.yml
```

**Step 6: Build and start everything.** The first build compiles MinIO from source and takes several minutes:
```powershell
docker compose up --build -d
docker compose ps
```
Expected: `mongo` and `minio` show **healthy**, `minio-init` shows **Exited (0)**, and `app` shows **running**.

**Step 7: Check that it works**
```powershell
curl.exe http://localhost:8080/healthz
# {"status":"ok","checks":{"minio":"ok","mongodb":"ok"}}
```
- Use `curl.exe`, not `curl`: in PowerShell 5.1 plain `curl` is an alias for `Invoke-WebRequest`.
- `http://localhost:8080/login` in a browser shows "not implemented". That is expected for now.
- **MinIO console:** `http://127.0.0.1:9001`. Log in with `MINIO_ROOT_USER` / `MINIO_ROOT_PASSWORD`[REDACTED]`securestore` bucket. This only works after Step 5.

**Day-to-day commands**
```powershell
docker compose logs -f app      # follow app logs
docker compose down             # stop, keep data
docker compose down -v          # stop AND wipe Mongo/MinIO data
```

**Gotchas specific to Windows**
- **Changing passwords:[REDACTED] Mongo and MinIO only read their root password the first time their data volume is created. If you change a password in `.env` later, run `docker compose down -v` first.
- **Race detector:** `go test -race` fails on your laptop (`cc1.exe: 64-bit mode not compiled in`, because your C compiler is 32-bit). Plain `go test ./...` works. To run the race check like CI does, use Docker:
  ```powershell
  docker run --rm -v "${PWD}:/src" -w /src golang:1.27.1 go test -race ./...
  ```
- **gofmt:** `gofmt -l .` lists 42 files on your machine. Git checked them out with Windows line endings (`core.autocrlf=true`). CI on Linux is unaffected. A `.gitattributes` with `*.go text eol=lf` would fix this; it's worth a small `chore/` PR.
- **Makefile:** its recipes are Unix shell (`/dev/urandom`, `set -a`). Use the commands above, or run `make` inside Git Bash or WSL.

---

## 3. Where the scaffold conflicts with CLAUDE.md

CLAUDE.md says to follow the scaffold on naming and layout, but its rules still apply. So I've split this into two groups.

### A. Design conflicts the team has to decide (don't let one PR pick silently)

1. **Key hierarchy. This is the biggest one.**
   - **Scaffold:** one server-wide `MASTER_KEY` from env. Each encryption gets a random data key, wrapped with that master key and stored in Mongo (envelope encryption). The server can decrypt anything without the user present.
   - **CLAUDE.md §3.3:** the key comes from the user's password via PBKDF2, lives only in session memory, and HKDF derives a key per object from a stored salt. Nothing is decryptable unless the user is logged in.

   This changes `config` (is `MASTER_KEY` still required?), the `Encryptor` interface (it currently has no per-user key parameter), and `crypto.Meta` (wrapped keys vs salt). CONTRIBUTING says any change to `Encryptor` needs a team discussion.
   My recommendation: keep the scaffold's interface shape, but build the `Encryptor` per request from the session's key. You get CLAUDE.md's security property without rewriting every package. Record the decision in `docs/decisions.md`.

2. **Sessions.** The scaffold's TODO suggests a **Mongo-backed** session store (there's a `sessions` TTL index and `SESSION_SECRET`). CLAUDE.md requires the key to live **only in memory**, so storing it in a Mongo session would break the rule "never stored in the DB". If you choose the password-derived key, sessions must be in memory.

3. **CSRF.** The scaffold suggests `SameSite=Strict` plus an Origin-header check. CLAUDE.md wants `SameSite=Lax` plus a CSRF token on every form. CLAUDE.md also requires a login rate limit, which the scaffold doesn't mention.

4. **Integrity check (HMAC).** The scaffold makes it mandatory: MAC over the ciphertext, and downloads verify the whole object before decrypting (two passes). CLAUDE.md calls it an optional stretch. The scaffold is stricter, so follow it. Note for the benchmark: a download then reads the object twice, so decrypt time includes the MAC pass. Say this in the report.

5. **Document categories.** The scaffold has 3 broad kinds (`idcard`, `document`, `video`). CLAUDE.md has 6 portal slots (`ktp`, `cv`, `transcript`, `recommendation`, `salary_slip`, `intro_video`), each with its own type and size limit. The scaffold has one global 2 GiB limit; CLAUDE.md wants 5 MB for docs and 100 MB for video.

6. **Profile.**
   - The scaffold has 6 fields, each encrypted separately, plus a NIK blind index (a keyed hash that enforces unique NIKs). CLAUDE.md adds place of birth, university and GPA, and encrypts the whole profile as one JSON blob.
   - If the key becomes per-user, the blind index can't be keyed per user and still catch duplicates across users. It would need a separate server key.

7. **Stored format details.**
   - `User` has no `kdf_salt` / `kdf_iter` fields.
   - The scaffold's TODO suggests object keys like `owner/<file id>/<alg>`. CLAUDE.md wants random UUIDs, which don't reveal who owns a file.
   - The scaffold stores the filename once per record, with one ciphertext per algorithm. CLAUDE.md puts it inside each variant.

### B. Naming and layout: follow the scaffold, no discussion needed

| CLAUDE.md / `docs/claude-prompts.md` says | Scaffold has (use this) |
|---|---|
| `internal/storage`, `internal/documents` | Each feature owns its `store.go`; MinIO lives in `platform/minio`; the upload feature is `internal/files`. CONTRIBUTING explicitly bans layer packages |
| `EncryptStream` / `NewParams` / `DeriveMasterKey` | `Encryptor.Encrypt` / `Decrypt` / `EncryptField` / `DecryptField` |
| `/documents/:id?alg=AES` | `/files/:id/download?alg=aes` |
| Branches `feat/crypto`, `chore/contracts`, `feat/storage` … (PR0–PR6) | `feature/crypto-core`, `feature/auth`, `feature/private-data`, `feature/file-storage`, `feature/frontend`, `feature/benchmark`, `docs/report` |
| `docs/report/` folder, `docs/decisions.md` | `docs/report.md` (one file); `decisions.md` still needs creating |
| Server-Timing header for benchmarks | Benchmarks stored in Mongo with `/benchmarks/export.csv`. These complement each other, so you can do both |

**`docs/claude-prompts.md` needs updating** before anyone uses it. Its branch names, package names (`internal/storage`) and PR split all disagree with the README and CONTRIBUTING. Also, `CLAUDE.md` and `docs/claude-prompts.md` are untracked: they aren't committed, so your teammates don't have them yet.

---

## 4. Git workflow (from CONTRIBUTING.md and the README)

- **Branches:** always from `main`, using `feature/<name>`, `chore/<name>` or `docs/<name>`.
- **Commits:** Conventional Commits, small and focused. For example `feat(files): stream uploads to minio`, `fix(auth): …`, `test: …`, `docs: …`.
- **Staging:** add files by path (`git add internal/crypto/aes.go`). Never use `git add .` or `git add -A`.
- **Before pushing:** run the tests and lint (`make test`, `make lint`). On your laptop, use the Docker race command above plus `go vet ./...`.
- **Pull requests into `main`:** need **one approving review** and a **green CI run**.
- **TODOs:** remove the `TODO(<your-branch>)` markers you complete. Every new TODO must name an owning branch.
- **Merge order:**
  1. `chore/scaffold` (already merged)
  2. `feature/crypto-core` and `feature/auth`
  3. `feature/private-data` and `feature/file-storage`
  4. `feature/frontend` and `feature/benchmark`
  5. `docs/report`
- **Never commit `.env` or secrets.** If one leaks, tell the team so the secret can be changed. Deleting the commit is not enough.

A typical cycle looks like this:
```powershell
git checkout main; git pull
git checkout -b feature/crypto-core
# ...work...
git add internal/crypto/stream.go internal/crypto/stream_test.go
git commit -m "feat(crypto): add aes-ctr, des-ctr and rc4 streaming encryptor"
git push -u origin feature/crypto-core
```
Then open the PR on GitHub.

**Next step:** decide the key-hierarchy question (§3 A.1) as a group before anyone starts `feature/crypto-core` or `feature/auth`, because both depend on it. If you'd like, I can draft that as the first entry in `docs/decisions.md` with both options and their trade-offs.

