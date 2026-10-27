# HTTP API and test cases

Every route of the app, the requests it accepts, and the responses to expect, written so each row can become one
request in Postman or Insomnia. The last sections show how to check that stored data is really encrypted and where
the ciphertext analysis and benchmark results come from.

The app is a server-rendered website, not a JSON API. Most responses are HTML pages, so tests check the **status
code**, **headers** (`Location`, `Content-Type`, `Content-Disposition`) and **text in the body**. The exceptions are
`/healthz` (JSON), downloads (the file), the CSV export, and `DELETE /files/:id` (empty body).

When checking body text, remember that HTML pages escape apostrophes: "couldn't" is sent as `couldn&#39;t`. The
strings in the tables below avoid apostrophes so they can be matched as they are.

## 1. Setup

Start the stack with `docker compose up -d --build` and check `GET http://localhost:8080/healthz`.

### Client settings (important)

| Setting | Postman | Insomnia | Why |
|---|---|---|---|
| Do not follow redirects | Settings → *Automatically follow redirects*: **off** (or per request) | Request → *Follow redirects*: **off** | Success is usually `303 See Other`; following it hides the status and `Location` |
| Keep cookies | On by default (cookie jar per domain) | On by default | Login sets the `session` cookie that every protected route needs |
| No `Origin` header | Not sent by default | Not sent by default | A foreign `Origin` makes POST/DELETE fail with 403 (CSRF protection, §3.2) |

### Variables

| Variable | Example | Set by |
|---|---|---|
| `baseUrl` | `http://localhost:8080` | you |
| `username` | `budi01` (3–32 letters or digits; use a new one per run) | you |
| `password` | `correct-horse-battery` (12–128 characters) | you |
| `fileId` | `6adc71e87fbf2bd6dc67a1f6` | the test script of `GET /files` (§4.4) |
| `since` | `2026-10-27T09:00:00Z` | you, or the benchmark runner's output |

Test files are in `scripts/testdata/` and are all fake: `ktp-fake.jpg`, `ktp-fake.png`, `sample.pdf`,
`sample.docx`, `sample.xlsx`, `sample.mp4`, `sample.txt`. Never upload real ID cards or personal data.

### Suggested folder order

1. Public (§4.1) → 2. Register (§4.2) → 3. Login (§4.3) → 4. Private data (§4.5) → 5. Files (§4.4) →
6. Benchmarks (§4.6) → 7. Cross-cutting checks (§3) → 8. Logout (§4.3, last, because it ends the session).

Rate limits are per client IP: **10 logins and 5 registrations per minute**. Running the register folder twice in a
minute returns 429; wait 60 seconds.

## 2. Route overview

| Method | Path | Login | Success | Body |
|---|---|---|---|---|
| GET | `/healthz` | no | 200 | JSON |
| GET | `/` | no | 200 (logged out) / 303 → `/files` (logged in) | HTML |
| GET | `/static/style.css` (and other assets) | no | 200 | CSS/JS/fonts |
| GET | `/register` | no | 200 (logged out) / 303 → `/files` (logged in) | HTML |
| POST | `/register` | no | 303 → `/login` | — |
| GET | `/login` | no | 200 (logged out) / 303 → `/files` (logged in) | HTML |
| POST | `/login` | no | 303 → `/files`, sets `session` cookie | — |
| POST | `/logout` | yes | 303 → `/login`, clears `session` | — |
| GET | `/profile?alg=aes\|des\|rc4` | yes | 200 | HTML |
| POST | `/profile` | yes | 303 → `/profile?alg=aes` | — |
| GET | `/files` | yes | 200 | HTML |
| POST | `/files` | yes | 303 → `/files` | — |
| GET | `/files/:id/download?alg=aes\|des\|rc4` | yes | 200 | the file |
| DELETE | `/files/:id` | yes | 200 | empty |
| GET | `/benchmarks?since=` | yes | 200 | HTML |
| GET | `/benchmarks/export.csv?since=` | yes | 200 | CSV |
| any | unknown path | no | 404 | HTML error page |

## 3. Behaviour on every route

### 3.1 Login required

Every protected route, for any method, answers a request without a valid `session` cookie with **303** and
`Location: /login`. An expired session also sets a one-time "session expired" message.

| Case | Request | Expect |
|---|---|---|
| No cookie | `GET /files`, `GET /profile`, `GET /benchmarks`, `GET /benchmarks/export.csv`, `POST /files`, `DELETE /files/{{fileId}}`, `POST /logout` | 303, `Location: /login` |
| Bad cookie | any of the above with `Cookie: session=AAAA` | 303, `Location: /login` |

### 3.2 CSRF protection

POST and DELETE requests are rejected when the browser says they come from another site. GET is never blocked.

| Case | Request | Expect |
|---|---|---|
| Foreign origin | `POST /login` with header `Origin: http://evil.example` | **403** |
| Cross-site fetch | `POST /profile` with header `Sec-Fetch-Site: cross-site` | **403** |
| Same origin | `POST /login` with `Origin: http://localhost:8080` | normal response (303 or 401) |
| No header (Postman default) | `POST /login` | normal response |

### 3.3 Body size limits

| Case | Request | Expect |
|---|---|---|
| Large form | `POST /login` with a body over 64 KiB (for example a 70,000-character `username`) | **413** |
| Large upload | `POST /files` over `MAX_BODY_BYTES` (2 GiB) | **413** |
| File over its kind's limit | ID card over 10 MiB, document over 50 MiB, video over 2 GiB | **413**, page says `Limits: ID card 10 MiB, document 50 MiB, video 2 GiB.` |

### 3.4 Security headers (check on any HTML page)

| Header | Value |
|---|---|
| `Content-Security-Policy` | starts with `default-src 'self'` |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Referrer-Policy` | `no-referrer` |

`Set-Cookie: session=...` after login must include `HttpOnly`, `SameSite=Strict` and `Max-Age=28800` (8 hours).
`Secure` is added when `COOKIE_SECURE=true`.

## 4. Routes and cases

### 4.1 Public

| Case | Request | Expect |
|---|---|---|
| Health | `GET /healthz` | 200, JSON `{"status":"ok","checks":{"minio":"ok","mongodb":"ok"}}` |
| Health, MongoDB down | `docker compose stop mongo`, then `GET /healthz` | 503, `"mongodb":"unavailable"` (start it again after) |
| Home, logged out | `GET /` | 200, body contains `Secure Store` |
| Home, logged in | `GET /` with session | 303, `Location: /files` |
| Static file | `GET /static/style.css` | 200, `Content-Type: text/css; charset=utf-8` |
| Unknown page | `GET /nope` | 404, body contains `find that page` |

### 4.2 Register — `POST /register`

Body: `x-www-form-urlencoded` with `username`, `password`, `confirm`.

| Case | Body | Expect |
|---|---|---|
| Success | new `username`, `password` = `confirm` = 12+ chars | 303, `Location: /login` |
| Username taken | same username again | **409**, body `That username is already taken.` |
| Username too short | `username=ab` | **422**, `Username must be 3–32 letters or digits.` |
| Username with symbols | `username=budi!` | 422, same message |
| Password too short | `password=short` | 422, `Password must be at least 12 characters.` |
| Password too long | 129 characters | 422, `Password must be at most 128 characters.` |
| Confirm differs | `confirm` ≠ `password` | 422, `The two passwords don` (the page shows "don't match") |
| Missing fields | empty body | 422 |
| Rate limit | 6th register within a minute from the same IP | **429**, `Retry-After` header, `Too many attempts.` |
| Already logged in | `GET /register` with session | 303, `Location: /files` |

Usernames are stored lower-case: `Budi01` and `budi01` are the same account.

### 4.3 Login and logout

`POST /login`, body `x-www-form-urlencoded` with `username`, `password`.

| Case | Body | Expect |
|---|---|---|
| Success | correct credentials | 303, `Location: /files`, `Set-Cookie: session=...` |
| Wrong password | correct username, wrong password | **401**, `Wrong username or password.` |
| Unknown user | username that doesn't exist | 401, **same message** (no hint that the user is missing) |
| Empty form | empty body | 401, same message |
| Rate limit | 11th attempt within a minute | **429**, `Retry-After` |
| Session rotation | log in twice, compare `session` cookies | the second login sets a different value |

`POST /logout` (no body, with session): 303, `Location: /login`, `Set-Cookie: session=; Max-Age=0`. After it, the old
cookie value is rejected: `GET /files` with it gives 303 to `/login` (the session is deleted server-side, not only in
the browser).

### 4.4 Files

#### Upload — `POST /files`

Body: **form-data** (multipart) with two fields, **in this order**:

| Key | Type | Value |
|---|---|---|
| `kind` | text | `idcard`, `document` or `video` |
| `file` | file | the file |

The `kind` field must come before `file` (the server streams the upload and needs the kind first). The file's
`Content-Type` set by the client is ignored; the type is detected from the extension and the first bytes.

| Case | kind | file | Expect |
|---|---|---|---|
| ID card JPG | `idcard` | `ktp-fake.jpg` | 303, `Location: /files` |
| ID card PNG | `idcard` | `ktp-fake.png` | 303 |
| PDF | `document` | `sample.pdf` | 303 |
| Word | `document` | `sample.docx` | 303 |
| Excel | `document` | `sample.xlsx` | 303 |
| Video | `video` | `sample.mp4` | 303 |
| Wrong kind for type | `idcard` | `sample.pdf` | **415**, `allowed for this kind` |
| Type not allowed | `document` | `sample.txt` | 415 |
| Renamed file | `idcard` | `sample.pdf` renamed to `fake.png` | 415 (content doesn't match the extension) |
| Unknown kind | `audio` | `sample.pdf` | **400**, `Unknown file kind.` |
| Empty file | `document` | a 0-byte `empty.pdf` | 400, `That file is empty.` |
| File before kind | fields in the wrong order | 400, `The upload form was incomplete.` |
| No file field | only `kind` | 400, same message |
| Not multipart | `x-www-form-urlencoded` body | 400 |
| Too large | `idcard`, an 11 MiB `.png` | **413** |

Errors are shown on the file list page (HTML) with the message in a red box; nothing is stored.

#### List — `GET /files`

200, HTML. Each file has three download links, one per algorithm, and a delete button. To capture a file id
for the next requests, add this test script to `GET /files` (Postman *Tests* / Insomnia *After-response*; in
Insomnia write `insomnia` instead of `pm`):

```js
const m = pm.response.text().match(/\/files\/([0-9a-f]{24})\/download/);
pm.test("a file is listed", () => pm.expect(m).to.not.be.null);
if (m) pm.environment.set("fileId", m[1]); // newest file first
```

#### Download — `GET /files/{{fileId}}/download?alg=aes`

| Case | Request | Expect |
|---|---|---|
| AES copy | `?alg=aes` | 200, the original bytes |
| DES copy | `?alg=des` | 200, identical bytes |
| RC4 copy | `?alg=rc4` | 200, identical bytes |
| Headers | any of the above | `Content-Type` is the detected type (e.g. `application/pdf`), `Content-Length` = original size, `Content-Disposition: attachment; filename=...`, `Cache-Control: no-store` |
| Bad algorithm | `?alg=3des` or no `alg` | **400**, `Unknown algorithm.` |
| Bad id | `/files/xyz/download?alg=aes` | **404** |
| Unknown id | `/files/000000000000000000000000/download?alg=aes` | 404 |
| Another user's file | log in as a second user, use the first user's `fileId` | **404** (not 403: it doesn't reveal that the file exists) |
| Tampered copy | flip a byte of the stored object (§5.3), then download that algorithm | **422**, `failed its integrity check`, no `Content-Disposition`, no file bytes |

A Postman test that checks all three copies are the same file (run it on each of the three download requests):

```js
pm.test("200 and attachment", () => {
  pm.response.to.have.status(200);
  pm.expect(pm.response.headers.get("Content-Disposition")).to.match(/^attachment/);
  pm.expect(pm.response.headers.get("Cache-Control")).to.eql("no-store");
});
const sha = CryptoJS.SHA256(CryptoJS.lib.WordArray.create(pm.response.stream)).toString();
const first = pm.environment.get("fileSha");
if (!first) pm.environment.set("fileSha", sha);
else pm.test("same bytes as the first copy", () => pm.expect(sha).to.eql(first));
```

Clear `fileSha` before a new file. For a reference value, run `sha256sum scripts/testdata/sample.pdf`.

#### Delete — `DELETE /files/{{fileId}}`

| Case | Expect |
|---|---|
| Own file | **200**, empty body; the file disappears from `GET /files`, its three objects are removed from MinIO |
| Again (already deleted) | 404 |
| Another user's file | 404, and the file is still there for its owner |
| Bad id (`/files/xyz`) | 404 |

### 4.5 Private data — `/profile`

`POST /profile`, body `x-www-form-urlencoded`:

| Field | Rule | Example |
|---|---|---|
| `full_name` | required, ≤ 100 characters | `Budi Santoso` |
| `nik` | exactly 16 digits, unique across users | `3171234567890123` |
| `date_of_birth` | `YYYY-MM-DD`, from 1900-01-01, not in the future | `1999-05-17` |
| `address` | required, ≤ 300 characters | `Jl. Contoh No. 1, Jakarta` |
| `phone` | 9–15 digits | `081234567890` |
| `email` | valid address, ≤ 254 characters | `budi@example.com` |

| Case | Request | Expect |
|---|---|---|
| Nothing saved yet | `GET /profile` | 200, empty form |
| Save | `POST /profile` with all fields valid | 303, `Location: /profile?alg=aes` |
| Read AES copy | `GET /profile?alg=aes` | 200, body contains the saved values (e.g. `Budi Santoso`) |
| Read DES copy | `GET /profile?alg=des` | 200, same values |
| Read RC4 copy | `GET /profile?alg=rc4` | 200, same values |
| Default algorithm | `GET /profile` | 200, AES copy |
| Bad algorithm | `GET /profile?alg=xyz` | **400**, `Unknown algorithm.` |
| Update | `POST /profile` again with a new address | 303; every `?alg=` shows the new address |
| Invalid NIK | `nik=123` | **422**, `NIK must be exactly 16 digits.` |
| Future birth date | `date_of_birth=2999-01-01` | 422 |
| Bad email | `email=not-an-email` | 422 |
| Short phone | `phone=0812` | 422 |
| Missing field | omit `address` | 422 |
| NIK used by another user | second user saves the first user's NIK | **409**, no hint whose account has it |
| Tampered copy | change a stored ciphertext (§5.3), then `GET /profile?alg=<that alg>` | **422**, integrity error; the other two algorithms still show the data |

### 4.6 Benchmarks

Records are written automatically: three `encrypt` records per upload and per profile save, a `decrypt` record per
profile view, and a `decrypt` plus a `download` record per file download. The page and the export show records
from **all users** (docs/decisions.md D34).

`since` must be an RFC 3339 time, for example `2026-10-27T09:00:00Z` or `2026-10-27T16:00:00+07:00`. URL-encode `+`
as `%2B`.

| Case | Request | Expect |
|---|---|---|
| Page | `GET /benchmarks` | 200, body contains `Summary`, `records,` and `processed` (or `No measurements yet.` on a fresh database) |
| Page, filtered | `GET /benchmarks?since={{since}}` | 200, only records at or after `since`; the Export CSV link keeps the filter |
| Nothing in range | `GET /benchmarks?since=2099-01-01T00:00:00Z` | 200, `No measurements yet.` |
| Bad since | `?since=yesterday`, `?since=2026-10-27` (no time) or `?since=2026-10-27T09:00:00` (no zone) | **400**, `RFC 3339` |
| Export | `GET /benchmarks/export.csv` | 200, `Content-Type: text/csv; charset=utf-8`, `Content-Disposition: attachment; filename="benchmarks.csv"`, `Cache-Control: no-store` |
| Export header | same | first line `created_at,algorithm,operation,file_kind,bytes,crypto_ns,total_ns` |
| Export, filtered | `GET /benchmarks/export.csv?since={{since}}` | only matching rows, oldest first |
| Export, bad since | `?since=nope` | 400, no `Content-Disposition` |
| Records appear | note the time, upload one file, export with `since` = that time | 3 rows: `encrypt` for `aes`, `des`, `rc4`, `file_kind` = the upload's kind |
| Download records | download with `?alg=des`, export again | 2 new rows: `des,decrypt` and `des,download` with the same `crypto_ns` |

Postman test for the export:

```js
pm.test("csv export", () => {
  pm.response.to.have.status(200);
  pm.expect(pm.response.headers.get("Content-Type")).to.include("text/csv");
  const lines = pm.response.text().trim().split("\n");
  pm.expect(lines[0]).to.eql("created_at,algorithm,operation,file_kind,bytes,crypto_ns,total_ns");
  lines.slice(1).forEach(l => pm.expect(l.split(",")[1]).to.be.oneOf(["aes", "des", "rc4"]));
});
```

## 5. Checking the encryption

MongoDB and MinIO are not exposed on the host. The commands below run inside their containers from the repository
root and read the credentials from the container's environment.

```bash
# MongoDB shell on the app database
M() { docker compose exec -T mongo sh -c 'mongosh --quiet -u "$MONGO_INITDB_ROOT_USERNAME" -p "$MONGO_INITDB_ROOT_PASSWORD" --authenticationDatabase admin securestore --eval "$0"' "$1"; }
# MinIO client, bucket securestore
MC() { docker compose exec -T minio sh -c 'mc alias set l http://localhost:9000 "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" >/dev/null; '"$1"; }
```

### 5.1 Private data is stored encrypted three times

```bash
M 'printjson(db.profiles.findOne({}, {full_name: 1, nik_index: 1}))'
```

Expect `full_name` to have three keys, `aes`, `des` and `rc4`, each with `ct` (ciphertext, the same length as the
plaintext) and `meta` (`alg`, `iv` — 16 bytes for AES, 8 for DES, none for RC4 — `wrapped_dek`, `wrapped_mac_key`,
`tag`). The three `ct` values differ from each other. Neither the name nor the NIK appears in plaintext anywhere:

```bash
M 'print(JSON.stringify(db.profiles.find().toArray()).includes("Budi"))'   # false
```

### 5.2 Files are stored encrypted three times

```bash
MC 'mc ls -r l/securestore/'                       # <user id>/<file id>/aes|des|rc4, no filenames
M 'printjson(db.files.findOne({}, {file_name: 0}))' # mime_type, size, variants.{aes,des,rc4}.{object_key, meta}
MC 'mc cat l/securestore/<user id>/<file id>/aes' | head -c 16 | xxd   # random bytes, not "%PDF"
head -c 16 scripts/testdata/sample.pdf | xxd                           # the plaintext starts with %PDF
```

Each object is the same size as the original file (CTR and RC4 add no padding). The original filename is only in
`file_name`, encrypted like the private data.

### 5.3 Tampering is detected

Change one byte of one copy, then request that copy. The app must refuse it with 422 and send no data, while the other
two algorithms still work.

```bash
# A file: flip a byte of the DES object (replace the key)
K='<user id>/<file id>/des'
MC "mc cat l/securestore/$K > /tmp/o; printf '\\x00' | dd of=/tmp/o bs=1 seek=100 conv=notrunc 2>/dev/null; mc cp -q /tmp/o l/securestore/$K; rm /tmp/o"
# Private data: change the first byte of the RC4 full_name ciphertext
M 'const p = db.profiles.findOne(); const b = Buffer.from(p.full_name.rc4.ct.buffer); b[0] ^= 1;
   db.profiles.updateOne({_id: p._id}, {$set: {"full_name.rc4.ct": BinData(0, b.toString("base64"))}})'
```

Then `GET /files/{{fileId}}/download?alg=des` and `GET /profile?alg=rc4` give 422. Save the profile again (or upload
the file again) to get valid copies back.

### 5.4 Ciphertext analysis

`docs/analysis/report.md` compares AES-256-CTR, DES-CTR and RC4 on the sample files: size, entropy, byte
uniformity (chi-square), the first 32 bytes, the effect of one flipped bit, tamper detection, and why ECB mode is not
used (`docs/analysis/ecb-demo-*.png`). The raw numbers are in `docs/analysis/results.csv`. To regenerate everything
with fresh keys:

```bash
go run ./cmd/cipheranalysis
```

### 5.5 Running time

Timings are recorded for every operation (§4.6). For numbers good enough for the report, use the runner, which
uploads fixed sizes and downloads each one N times per algorithm, one request at a time:

```bash
go run ./scripts/bench -n 10      # prints since=..., saves bench-results/run-<time>.csv, prints a summary
```

Open `/benchmarks?since=<printed value>` to see the same run in the browser. Compare **decrypt** rows across
algorithms (docs/decisions.md D35). For the cipher alone, without HMAC, storage or network:

```bash
go test -run '^$' -bench . ./internal/crypto/
```
