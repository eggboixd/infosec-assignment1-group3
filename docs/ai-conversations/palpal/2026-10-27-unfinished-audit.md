# Audit of unfinished work on main

- Session: `682e4ce2-cb12-4a73-b424-7b212446786f`
- Started: 2026-10-27 01:16 (WIB, UTC+7)
- Git branch when started: `main`
- Export notes: prompts and replies are verbatim (system reminders and hook context stripped); tool calls are one-line summaries; tool output and hidden reasoning are omitted; secrets are replaced with [REDACTED].

---

_(slash command: `/clear`)_

_(slash command: `/model`)_

_(slash command: `/effort`)_

## ðŸ§‘ User

Audit what's still unfinished in main. List every TODO( marker with its file and owner branch.
Check: (1) file storage — upload, list, download with AES, DES and RC4, and delete all work end-to-end;
(2) frontend — every page gets its real data (.Files[].Name, .Errors, .Username, .JustLoggedIn,
.Flash), no page returns 501 or "not implemented"; (3) the 3 leftover TODO(feature/frontend)
markers. Run the app with docker compose and test it. Don't change any code — just give me a
short list: done / not done / broken.

## ðŸ¤– Claude

I'll start by listing the TODO markers and the repo layout.


- _tool:_ **Grep** TODO\(
- _tool:_ **Glob** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1
- _tool:_ **Bash** List tracked files, branches and docker versions â€” `cd "C:/Users/ASUS/Desktop/kuliah/sem5/tkti/groupassignment1" && git ls-files | grep -v '^\.playwrigh`
- _tool:_ **Grep** 501|NotImplemented|not implemented|TODO|FIXME|XXX
- _tool:_ **Read** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\internal\files\handlers.go
- _tool:_ **Read** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\internal\files\routes.go
- _tool:_ **Read** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\internal\web\templates\files.html
- _tool:_ **Read** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\internal\web\server.go
- _tool:_ **Read** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\internal\benchmark\handlers.go
- _tool:_ **Read** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\internal\web\templates\benchmarks.html
- _tool:_ **Read** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\cmd\server\main.go
- _tool:_ **Read** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\internal\benchmark\routes.go
- _tool:_ **Read** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\internal\auth\handlers.go
- _tool:_ **Read** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\internal\profile\handlers.go
- _tool:_ **Read** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\internal\web\home.go
- _tool:_ **Read** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\internal\web\render.go
- _tool:_ **Read** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\internal\web\templates\layout.html
- _tool:_ **Read** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\internal\web\templates\login.html
- _tool:_ **Read** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\internal\web\templates\register.html
- _tool:_ **Read** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\internal\web\templates\profile.html
- _tool:_ **Read** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\internal\files\service.go
- _tool:_ **Read** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\internal\auth\flash.go
- _tool:_ **Grep** JustLoggedIn|justLoggedIn
- _tool:_ **Grep** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\internal\files
- _tool:_ **Bash** Show compose file, env example, recent history â€” `cd "C:/Users/ASUS/Desktop/kuliah/sem5/tkti/groupassignment1" && cat docker-compose.yml && echo ---- `
## ðŸ¤– Claude

Static review is done. I'm now building and running the stack with docker compose, so I can test the flows live.


- _tool:_ **Bash** Check Docker daemon and existing containers â€” `cd "C:/Users/ASUS/Desktop/kuliah/sem5/tkti/groupassignment1" && docker info --format '{{.ServerVersi`
## ðŸ¤– Claude

A stack is already up, but the app container is 9 days old and may predate the latest merge. I'll rebuild the app image from current `main`. That leaves the mongo and minio volumes alone.


- _tool:_ **Bash** Rebuild and restart the app container, check health â€” `cd "C:/Users/ASUS/Desktop/kuliah/sem5/tkti/groupassignment1" && docker compose up -d --build app 2>&`
## ðŸ¤– Claude

The app is healthy. Next is an end-to-end run with `curl.exe` and a throwaway user: register, log in, upload, list, download with each algorithm, compare bytes, then delete.


- _tool:_ **Bash** Test public pages, register, login, and files page â€” `cd "C:/Users/ASUS/Desktop/kuliah/sem5/tkti/groupassignment1" && S="C:/Users/ASUS/AppData/Local/Temp/`
## ðŸ¤– Claude

Auth and the page data all work. Now the file flow: upload each kind, download with all three algorithms, compare bytes, then delete.


- _tool:_ **Bash** Upload all file kinds, test rejections, list files â€” `S="C:/Users/ASUS/AppData/Local/Temp/claude/C--Users-ASUS-Desktop-kuliah-sem5-tkti-groupassignment1/6`
- _tool:_ **Bash** Download every file with each algorithm and compare hashes â€” `S="C:/Users/ASUS/AppData/Local/Temp/claude/C--Users-ASUS-Desktop-kuliah-sem5-tkti-groupassignment1/6`
## ðŸ¤– Claude

All 18 downloads match the originals byte for byte. Remaining: delete, another user's access (IDOR), profile, and the benchmark pages.


- _tool:_ **Bash** Test IDOR, delete, profile, benchmarks, logout â€” `S="C:/Users/ASUS/AppData/Local/Temp/claude/C--Users-ASUS-Desktop-kuliah-sem5-tkti-groupassignment1/6`
## ðŸ¤– Claude

One last check: does delete remove the encrypted objects from MinIO, or only the Mongo metadata?


- _tool:_ **Bash** Check MinIO objects for the deleted file â€” `cd "C:/Users/ASUS/Desktop/kuliah/sem5/tkti/groupassignment1" && docker compose exec -T minio sh -c '`
## ðŸ¤– Claude

Nothing is broken apart from the benchmark routes. File storage and the frontend work end-to-end, but `/benchmarks` and `/benchmarks/export.csv` are still stubs that return 501. I changed no code. I rebuilt the app image from `main` with `docker compose up -d --build app`, then tested with `curl.exe` against `localhost:8080`.

**Done (verified live)**
- **Upload:** ID card (PNG, JPG), document (PDF, DOCX, XLSX) and video (MP4) all upload with a 303 back to `/files`.
- **Rejections:** a wrong file type gets 415, an unknown kind gets 400, and an empty file gets 400 with "That file is empty."
- **List:** the 6 uploaded files show their real decrypted names, e.g. `sample.mp4`.
- **Download:** all 6 files × AES, DES and RC4 return 200 and match the original SHA-256. The responses carry `Content-Disposition: attachment`. A bad algorithm returns 400, and a bad or unknown ID returns 404.
- **Delete:** the owner gets 200, then 404 on a repeat. The deleted file's objects are gone from MinIO, 0 left.
- **Other users (IDOR):** a second user gets 404 on the first user's file for both download and delete, and sees 0 files in their own list.
- **Template data:**
  - `.Errors` and `.Username` render on login and register: a bad password shows its message and the username is refilled.
  - `.Flash` shows "Account created…" after registering.
  - `.JustLoggedIn` shows the unlocked mascot only on the first `/files` load after login.
  - `.Files[].Name` renders on `/files`.
- **Profile:** saving and reading back works with AES, DES and RC4, and validation errors show up.
- **Other routes:** `/`, `/login`, `/register` and 404 pages render, and logged-out access redirects to `/login`.

**Not done: `TODO(` markers**

| File | Owner branch |
|---|---|
| `internal/benchmark/handlers.go:19` (`index`) | `feature/benchmark` |
| `internal/benchmark/handlers.go:25` (`exportCSV`) | `feature/benchmark` |
| `internal/web/templates/benchmarks.html:21` | `feature/benchmark` |
| `scripts/bench/README.md:5` (benchmark script) | `feature/benchmark` |
| `docs/report.md:3` (every section) | `docs/report` |

**Broken**
- **`GET /benchmarks`** returns a plain-text 501 "not implemented" with no layout. The "Benchmarks" link in the nav on every page leads there.
- **`GET /benchmarks/export.csv`** also returns 501.
- **`benchmarks.html`** has an empty `<tbody></tbody>`, so it would show nothing even once the handler passes `.Records`.

**Your third check doesn't match the code.** I found no three `TODO(feature/frontend)` markers. There is one, at `internal/benchmark/handlers.go:20`, and it's a side reference inside the `feature/benchmark` comment, not a standalone marker. The template TODO in `benchmarks.html` is owned by `feature/benchmark`. The frontend work you listed appears finished, and what's left is benchmark work that spans the handler, the template and the script.

**Minor, not broken:** a download without `?alg=` returns 400, while `/profile` defaults to AES. That follows the documented `?alg=aes|des|rc4`.

**Left behind by my testing**
- Two test users: `audit14263`, who still has 5 files and a profile, and `other27954`.
- The stack is still running with the rebuilt app.
- I didn't run `go vet` or `go test`.
- I didn't check whether benchmark records are being written to MongoDB, only that nothing displays them.

_(slash command: `/exit`)_

