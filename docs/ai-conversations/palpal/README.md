# AI conversation logs: palpal

Exported Claude Code sessions for this repository, one Markdown file per session. Prompts and replies are verbatim;
tool calls are cut to one line each, tool output and hidden reasoning are left out, and secrets are replaced with
`[REDACTED]`. Times are WIB (UTC+7). The last session was exported while it was still running, so it stops at the export request.

| Date | Log | Branch | What was done |
|---|---|---|---|
| 2026-10-10 | [repo-review](2026-10-10-repo-review.md) | `main` | Read the scaffold, explained what exists and what is still `TODO`, how to run it with Docker, and the open design questions |
| 2026-10-11 | [crypto-core](2026-10-11-crypto-core.md) | `feature/crypto-core` | The AES, DES and RC4 envelope encryption, its tests and decision records (D2: one `MASTER_KEY` encrypts per-call data keys) |
| 2026-10-13 | [frontend](2026-10-13-frontend.md) | `feature/frontend` | Templates and styling for login, register, profile, files and benchmarks, and the animated mascot |
| 2026-10-14 | [frontend-palette](2026-10-14-frontend-palette.md) | `feature/frontend` | Colour palette previews and design tweaks after the first theme was rejected |
| 2026-10-17 | [home-page](2026-10-17-home-page.md) | `feature/home` | The landing page at `/` |
| 2026-10-17 | [clear-empty](2026-10-17-clear-empty.md) | `feature/home` | Empty session: only a `/clear` |
| 2026-10-17 | [ciphertext-analysis](2026-10-17-ciphertext-analysis.md) | `feature/ciphertext-analysis` | The tool that compares the three ciphers' output on sample files (the assignment's "analyse the differences" part) |
| 2026-10-26 | [crypto-manual](2026-10-26-crypto-manual.md) | `feature/crypto-manual` | Exercise: strip the cipher code bodies down to `TODO` comments so the team could re-implement them by hand |
| 2026-10-27 | [unfinished-audit](2026-10-27-unfinished-audit.md) | `main` | Audit of unfinished `TODO` markers and a live check of upload, download, delete and the profile on the running stack |
| 2026-10-27 | [scholarship-ui](2026-10-27-scholarship-ui.md) | `feature/scholarship-ui` | The scholarship portal pages: checklist, detail pages and apply flow |
| 2026-10-27 | [final-qa-testing](2026-10-27-final-qa-testing.md) | `main` | Test-only run before the deadline: `go vet`, `go test`, and an end-to-end curl check of every route; then this export |

## How I used AI

I used Claude Code as a pair programmer inside the repository, working one planned branch at a time. Each session
started with the same instruction: read `CLAUDE.md`, the README, `CONTRIBUTING.md` and `docs/architecture.md`, then
find the `TODO(<branch>)` markers for that branch, so the AI worked from the team's design and not its own guesses. I
asked for a plan before any change that touched more than one package, and I asked it to write short "why" comments
and decision records so that I could explain every line to the TA. For crypto and auth code I treated the AI's
output as a draft to review against the hard rules (standard library only, no ECB, no key or IV reuse, no secrets in
logs, every query scoped to the logged-in owner). I also used it for audits, for end-to-end testing with curl, and
for design iteration on the frontend. Decisions about the design and what to merge stayed with me and the team.
