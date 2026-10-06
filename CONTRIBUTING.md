# Contributing

These rules apply to everyone working on this repository. Correctness matters more than features, and security mistakes count as correctness mistakes.

## Package boundaries

- **Organise by feature, not by layer.** Each feature package (`auth`, `profile`, `files`, `benchmark`) owns its models, MongoDB store, service logic, and HTTP handlers. Do not create generic packages such as `model/`, `utils/`, or `common/`.
- **Consumers declare the interfaces they need.** A package that depends on something declares a small, unexported interface for exactly the methods it calls (see `metadataStore` in `internal/files/service.go`).
- **`internal/crypto` is the shared contract.** It is the only package that exports an interface used across features (`Encryptor`). Changing it affects every branch, so discuss the change with the team before opening a pull request.
- **Gin stays at the edge.** Import Gin only in `handlers.go`, `middleware.go`, `routes.go`, and `internal/web`. Model, store, and service files must never import Gin.
- **Handlers are thin.** A handler parses and validates input with Gin binding tags, calls a service function that takes plain Go types, and writes the response. Business logic goes in the service.

## Security rules

- **Never commit secrets.** No keys, passwords, tokens, or real personal data in any committed file. Use `.env`, which is gitignored. If a secret is committed by mistake, tell the team at once so it can be rotated. Deleting the commit is not enough.
- **Never log plaintext, keys, or private data.** That includes DEKs, MAC keys, the master key, password hashes, session values, NIKs, and file contents. Log IDs and sizes instead.
- **Always stream files.** Use `io.Reader`, `io.Writer`, and `io.Pipe`. Never read a whole upload or download into memory with `io.ReadAll`, `bytes.Buffer`, or similar.
- **Never use `c.FormFile()` or `c.MultipartForm()` for uploads.** They buffer files in memory or in temporary files on disk. Use `c.Request.MultipartReader()` and stream each part (see `internal/files/handlers.go`).
- **Use `crypto/rand` only.** Never import `math/rand` or `math/rand/v2` anywhere, including in tests.
- **Never reuse an IV or a stream-cipher key.** Generate a fresh random DEK, IV, and MAC key for every encryption. CTR mode and RC4 lose all confidentiality if a key stream repeats.
- **Verify before decrypting.** Check the HMAC over the whole ciphertext before writing any plaintext, and compare tags with `hmac.Equal`.
- **Validate all input** with binding tags (`binding:"required,..."`) and the allowlists in the feature packages. Scope every database query to the current user.

## Tests

- Write table-driven tests (see `internal/config/config_test.go`).
- Test failure paths too, not only the happy path: tampered ciphertext, wrong algorithm, missing fields, oversized input.
- Run `make test` and `make lint` before every push. CI runs the same checks: `gofmt`, `go vet`, `go test -race`, `go build`, and `gosec`.

## Branches and pull requests

- Branch from `main` using one of these prefixes:
  - `feature/<name>`: new functionality, for example `feature/crypto-core`
  - `chore/<name>`: tooling, dependencies, or structure
  - `docs/<name>`: documentation and the report
- Write commit messages in [Conventional Commits](https://www.conventionalcommits.org/) style, for example `feat(files): stream uploads to minio`. Keep commits small and focused.
- Stage files explicitly by path. Do not use `git add .` or `git add -A`.
- Every pull request into `main` needs **one approving review** and a **passing CI run** before it is merged.
- Remove the `TODO(<your-branch>)` markers you complete. Do not leave new TODOs without an owning branch.
- Follow the merge order in the [README](README.md#team-branches).
