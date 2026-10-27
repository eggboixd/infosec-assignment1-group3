# Information Security - Group 3: BeasiswaKu

**BeasiswaKu** is a university scholarship application portal of a fictional foundation, Yayasan Cendekia Nusantara. Students register, fill in their applicant data, upload the documents a scholarship committee asks for (a KTP scan, CV, transcript, recommendation letter, their parents' salary slip and a self-introduction video) and submit an application to one or both open scholarships. These are exactly the kinds of personal data that UU PDP and GDPR protect, so everything private is stored encrypted three times, once each with **AES-256**, **DES**, and **RC4**, and only the logged-in student can read it back. The team compares running time and ciphertext across the ciphers in the final report.

Stored data:

1. Applicant data, personal data as defined by GDPR and Indonesia's UU PDP (name, NIK, date of birth, address, phone, email), stored in MongoDB
2. ID card images (JPEG, PNG)
3. Documents (PDF, DOC, DOCX, XLS, XLSX)
4. Videos (MP4, WebM)
5. Applications: which scholarship a student applied to, and when

> **Status:** cryptography, the frontend, private data, authentication (accounts, sessions, CSRF protection), encrypted file storage (streaming upload, download and delete) and benchmarks (summary page, CSV export, and the `scripts/bench` runner) and scholarship applications (home page, detail pages, encrypted submit) are implemented. Every HTTP route and its test cases are listed in [docs/api.md](docs/api.md). Measured running times are in [docs/benchmark/](docs/benchmark/README.md). See [Team branches](#team-branches).

## Architecture

| Component | Technology |
|---|---|
| Web app | Go, Gin, server-rendered `html/template` + htmx, embedded into one binary |
| Metadata and private data | MongoDB (official Go driver v2) |
| Encrypted file objects | MinIO (S3-compatible), via `minio-go` |
| Deployment | Docker Compose: `app`, `mongo`, `minio`, `minio-init` |

Crypto design in brief:

- AES-256-CTR and DES-CTR, and RC4 as a native stream cipher. All three go through Go's `cipher.Stream`, so one streaming code path serves every algorithm.
- Each encryption gets fresh random data keys (DEKs), a fresh IV, and a separate HMAC-SHA256 key. The MAC is computed over the ciphertext (encrypt-then-MAC).
- DEKs are wrapped with a master key (`MASTER_KEY`) taken from the environment. The master key is never stored in the database or the repository.
- Downloads verify the HMAC over the whole object first, then decrypt in a second pass.
- Files stream end to end and are never fully loaded into memory.
- Every encryption, decryption, and download is timed. The timings feed the `/benchmarks` view and its CSV export.

Details and data-flow diagrams are in [docs/architecture.md](docs/architecture.md).

### Code layout

The code is organised by feature, not by layer:

```
cmd/server/            entry point: config, clients, wiring, graceful shutdown
internal/config/       environment loading and validation
internal/crypto/       shared Encryptor contract (the team-wide interface)
internal/auth/         users, login, sessions, RequireAuth middleware
internal/profile/      encrypted private personal data
internal/files/        encrypted file upload and download
internal/benchmark/    timing records, /benchmarks view, CSV export
internal/applications/ scholarship catalogue, home page, encrypted applications
internal/platform/     MongoDB and MinIO clients
internal/web/          Gin engine, templates, static files, /healthz
deploy/minio/          MinIO image built from source
docs/                  architecture notes and the report
```

## Prerequisites

- Docker with Docker Compose v2
- Go 1.27 or newer (only needed for development outside Docker)
- `make`

## Run locally with Docker

```sh
cp .env.example .env
make gen-key   # paste the output into MASTER_KEY
make gen-key   # paste the output into SESSION_SECRET
# also change MONGO_ROOT_PASSWORD and MINIO_ROOT_PASSWORD in .env

make up        # docker compose up --build -d
curl localhost:8080/healthz
# {"status":"ok","checks":{"minio":"ok","mongodb":"ok"}}
```

The first build compiles MinIO from source and takes several minutes. MinIO no longer publishes public container images, so `deploy/minio/Dockerfile` builds the last community release at a pinned commit.

Only the app publishes a port. To reach MongoDB and MinIO from the host, for example to use `make run` or the MinIO console, run:

```sh
cp docker-compose.override.yml.example docker-compose.override.yml
docker compose up -d
```

The override binds MongoDB to `127.0.0.1:27017`, the MinIO API to `127.0.0.1:9000`, and the MinIO console to `127.0.0.1:9001`.

Other targets:

| Target | Action |
|---|---|
| `make run` | Run the server with `go run`, reading `.env` |
| `make build` | Build `bin/server` |
| `make test` | Run tests with the race detector |
| `make lint` | `gofmt` check, `go vet`, and `gosec` |
| `make down` / `make logs` | Stop services and keep the data volumes / follow logs |
| `make gen-key` | Print a random base64 32-byte key |

## Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `MASTER_KEY` | yes | | Base64 of 32 random bytes; wraps all data keys |
| `SESSION_SECRET` | yes | | At least 32 characters; keys the HMAC that turns session tokens into stored IDs |
| `COOKIE_SECURE` | no | `false` | Mark session cookies `Secure`; set to `true` when served over HTTPS |
| `MONGO_URI` | yes | | MongoDB connection string (set by Compose for the container) |
| `MONGO_DATABASE` | no | `securestore` | Database name |
| `MINIO_ENDPOINT` | yes | | `host:port` of MinIO (set by Compose for the container) |
| `MINIO_ACCESS_KEY` | yes | | MinIO access key |
| `MINIO_SECRET_KEY` | yes | | MinIO secret key |
| `MINIO_BUCKET` | no | `securestore` | Bucket for encrypted objects |
| `MINIO_USE_SSL` | no | `false` | Use HTTPS to reach MinIO |
| `HTTP_ADDR` | no | `:8080` | Listen address inside the container |
| `GIN_MODE` | no | `release` | `debug`, `release`, or `test` |
| `MAX_BODY_BYTES` | no | `2147483648` | Maximum request body size |
| `SHUTDOWN_TIMEOUT` | no | `15s` | Grace period for in-flight requests on shutdown |
| `APP_PORT` | no | `8080` | Host port published by Compose |
| `MONGO_ROOT_USERNAME`, `MONGO_ROOT_PASSWORD` | yes (Compose) | | MongoDB root credentials |
| `MINIO_ROOT_USER`, `MINIO_ROOT_PASSWORD` | yes (Compose) | | MinIO root credentials |

The app refuses to start if a required variable is missing or invalid. Never commit `.env`.

## Team branches

Each branch fills in the `TODO(<branch>)` markers in the code.

| Branch | Scope |
|---|---|
| `feature/crypto-core` | Real `Encryptor` (AES-256-CTR, DES-CTR, RC4, HMAC-SHA256), key wrapping, HKDF subkeys |
| `feature/auth` | Registration, login, Argon2id hashing, MongoDB-backed sessions, real `RequireAuth`, CSRF protection |
| `feature/private-data` | Field-level encryption of personal data and the NIK blind index |
| `feature/file-storage` | Streaming multipart upload, three-way encryption to MinIO, verify-then-decrypt download, delete |
| `feature/frontend` | Templates and htmx interactions |
| `feature/benchmark` | Benchmark view, CSV export, and the repeated-download script in `scripts/bench/` |
| `docs/report` | The analysis report in `docs/report.md` |

Merge order:

1. `chore/scaffold`
2. `feature/crypto-core` and `feature/auth`
3. `feature/private-data` and `feature/file-storage`
4. `feature/frontend` and `feature/benchmark`
5. `docs/report`

See [CONTRIBUTING.md](CONTRIBUTING.md) for the rules every branch follows.
