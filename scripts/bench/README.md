<<<<<<< HEAD
# Repeated download benchmark

This script measures full client-observed download time for every file in the logged-in account, repeated for AES, DES, and RC4. The app independently records crypto-only and server-side total time in MongoDB.

## Prepare

1. Start the app and register or choose a test account.
2. Upload generated test files through the web UI. Use several sizes and file kinds where available; do not use real personal data.
3. Run the script with Python 3.10 or newer.

## Run

PowerShell:

```powershell
$env:BENCH_USERNAME = "your-test-user"
$env:BENCH_PASSWORD = "your-test-password"
python scripts/bench/download_benchmark.py --repeat 10 --output docs/analysis/client-downloads.csv
```

Options include `--url http://localhost:8080`, `--repeat N`, and `--output PATH`. The output has one row per file, algorithm, and iteration. Client timings include request/response overhead and the full response body. Use `/benchmarks/export.csv` for server-side `crypto_ns` and `total_ns` values.

Only generated files from `scripts/testdata/` should be used. Results depend on hardware and load; record the environment and run all algorithms under the same conditions.
=======
# Benchmark runner

`scripts/bench` measures the three ciphers under controlled conditions and saves the server's timing records as CSV
for the report (docs/decisions.md D35).

```bash
docker compose up -d --build   # the app must be running
go run ./scripts/bench -n 10   # or: make bench N=10
```

What it does:

1. Registers a fresh account with a random password (or logs in with `-user` and `BENCH_PASSWORD`).
2. Warm-up: uploads and downloads one 1 MiB file and deletes it. These records come before the run's `since` time,
   so they are not in the results.
3. For each size in `-sizes` (default `1KiB,64KiB,1MiB,16MiB`), uploads a fake video `-uploads` times (each upload
   is three encryptions), then downloads it `-n` times per algorithm, **one request at a time**, rotating which
   algorithm goes first. Every download is checked against the SHA-256 of what was uploaded.
4. Fetches `/benchmarks/export.csv?since=<start>`, saves it to `bench-results/run-<UTC time>.csv` (gitignored), checks
   that the server recorded every operation, and prints a summary.
5. Deletes the uploaded files (`-keep` to keep them).

| Flag | Default | Meaning |
|---|---|---|
| `-url` | `http://localhost:8080` | Base URL of the app |
| `-user` | empty (new account) | Existing username; the password is read from `BENCH_PASSWORD` |
| `-sizes` | `1KiB,64KiB,1MiB,16MiB` | File sizes, up to `2GiB` (the video limit) |
| `-n` | `10` | Downloads per file size per algorithm |
| `-uploads` | `5` | Uploads per file size; each gives one encrypt record per algorithm |
| `-out` | `bench-results/run-<UTC time>.csv` | Where to save the CSV |
| `-keep` | `false` | Keep the uploaded files |

The files are a 24-byte MP4 header followed by random bytes, generated while uploading. Nothing is written to disk
except the CSV, and no real data is used.

Notes for reading the numbers:

- **Decrypt and download records are the cleanest comparison.** Each download decrypts one algorithm on its own. The
  three encryptions of an upload run at the same time and compete for CPU (D32), which adds up to about 25% to
  encrypt times (D35).
- Keep other use of the app to a minimum during a run. The runner fails if the record counts don't match its own
  requests, which usually means someone else was using the app.
- For the cipher alone, without HMAC, storage or network: `go test -run '^$' -bench . ./internal/crypto/`.
>>>>>>> origin/main
