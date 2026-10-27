# Benchmark results: AES-256-CTR vs DES-CTR vs RC4

Raw data behind the running-time numbers in the report. The ciphertext analysis (entropy, chi-square, bit flips, tampering, ECB) lives separately in [`docs/analysis/`](../analysis/report.md).

The same measurements were taken on two machines. Machine A's files are in this folder; machine B's are in [`ryzen-3550h/`](ryzen-3550h/), which also holds a run of the whole app (with MinIO and MongoDB). **Compare algorithms within one machine only.** Absolute speeds differ by 2–3× between the machines, and even one machine varies between sessions (see "Reading the numbers").

## Environment

| Item | Machine A | Machine B |
|---|---|---|
| Host | Acer Predator Helios Neo 16S, Intel Core Ultra 7 255HX | Laptop, AMD Ryzen 5 3550H (4 cores, 8 threads, AES-NI) |
| Runtime | Linux VM on that laptop, 2 vCPUs, 3.9 GB RAM, kernel 6.8 | WSL2 on Windows, 8 logical CPUs, 6.7 GiB RAM, kernel 6.18; the app in Docker Desktop 26.0 |
| Go | 1.27.1, linux/amd64 | 1.27.1, linux/amd64 |
| Code | `main` at `dc24398` (24 October 2026) | `docs/benchmark-results` at `8a9c538` (`dc24398` plus the benchmark feature) and the runner's `-uploads` option |
| Measured | 25 October 2026 | 27 October 2026, 18:40–18:45 (UTC+7), one session |

## Files

| File | Produced by | What it holds |
|---|---|---|
| `crypto_bench.txt` | `go test -run='^$' -bench=. -benchmem -count=3 ./internal/crypto` (run in three parts by size) | Raw `Keystream`, `Encrypt` and `Decrypt` benchmarks from `internal/crypto/bench_test.go`, 1 KiB to 100 MiB, 3 runs each |
| `pipe.csv` | `PIPE_REPORT=docs/benchmark/pipe.csv go test -run TestPipelineReport -count=1 ./internal/files` | Every upload and download through the real `files.Service`, 7 rounds per file kind |
| `field_report.txt` | `FIELD_REPORT=1 go test -run TestFieldReport -count=1 -v ./internal/crypto` | Encrypting and decrypting one whole profile (6 fields, 119 bytes), 3,000 runs per algorithm |
| `ryzen-3550h/crypto_bench.txt`, `pipe.csv` | The same commands on machine B (the benchmarks in three parts: `-bench='//^(1KiB\|1MiB)$'`, `'//^10MiB$'`, `'//^100MiB$'`) | As above |
| `ryzen-3550h/field_report.txt` | The same command, run three times | Three runs, to show the run-to-run spread |
| `ryzen-3550h/crypto_bench_1807.txt` | `go test -run='^$' -bench='/(aes\|des\|rc4)/10MiB' -count=3 ./internal/crypto` at 18:07, 35 minutes before the rest | An earlier 10 MiB run on machine B, kept to show how much one machine drifts |
| `ryzen-3550h/app.csv` | `go run ./scripts/bench -uploads 6 -n 6 -sizes 1MiB,10MiB,100MiB -out docs/benchmark/ryzen-3550h/app.csv` with the stack running | The app's own benchmark records (`/benchmarks/export.csv`) for 6 uploads and 6 downloads per algorithm of each size, through MinIO and MongoDB |

`TestPipelineReport` and `TestFieldReport` skip themselves unless their environment variable is set, so `go test ./...` and CI do not run them.

### `pipe.csv` columns

| Column | Meaning |
|---|---|
| `kind`, `bytes` | File kind and plaintext size: ID card 1 MiB, document 10 MiB, video 100 MiB (random bytes behind the first 4 KiB of a sample in `scripts/testdata/`, so the content check accepts them) |
| `op`, `alg` | `upload` or `download`, and the algorithm |
| `run` | Round 0 to 6; round 0 is a warm-up and is left out of the medians |
| `crypto_ns` | `benchmark.Record.CryptoDuration`: time inside the cipher and HMAC only |
| `total_ns` | `benchmark.Record.TotalDuration`: the whole operation for that algorithm, including waiting on pipes and storage |
| `wall_ns` | Wall-clock time of the whole `Upload` call (all three copies) or `Download` call |

Storage is in memory (`memObjects`, `memMeta` from the files tests), so these numbers leave out MinIO and network time. The upload rows are the app's `encrypt` records; the download rows are its `decrypt` records.

### `app.csv` columns

The export format of `/benchmarks/export.csv`: `created_at,algorithm,operation,file_kind,bytes,crypto_ns,total_ns`. Each upload adds one `encrypt` row per algorithm. Each download adds a `decrypt` row (verify and decrypt) and a `download` row (the whole request); both carry the same `crypto_ns`.

## Summary (medians)

Units: **MiB/s** (2^20 bytes per second) and milliseconds. `go test -bench` prints MB/s (10^6 bytes per second); the values below are converted (1 MiB/s = 1.048576 MB/s). "Cipher + MAC" is `crypto_ns`: the time inside the cipher and the HMAC, without I/O.

### 1. Cipher speed alone (`go test -bench`, 10 MiB, median of 3 runs), MiB/s

| Algorithm | A: Keystream | A: Encrypt | A: Decrypt | B: Keystream | B: Encrypt | B: Decrypt |
|---|---:|---:|---:|---:|---:|---:|
| AES-256-CTR | 9,686 | 2,687 | 1,581 | 3,466 | 897 | 517 |
| DES-CTR | 116 | 113 | 109 | 62 | 59 | 50 |
| RC4 | 948 | 750 | 625 | 298 | 243 | 204 |

*Keystream* is the bare cipher. *Encrypt* adds key generation, key wrapping and the HMAC. *Decrypt* unwraps the keys and reads the data twice (verify the HMAC, then decrypt), so it is slower than Encrypt.

### 2. Through the file pipeline (in-memory storage, median of rounds 1 to 6), ms

Cipher + MAC time for every column except "Whole upload", which is the wall-clock time of the `Upload` call.

| Machine | Kind (size) | Whole upload | Upload: AES | DES | RC4 | Download: AES | DES | RC4 |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| A | ID card (1 MiB) | 11.9 | 0.4 | 9.4 | 1.3 | 0.6 | 9.2 | 1.5 |
| A | Document (10 MiB) | 111 | 3.8 | 92.4 | 13.6 | 5.7 | 90.1 | 15.4 |
| A | Video (100 MiB) | 1,052 | 36.4 | 892 | 132 | 57.4 | 903 | 152 |
| B | ID card (1 MiB) | 28.8 | 1.1 | 21.3 | 5.4 | 1.6 | 17.1 | 5.1 |
| B | Document (10 MiB) | 263 | 9.4 | 209 | 51.7 | 20.7 | 192 | 52.5 |
| B | Video (100 MiB) | 2,994 | 112 | 2,298 | 564 | 174 | 1,779 | 481 |

The whole upload takes about as long as DES alone: the three encryptions run in parallel and the upload waits for the slowest.

### 3. Three methods on one machine (B, 10 MiB), cipher + MAC, ms

| Algorithm | Encrypt: `go test -bench` | Encrypt: pipeline harness | Encrypt: app | Decrypt: `go test -bench` | Decrypt: pipeline harness | Decrypt: app |
|---|---:|---:|---:|---:|---:|---:|
| AES-256-CTR | 11.2 | 9.4 | 12.9 | 19.3 | 20.7 | 20.6 |
| DES-CTR | 168 | 209 | 190 | 198 | 192 | 203 |
| RC4 | 41.2 | 51.7 | 43.4 | 48.9 | 52.5 | 61.5 |

The three methods agree: decrypt within 7% for AES and DES, and within 26% for RC4. Inside an upload, DES and RC4 encrypt up to about 25% slower than alone, because the three encryptions share the CPU (docs/decisions.md D35). Decrypt timings, where one algorithm runs alone, are the cleanest comparison.

### 4. The whole app on machine B (Docker, MinIO, MongoDB; 6 runs each), ms

| Size | Whole upload | Encrypt (cipher + MAC): AES | DES | RC4 | Decrypt (cipher + MAC): AES | DES | RC4 | Whole download: AES | DES | RC4 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 MiB | 77.9 | 1.8 | 26.6 | 5.4 | 2.0 | 21.8 | 5.5 | 21.6 | 45.2 | 27.1 |
| 10 MiB | 382 | 12.9 | 190 | 43.4 | 20.6 | 203 | 61.5 | 102 | 319 | 157 |
| 100 MiB | 5,179 | 154 | 2,272 | 503 | 235 | 2,667 | 728 | 1,972 | 4,114 | 2,069 |

"Whole upload" and "whole download" are the `total_ns` of the `encrypt` and `download` records: they include MinIO, MongoDB and the network. For AES and RC4 most of a download's time is storage and network; for DES the cipher dominates.

### 5. One profile (6 fields, 119 bytes), µs

| Algorithm | A: encrypt median (p95) | A: decrypt median (p95) | B: encrypt median, 3 runs | B: decrypt median, 3 runs |
|---|---:|---:|---:|---:|
| AES-256-CTR | 35 (135) | 28 (126) | 127–146 | 135–155 |
| DES-CTR | 60 (184) | 54 (180) | 179–223 | 188–231 |
| RC4 | 35 (142) | 31 (137) | 121–155 | 127–164 |

These timings include generating and wrapping two keys per field, which costs the same for every algorithm. On both machines DES is 1.4–1.9× slower than AES, but **AES and RC4 are within noise of each other**: they tie on machine A, and on machine B RC4 is faster in two of three runs and AES in one. Do not compare these numbers with file throughput (docs/decisions.md D22).

## Reading the numbers

- **Ranking for files: AES > RC4 > DES, on both machines and with every method.** RC4 is about 2.5× slower than AES on both machines (decrypt: 1,581 vs 625 MiB/s on A, 517 vs 204 on B). DES is 14.5× slower than AES on A and 10.3× slower on B, so the size of the gap depends on the processor.
- **For small items (a profile), only "DES is slowest" holds.** Fixed costs (random keys, key wrapping) dominate, and AES and RC4 cannot be told apart.
- **Absolute numbers depend on the machine and the session.** Machine A is 2–3× faster than B. Machine B itself was 20–30% slower in the session above than 35 minutes earlier (`ryzen-3550h/crypto_bench_1807.txt`, 10 MiB: AES decrypt 636 vs 517 MiB/s, DES 70 vs 50), probably because the laptop slowed down under sustained load. Take every number in the report from one session, and name the machine.
- **Machine A reran the profile timings within about 10%;** machine B's three runs differ by up to 25% (above). Report medians, not single runs.

## Reproduce

```bash
# Cipher speed (one size range at a time keeps each run short)
go test -run='^$' -bench='//^10MiB$' -benchmem -count=3 ./internal/crypto
# Pipeline with in-memory storage
PIPE_REPORT=pipe.csv go test -run TestPipelineReport -count=1 ./internal/files
# One profile
FIELD_REPORT=1 go test -run TestFieldReport -count=1 -v ./internal/crypto
# The whole app (start the stack first: docker compose up -d --build)
go run ./scripts/bench -uploads 6 -n 6 -sizes 1MiB,10MiB,100MiB -out app.csv
```

Close other programs while measuring, keep the laptop on mains power, and run the commands one after another, not in parallel.
