# Benchmark results: AES-256-CTR vs DES-CTR vs RC4

Raw data behind the running-time numbers in the report. The ciphertext analysis (entropy, chi-square, bit flips, tampering, ECB) lives separately in [`docs/analysis/`](../analysis/report.md).

## Environment

| Item | Value |
|---|---|
| Host | Acer Predator Helios Neo 16S, Intel Core Ultra 7 255HX |
| Runtime | Linux VM on that laptop, 2 vCPUs, 3.9 GB RAM, kernel 6.8 |
| Go | 1.27.1, linux/amd64 |
| Code | `main` at `dc24398` (24 October 2026) |
| Measured | 25 October 2026 |

## Files

| File | Produced by | What it holds |
|---|---|---|
| `crypto_bench.txt` | `go test -run='^$' -bench=. -benchmem -count=3 ./internal/crypto` (run in three parts by size) | Raw `Keystream`, `Encrypt` and `Decrypt` benchmarks from `internal/crypto/bench_test.go`, 1 KiB to 100 MiB, 3 runs each |
| `pipe.csv` | `PIPE_REPORT=docs/benchmark/pipe.csv go test -run TestPipelineReport -count=1 ./internal/files` | Every upload and download through the real `files.Service`, 7 rounds per file kind |
| `field_report.txt` | `FIELD_REPORT=1 go test -run TestFieldReport -count=1 -v ./internal/crypto` | Encrypting and decrypting one whole profile (6 fields, 119 bytes), 3,000 runs per algorithm |

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

Storage is in memory (`memObjects`, `memMeta` from the files tests), so the numbers leave out MinIO and network time. These are the same records the app stores in MongoDB.

## Summary (medians)

Throughput for a 10 MiB input, MB/s (1 MB = 10^6 bytes):

| Algorithm | Keystream (raw cipher) | Encrypt (envelope) | Decrypt (envelope) |
|---|---:|---:|---:|
| AES-256-CTR | 10,157 | 2,818 | 1,657 |
| DES-CTR | 122 | 119 | 115 |
| RC4 | 994 | 786 | 655 |

Through the file pipeline, ms (median of rounds 1 to 6):

| Kind (size) | Whole upload | Cipher + MAC: AES | DES | RC4 | Download: AES | DES | RC4 |
|---|---:|---:|---:|---:|---:|---:|---:|
| ID card (1 MiB) | 11.9 | 0.4 | 9.5 | 1.3 | 0.6 | 9.3 | 1.6 |
| Document (10 MiB) | 111 | 3.8 | 92.4 | 13.6 | 6.9 | 91.8 | 16.9 |
| Video (100 MiB) | 1,052 | 36.4 | 892 | 132 | 68.7 | 918 | 164 |

One profile (6 fields, 119 bytes), µs:

| Algorithm | Encrypt median | Encrypt p95 | Decrypt median | Decrypt p95 |
|---|---:|---:|---:|---:|
| AES-256-CTR | 35 | 135 | 28 | 126 |
| DES-CTR | 60 | 184 | 54 | 180 |
| RC4 | 35 | 142 | 31 | 137 |

Absolute numbers change from machine to machine and run to run. A re-run on the same laptop gave profile timings within about 10% of these. The ranking (AES fastest, DES slowest) and the DES-paced upload should hold on any amd64 processor with AES-NI.
