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
