# Final demo checklist

## Reset and start clean

From PowerShell at the repository root:

```powershell
./scripts/demo.ps1
```

The script asks for the literal word `RESET` before running `docker compose down -v`. This permanently deletes the Compose project's MongoDB and MinIO volumes, including users, files, sessions, private data, and benchmark records. It then rebuilds and starts the services and waits for `/healthz`. Use a disposable demo environment only.

If the script reports that the app is not healthy, inspect `docker compose ps` and `docker compose logs app mongo minio` before continuing.

## Demo flow

1. Open `http://localhost:8080/register` and create a demo account using a password of at least 12 characters.
2. Sign in and open **Private data**. Enter clearly fake values and save; show that the app confirms the record without exposing stored fields.
3. Return to **Files** and upload generated samples from `scripts/testdata/` (for example `sample.pdf`, `ktp-fake.png`, and `sample.mp4`). Do not use real personal data.
4. Show the uploaded rows. Explain that each file has three independent encrypted objects in MinIO and metadata/name ciphertext in MongoDB.
5. Download the document once as AES, DES, and RC4. Confirm each downloaded file matches the original sample.
6. Open **Benchmarks**. Show the recorded encryption/decryption/download rows and per-algorithm averages. Export `benchmarks.csv`.
7. For repeated measurements, run `scripts/bench/download_benchmark.py` as described in `scripts/bench/README.md`; compare client timings with the app's exported server timings.
8. Corrupt a test variant only if you have a safe developer procedure available. The expected behavior is a generic integrity error and no plaintext response.
9. Delete a file in the UI and show it disappears from the list; sign out.

## Presenter notes

- State the machine, Go/Docker versions, file sizes, and repeat count when discussing timing results.
- DES and RC4 are included for the course comparison; they are not recommendations for protecting real data.
- A clean reset erases the previous demo data. Never point this script at a Compose project whose volumes contain data you need.
from pathlib import Path
p = Path('scripts/bench/download_benchmark.py')
s = p.read_text(encoding='utf-8-sig')
s = s.replace('''            for file_id, name in files:
                for algorithm in ALGORITHMS:
                    for iteration in range(1, args.repeat + 1):
                        url = f"{base}/files/{file_id}/download?alg={algorithm}"
                        started = time.perf_counter_ns()
                        request = Request(url, headers={"Cache-Control": "no-cache"})
                        with opener.open(request, timeout=1800) as response:
                            status = response.status
                            byte_count = read_all(response)
                        elapsed = time.perf_counter_ns() - started
                        writer.writerow((file_id, name, algorithm, iteration, byte_count, elapsed, status))
                        out.flush()
                        print(f"{name}: {algorithm} {iteration}/{args.repeat}: {byte_count} bytes in {elapsed / 1e6:.3f} ms")
''','''            for file_id, name in files:
                for iteration in range(1, args.repeat + 1):
                    # Rotate order each repetition to reduce fixed-order bias.
                    offset = (iteration - 1) % len(ALGORITHMS)
                    algorithm_order = ALGORITHMS[offset:] + ALGORITHMS[:offset]
                    for algorithm in algorithm_order:
                        url = f"{base}/files/{file_id}/download?alg={algorithm}"
                        started = time.perf_counter_ns()
                        request = Request(url, headers={"Cache-Control": "no-cache"})
                        with opener.open(request, timeout=1800) as response:
                            status = response.status
                            byte_count = read_all(response)
                        elapsed = time.perf_counter_ns() - started
                        writer.writerow((file_id, name, algorithm, iteration, byte_count, elapsed, status))
                        out.flush()
                        print(f"{name}: {algorithm} {iteration}/{args.repeat}: {byte_count} bytes in {elapsed / 1e6:.3f} ms")
''')
p.write_text(s, encoding='utf-8', newline='\n')
PY
Remove-Item -LiteralPath scripts\bench\__pycache__ -Recurse -Force -ErrorAction SilentlyContinue
@'
# Demo prerequisites

Before the reset, follow the README setup: create `.env`, generate separate `MASTER_KEY` and `SESSION_SECRET` values, and set non-default MongoDB and MinIO passwords. The demo script only resets Compose volumes and starts services; it does not initialize credentials or create an account.
