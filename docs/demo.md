# Final demo checklist

## Prerequisites

Before the reset, follow the README setup: create `.env`, generate separate `MASTER_KEY` and `SESSION_SECRET` values, and set non-default MongoDB and MinIO passwords. The demo script only resets Compose volumes and starts services; it does not initialize credentials or create an account.

## Reset and start clean

From PowerShell at the repository root:

```powershell
./scripts/demo.ps1
```

The script asks for the literal word `RESET` before running `docker compose down -v`. This permanently deletes the Compose project's MongoDB and MinIO volumes, including users, files, sessions, private data, and benchmark records. It then rebuilds and starts the services and waits for `/healthz`. Use a disposable demo environment only.

If the script reports that the app is not healthy, inspect `docker compose ps` and `docker compose logs app mongo minio` before continuing.

## Demo flow

1. Open `http://localhost:8080/register` and create a demo account using a password of at least 12 characters.
2. Sign in; you land on the scholarship home page. Open **My application** (step 1, **Applicant data**). Enter clearly fake values and save; show that the app confirms the record without exposing stored fields.
3. Open step 2, **Documents**, and upload generated samples from `scripts/testdata/` into the six checklist slots (for example `ktp-fake.png` for the KTP, `sample.pdf` for the CV and transcript, `sample.docx`, `sample.xlsx` and `sample.mp4`). Do not use real personal data.
4. Show the uploaded documents. Explain that each file has three independent encrypted objects in MinIO and metadata/name ciphertext in MongoDB. Then open a scholarship from the home page and submit; the chosen scholarship is also stored encrypted with all three ciphers.
5. Download the document once as AES, DES, and RC4. Confirm each downloaded file matches the original sample.
6. Open **Benchmarks**. Show the recorded encryption/decryption/download rows and per-algorithm averages. Export `benchmarks.csv`.
7. For repeated measurements, run `scripts/bench/download_benchmark.py` as described in `scripts/bench/README.md`; compare client timings with the app's exported server timings.
8. Corrupt a test variant only if you have a safe developer procedure available. The expected behavior is a generic integrity error and no plaintext response.
9. Delete a file in the UI and show it disappears from its slot; sign out.

## Presenter notes

- State the machine, Go/Docker versions, file sizes, and repeat count when discussing timing results.
- DES and RC4 are included for the course comparison; they are not recommendations for protecting real data.
- A clean reset erases the previous demo data. Never point this script at a Compose project whose volumes contain data you need.
