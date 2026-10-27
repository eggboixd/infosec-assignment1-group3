# feature/ciphertext-analysis: comparing the ciphers

- Session: `43ec2b53-b63b-4b22-b519-da12b8c97d10`
- Started: 2026-10-17 18:00 (WIB, UTC+7)
- Git branch when started: `feature/ciphertext-analysis`
- Export notes: prompts and replies are verbatim (system reminders and hook context stripped); tool calls are one-line summaries; tool output and hidden reasoning are omitted; secrets are replaced with [REDACTED].

---

## ðŸ§‘ User

I'm on feature/ciphertext-analysis. Read CLAUDE.md, README.md, docs/architecture.md,
docs/decisions.md and internal/crypto. Goal: the assignment asks us to "analyse the difference
between each cipher: running time AND the resulting ciphertext". Rayen does running time
(feature/benchmark). I do the CIPHERTEXT analysis.

Plan:
1. scripts/testdata/: generate small FAKE sample files (no real personal data): a fake KTP-style
   image (PNG/JPG), a PDF, a DOCX, an XLSX, a short MP4 (or tell me if a video must be added by hand),
   a text file, plus a highly repetitive file and a BMP image for the visual test. Keep total size small;
   add a README listing them.
2. cmd/cipheranalysis (or scripts/cipheranalysis): uses the real crypto.Envelope to encrypt each sample
   with AES, DES and RC4 and writes a report (Markdown + CSV) with, per file × algorithm:
   size plaintext vs ciphertext (overhead), Shannon entropy (plaintext vs ciphertext), byte histogram
   chi-square vs uniform, same file encrypted twice → % of differing bytes, first 32 bytes hex,
   and a 1-bit plaintext change → how many ciphertext bytes change (explain why CTR/RC4 only change
   one bit, i.e. no diffusion, and why the HMAC tag catches tampering).
3. "Why not ECB" visual for the report: encrypt the BMP with AES-ECB (demo only, clearly marked as
   NOT used in the app, never stored) vs our AES-CTR, save both as images. Add a #nosec note.
4. PNG charts (entropy and histogram per algorithm) for the report.
Tests for the analysis functions (entropy of all-zero = 0, uniform ≈ 8, chi-square sanity).
Stdlib only unless you justify a dependency. Small commits staged by path, no Claude co-author
lines, don't push. Explain results in simple words at the end. Don't edit until I approve.

## ðŸ¤– Claude

I'll start by reading the files you named.


- _tool:_ **Read** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\docs\architecture.md
- _tool:_ **Read** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\docs\decisions.md
- _tool:_ **Glob** **/*.go
- _tool:_ **Glob** {scripts,cmd,docs}/**/*
- _tool:_ **Read** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\CONTRIBUTING.md
- _tool:_ **Read** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\internal\crypto\crypto.go
- _tool:_ **Read** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\internal\crypto\envelope.go
- _tool:_ **Read** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\internal\crypto\ciphers.go
- _tool:_ **Read** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\README.md
- _tool:_ **Read** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\docs\report.md
- _tool:_ **Bash** cat go.mod && ls && cat .gitignore && git branch -a && cat scripts/bench/README.md && go version
- _tool:_ **Bash** (which ffmpeg python python3 magick; ffmpeg -version | head -1) 2>&1 | head; git log --oneline -3 feature/ciphertext-analysis; grep -n "allow\|mp4\|MP4" internal/files/file.go | head -20; ls internal/crypto; sed -n 1,40p
- _tool:_ **AskUserQuestion**
- _tool:_ **Write** C:\Users\ASUS\.claude\plans\pasted-content-id-09f7-i-m-on-happy-penguin.md
- _tool:_ **ExitPlanMode**
## ðŸ¤– Claude

Approved with those two changes. Starting with the metrics package.


- _tool:_ **Write** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\internal\cipheranalysis\stats.go
- _tool:_ **Write** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\internal\cipheranalysis\stats_test.go
- _tool:_ **Bash** go vet ./internal/cipheranalysis/ && go test ./internal/cipheranalysis/ 2>&1 | tail -20
## ðŸ¤– Claude

Commit 1, staged by path.


- _tool:_ **Bash** git add internal/cipheranalysis/stats.go internal/cipheranalysis/stats_test.go && git commit -q -m "feat(analysis): add entropy, chi-square and diff metrics with tests" && git log --oneline -1
- _tool:_ **Write** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\scripts\gentestdata\main.go
- _tool:_ **Bash** python - <<'EOF' import re p='scripts/gentestdata/main.go' s=open(p,encoding='utf-8').read() a=s.index('\tvar b bytes.Buffer\n\tb.WriteString("BM")') z=s.index('\tfor y := range size {') new='''\tle := binary.LittleEndia
- _tool:_ **Bash** sha256sum scripts/testdata/* > /tmp/a.txt && go run ./scripts/gentestdata >/dev/null && sha256sum scripts/testdata/* | diff - /tmp/a.txt && echo DETERMINISTIC; python -I - <<'EOF' import zipfile for f in ['docx','xlsx']:
- _tool:_ **Write** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\scripts\testdata\README.md
- _tool:_ **Bash** git add scripts/gentestdata/main.go scripts/testdata/README.md scripts/testdata/ktp-fake.png scripts/testdata/ktp-fake.jpg scripts/testdata/sample.pdf scripts/testdata/sample.docx scripts/testdata/sample.xlsx scripts/tes
- _tool:_ **Bash** printf '# Samples are byte-exact (PDF offsets, hashes): never convert line endings.\n* -text\n' > scripts/testdata/.gitattributes && git add scripts/testdata/.gitattributes && git add --renormalize scripts/testdata && gi
## ðŸ¤– Claude

Generator and samples are committed (plus a `.gitattributes` so line-ending conversion can't corrupt the byte-exact files). Next up is the demo-only cipher file and the analyser.


- _tool:_ **Write** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\internal\cipheranalysis\demo.go
- _tool:_ **Write** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\internal\cipheranalysis\analyze.go
- _tool:_ **Write** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\internal\cipheranalysis\demo_test.go
- _tool:_ **Write** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\internal\cipheranalysis\analyze_test.go
- _tool:_ **Bash** python - <<'EOF' p='internal/cipheranalysis/analyze_test.go' s=open(p,encoding='utf-8').read() i=s.index('// failingEncryptor lets') s=s[:i]+'''// errEncryptor fails every Encrypt call. type errEncryptor struct { 	crypto
- _tool:_ **Bash** git add internal/cipheranalysis/demo.go internal/cipheranalysis/demo_test.go internal/cipheranalysis/analyze.go internal/cipheranalysis/analyze_test.go && git commit -q -m "feat(analysis): analyse real envelope ciphertex
- _tool:_ **Bash** python - <<'EOF' p='internal/cipheranalysis/analyze.go' s=open(p,encoding='utf-8').read() s=s.replace('''	PlainHex  string // first HexPrefixLen bytes ''','''	// PlainHist and CipherHist are the byte histograms behind th
## ðŸ¤– Claude

Writing the CSV/Markdown report and the image demo now.


- _tool:_ **Write** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\internal\cipheranalysis\image.go
- _tool:_ **Write** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\internal\cipheranalysis\chart.go
- _tool:_ **Bash** python - <<'EOF' p='internal/cipheranalysis/chart.go' s=open(p,encoding='utf-8').read() s=s.replace('''		maxC := 1 		for _, c := range p.hist {''','''		// Scale to at least twice the expected count, so random noise aroun
- _tool:_ **Write** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\internal\cipheranalysis\report.go
- _tool:_ **Write** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\cmd\cipheranalysis\main.go
- _tool:_ **Bash** gofmt -w cmd/cipheranalysis internal/cipheranalysis && go vet ./cmd/... ./internal/cipheranalysis/ && go run ./cmd/cipheranalysis && ls -l docs/analysis && cat docs/analysis/results.csv | cut -c1-170
- _tool:_ **Read** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\docs\analysis\ecb-demo-ecb.png
- _tool:_ **Read** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\docs\analysis\ecb-demo-aes.png
- _tool:_ **Bash** E="/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"; D=$(pwd -W); for f in entropy histogram-repetitive; do "$E" --headless --disable-gpu --screenshot="C:\\Users\\ASUS\\AppData\\Local\\Temp\\claude\\C--Users
## ðŸ¤– Claude

Rendering the SVG charts in a browser to check how they look.


- _tool:_ **Bash** S="/c/Users/ASUS/AppData/Local/Temp/claude/C--Users-ASUS-Desktop-kuliah-sem5-tkti-groupassignment1/43ec2b53-b63b-4b22-b519-da12b8c97d10/scratchpad"; mkdir -p "$S"; ls "/c/Program Files/Microsoft/Edge/Application/msedge.e
- _tool:_ **Bash** S="C:\\Users\\ASUS\\AppData\\Local\\Temp\\claude\\C--Users-ASUS-Desktop-kuliah-sem5-tkti-groupassignment1\\43ec2b53-b63b-4b22-b519-da12b8c97d10\\scratchpad"; D=$(pwd -W); for f in entropy histogram-repetitive; do "/c/Pro
- _tool:_ **Bash** S="C:/Users/ASUS/AppData/Local/Temp/claude/C--Users-ASUS-Desktop-kuliah-sem5-tkti-groupassignment1/43ec2b53-b63b-4b22-b519-da12b8c97d10/scratchpad"; D=$(pwd -W); timeout 60 "/c/Program Files/Google/Chrome/Application/chr
- _tool:_ **Bash** S="C:/Users/ASUS/AppData/Local/Temp/claude/C--Users-ASUS-Desktop-kuliah-sem5-tkti-groupassignment1/43ec2b53-b63b-4b22-b519-da12b8c97d10/scratchpad"; D=$(pwd -W); timeout 60 "/c/Program Files/Google/Chrome/Application/chr
- _tool:_ **Read** C:\Users\ASUS\AppData\Local\Temp\claude\C--Users-ASUS-Desktop-kuliah-sem5-tkti-groupassignment1\43ec2b53-b63b-4b22-b519-da12b8c97d10\scratchpad\entropy.png
- _tool:_ **Read** C:\Users\ASUS\AppData\Local\Temp\claude\C--Users-ASUS-Desktop-kuliah-sem5-tkti-groupassignment1\43ec2b53-b63b-4b22-b519-da12b8c97d10\scratchpad\hist.png
- _tool:_ **Bash** python - <<'EOF' p='internal/cipheranalysis/report.go' s=open(p,encoding='utf-8').read() old='''b.WriteString("Plaintext does not: text''' new='''b.WriteString("Keys are fresh on every run, so the exact numbers change a 
## ðŸ¤– Claude

The shell heredoc broke on quoting, so I'll write the test file and edit the prose with the file tools instead.


- _tool:_ **Edit** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\internal\cipheranalysis\report.go
- _tool:_ **Write** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\internal\cipheranalysis\output_test.go
- _tool:_ **Bash** gofmt -w internal/cipheranalysis && go vet ./internal/cipheranalysis/ && go test -cover ./internal/cipheranalysis/ 2>&1 | tail -30
- _tool:_ **Write** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\cmd\cipheranalysis\main_test.go
- _tool:_ **Bash** gofmt -l cmd internal scripts; go vet ./... && go test ./cmd/cipheranalysis/ ./internal/cipheranalysis/ 2>&1 | tail
- _tool:_ **Bash** git add internal/cipheranalysis/analyze.go internal/cipheranalysis/report.go internal/cipheranalysis/chart.go internal/cipheranalysis/image.go internal/cipheranalysis/output_test.go && git commit -q -m "feat(analysis): a
- _tool:_ **Write** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\docs\decisions-analysis.md
- _tool:_ **Bash** git add docs/decisions-analysis.md && git commit -q -m "docs: record ciphertext-analysis decisions" 2>&1 | grep -v warning; go vet ./... && go test ./... 2>&1 | tail -15
## ðŸ¤– Claude

I'm stopping here for the MP4, as you asked.

**Please add the video:**
- **Path:** `C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\scripts\testdata\sample.mp4`
- **Maximum size:** 500 KB. Smaller is fine, and 2–5 seconds is enough.
- **Content:** nothing personal. A short screen recording of an empty desktop or a test pattern works.

Tell me when it's in place. I'll then regenerate `docs/analysis/` (report, CSV, charts, ECB pictures) with the video included, check the numbers against the prose, and commit it. The generated files are currently untracked, and I haven't committed them yet.

**State of the branch**
- Seven commits, all staged by path, with no co-author lines. Nothing is pushed.
- `go vet ./...` and `go test ./...` pass. I haven't run the race tests in Docker or gosec yet.
- I did not touch `docs/report.md`, `docs/decisions.md` or `internal/crypto`.

**Decisions to confirm**
- **D15 amendment:** the one-bit and ECB demos need a fixed key. So `internal/cipheranalysis/demo.go` builds DES and RC4 itself, with `#nosec` comments. I recorded this as "Amends D15" in `docs/decisions-analysis.md` (A3). You said to do it this way.
- **Chi-square:** it varies from run to run, because keys are fresh each time. In my run one DES value (sample.txt) came out at 335, above the 293 threshold. That's expected: about 1 in 20 values lands there by chance. The report says so.

**What the results show, in simple words**
- **Ciphertext looks random for all three ciphers.** Files of a few KB or more reach about 7.99 bits per byte, where 8 is the maximum. The repetitive file drops from 4.0 to 7.997. AES, DES and RC4 can't be told apart by looking at one ciphertext.
- **Size.** The ciphertext is exactly as long as the plaintext, because CTR and RC4 need no padding. The overhead is the stored metadata: 168 bytes for AES, 136 for DES and 152 for RC4.
- **Same file encrypted twice.** About 99.6% of bytes differ, which is what unrelated random data gives (255 out of 256).
- **One flipped plaintext bit** flips exactly one ciphertext bit in all three. So CTR and RC4 have no diffusion, and an attacker could flip bits without knowing the key. That's why the HMAC matters: flipping a stored bit made the real `Decrypt` fail with `ErrAuthentication` in every case, and nothing was written out.
- **ECB picture.** AES-ECB still shows the disc, ring and square outline. AES, DES and RC4 through `Envelope` look like noise, and I checked the AES result visually. The mode matters more than the cipher.
- **Where the ciphers really differ.** They differ in security, not in how the ciphertext looks: key size (DES has only 56 effective bits), RC4's known biases, and RC4 being banned in TLS.

## ðŸ§‘ User

sample.mp4 is in scripts/testdata/. Regenerate docs/analysis/ with it, check the numbers against
the prose, commit. Then run the Docker -race test and gosec (if it works with Go 1.27), and show
me the final results and the list of commits.


- _tool:_ **Bash** ls -l scripts/testdata/sample.mp4 && head -c 12 scripts/testdata/sample.mp4 | xxd && git status --short && go run ./cmd/cipheranalysis && grep -E "mp4|Skipped" docs/analysis/report.md | head; grep -n "sample.mp4" docs/an
- _tool:_ **Bash** python -I - <<'EOF' d=open('scripts/testdata/sample.mp4','rb').read() print(len(d), d.count(0)/len(d)) import collections print(collections.Counter(d).most_common(3)) EOF awk -F, 'NR>1{ if($10=="true"){ if($9>m)m=$9; if(
- _tool:_ **Grep** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\internal\cipheranalysis\report.go
- _tool:_ **Bash** python -I - <<'PYEOF' p='internal/cipheranalysis/report.go' s=open(p,encoding='utf-8').read() a=s.index('\tb.WriteString("- **All three look random.**') z=s.index('\tb.WriteString("- **Differences between the ciphers') n
- _tool:_ **Read** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\internal\cipheranalysis\report.go
## ðŸ¤– Claude

Python mangled the line breaks inside two strings. Fixing those lines directly.


- _tool:_ **Edit** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\internal\cipheranalysis\report.go
- _tool:_ **Edit** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\internal\cipheranalysis\report.go
- _tool:_ **Bash** gofmt -l cmd/cipheranalysis internal/cipheranalysis; go vet ./internal/cipheranalysis/ && go test ./internal/cipheranalysis/ ./cmd/cipheranalysis/ 2>&1|tail -3 && go run ./cmd/cipheranalysis && sed -n '/## 7/,$p' docs/an
- _tool:_ **Bash** git add scripts/testdata/sample.mp4 && git commit -q -m "chore(analysis): add hand-made sample.mp4" 2>&1 | grep -v warning; git add internal/cipheranalysis/report.go && git commit -q -m "fix(analysis): correct report pro
- _tool:_ **Bash** grep -n "gosec" -r Makefile .github 2>/dev/null | head; (docker run --rm -v "$(pwd -W):/src" -w /src golang:1.27.1 go test -race ./... 2>&1 | tail -20)
## ðŸ¤– Claude

Git Bash rewrote the `-w /src` path. I'll rerun with path conversion disabled and run gosec in the same container.


- _tool:_ **Bash** export MSYS_NO_PATHCONV=1 && docker run --rm -v "$(pwd -W):/src" -w /src golang:1.27.1 sh -c 'go test -race ./... 2>&1 | tail -20; echo ---GOSEC---; go run github.com/securego/gosec/v2/cmd/gosec@v2.29.0 ./... 2>&1 | tail
## ðŸ¤– Claude

Race tests pass and gosec runs on Go 1.27. It flags two G115 conversions in `image.go`. While fixing them I also noticed that huge BMP dimensions could overflow the size check, so I'm capping them.


- _tool:_ **Read** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\internal\cipheranalysis\image.go
- _tool:_ **Edit** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\internal\cipheranalysis\image.go
- _tool:_ **Edit** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\internal\cipheranalysis\image.go
- _tool:_ **Edit** C:\Users\ASUS\Desktop\kuliah\sem5\tkti\groupassignment1\internal\cipheranalysis\output_test.go
- _tool:_ **Bash** cat >> internal/cipheranalysis/output_test.go <<'XEOF'  func TestBMPTopDownIsAccepted(t *testing.T) { 	bm := testBMP(8, 4) 	// Height -4 as two's complement: rows stored top-down. 	bm[22], bm[23], bm[24], bm[25] = 0xfc, 
## ðŸ¤– Claude

That last run regenerated the outputs with new random keys. I'll restore the committed run, since that's the one I checked against the prose, and commit only the fix.


- _tool:_ **Bash** git checkout -- docs/analysis && git add internal/cipheranalysis/image.go internal/cipheranalysis/output_test.go && git commit -q -m "fix(analysis): parse BMP dimensions without signed conversions and cap their size" 2>&
## ðŸ¤– Claude

The MP4 is in, the report is regenerated and committed, and the Docker `-race` run and gosec are clean. I'm showing the numbers from the committed run.

**Corrections from checking the prose against the numbers**
- **MP4 entropy.** I had written that compressed formats like MP4 start with high plaintext entropy. That was wrong for the clip: it is 71% zero bytes, so plaintext entropy is only 3.13. I rewrote the bullet to say plaintext entropy depends on the file and that encryption brings all of them to about the same level.
- **Metadata overhead.** I had written that RC4 has less overhead than DES. The real order is DES 136 B, RC4 152 B, AES 168 B, because RC4 has no IV but a 32-byte key. I fixed the prose.
- **BMP parser, found by gosec.** Gosec flagged two G115 signed conversions in `image.go`. While fixing them I found that a BMP header with huge dimensions could overflow the size check. I now parse the dimensions without signed conversions and cap them at 16384, with tests for huge, zero-height and top-down BMPs.

**Checks**
- **Race tests.** `go vet ./...` and `go test -race ./...` in `golang:1.27.1` pass for every package.
- **Gosec.** Gosec v2.29.0 runs on Go 1.27 and reports 0 issues over `cmd`, `internal` and `scripts`. Its exit code was hidden behind `tail`, so I'm relying on `-quiet` printing nothing. A full `./...` run also scans your untracked `.playwright-mcp/` folder. CI will not see that folder, so I left it out.
- **Docker path.** In Git Bash, Docker needs `MSYS_NO_PATHCONV=1`, or it rewrites `-w /src`.
- **Local gofmt.** I didn't run `gofmt -l` over the whole repo, since `autocrlf` makes it noisy. My files are formatted.

**Final results**

I checked the table below (committed run) against the prose. The prose holds: every row reaches high ciphertext entropy and passes the tamper and round-trip checks.

| File | Plaintext → ciphertext entropy | Chi-square range (3 ciphers) | Ciphertext bits changed by a 1-bit plaintext flip |
|---|---|---|---|
| ktp-fake.jpg / .png | 7.55 / 7.87 → ~7.99 / 8.00 | 226–275 | 1 |
| pattern.bmp | 1.15 → 7.999 | 252–259 | 1 |
| repetitive.txt | 4.00 → 7.997 | 240–292 | 1 |
| sample.mp4 | 3.13 → 7.993–7.995 | 204–280 | 1 |
| sample.txt / .xlsx | 4.36 / 7.41 → ~7.94–7.95 / ~7.92–7.93 | 239–335 | 1 |
| sample.docx / .pdf | 7.03 / 4.92 → ~7.83 / ~7.7 | n/a (under 1280 B) | 1 |

- **Chi-square above the threshold.** Across the runs I looked at, a few reliable values landed above 293, up to 335 (sample.txt DES) and 304. That's the expected 1-in-20 chance, and the report says so.
- **Size and metadata.** Ciphertext length equals plaintext length in all 27 rows. Stored metadata is 168 B for AES, 136 B for DES and 152 B for RC4.
- **ECB picture.** In the committed run, ECB and the original image both have 12,219 of 12,288 blocks repeating. AES-CTR, DES-CTR and RC4 through `Envelope` have 0.
- **Re-running changes the numbers.** Re-running `go run ./cmd/cipheranalysis` regenerates `docs/analysis/` with new random keys, so the files show as modified in git. I restored the committed run after my test run. Only re-run it when you want new numbers.

**Commits on `feature/ciphertext-analysis` (11, none pushed, staged by path, no co-author lines)**
```
c30cf0b fix(analysis): parse BMP dimensions without signed conversions and cap their size
fbac7c1 docs(analysis): add generated ciphertext analysis report, charts and ECB pictures
b745318 fix(analysis): correct report prose on entropy and metadata overhead
5d0f16d chore(analysis): add hand-made sample.mp4
05fbcee docs: record ciphertext-analysis decisions
6ab36ca feat(analysis): add cipheranalysis command
83aed6c feat(analysis): add CSV/Markdown report, SVG charts and ECB picture helpers
db1f044 feat(analysis): analyse real envelope ciphertext and add demo-only fixed-key ciphers
d18039a chore(analysis): keep sample files byte-exact with .gitattributes
f5e92ac feat(analysis): add fake sample data generator and samples
35cf291 feat(analysis): add entropy, chi-square and diff metrics with tests
```
The working tree has only the untracked files that were there before I started (`.playwright-mcp/`, `CLAUDE.md`, `docs/claude-prompts.md`).

**Before you open the PR**
- Skim `docs/analysis/report.md` and the PNG/SVG files, since you'll defend them to the TA.
- Link `docs/analysis/report.md` into the main report after Rayen's branch merges.
- I did not open a PR or push.

