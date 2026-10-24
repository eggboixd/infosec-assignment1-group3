# Test data for the ciphertext analysis

Small **fake** sample files for `cmd/cipheranalysis`. None of them contains real personal data or a real ID card.
Regenerate everything except the video with `go run ./scripts/gentestdata` (output is deterministic).

| File | What it is | Why it is here |
|---|---|---|
| `ktp-fake.png` | Drawn KTP-style card layout (coloured bands, grey bars, noisy "photo"), no text | ID card image, lossless compressed |
| `ktp-fake.jpg` | Same drawing as JPEG | ID card image, lossy compressed |
| `sample.pdf` | One-page PDF saying it is a fake sample | PDF document |
| `sample.docx` | Minimal Word file, 40 fake paragraphs | DOCX document (a ZIP inside) |
| `sample.xlsx` | Minimal Excel file, 60 fake rows | XLSX document (a ZIP inside) |
| `sample.txt` | About 4 KB of English prose | Low-entropy text |
| `repetitive.txt` | The same 16 bytes repeated 4096 times (64 KiB) | Worst case for ECB; shows CTR/RC4 hide repetition |
| `pattern.bmp` | 256x256 uncompressed 24-bit image of a disc, ring and square | Input for the "why not ECB" picture |
| `sample.mp4` | **Added by hand** (see below) | Video file |

## sample.mp4 (add by hand)

The Go standard library cannot encode video, so this one is not generated. Put a tiny clip at
`scripts/testdata/sample.mp4`, **at most 500 KB**, 2 to 5 seconds, containing nothing personal (a screen recording of an
empty desktop or a test pattern is fine). If the file is missing, `cmd/cipheranalysis` skips it and says so.
