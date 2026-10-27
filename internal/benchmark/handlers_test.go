package benchmark

import (
	"testing"

	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
)

func TestSummarize(t *testing.T) {
	records := []Record{
		{Algorithm: crypto.AES, Operation: OpEncrypt, CryptoDuration: 2_000_000, TotalDuration: 4_000_000},
		{Algorithm: crypto.AES, Operation: OpEncrypt, CryptoDuration: 4_000_000, TotalDuration: 8_000_000},
		{Algorithm: crypto.DES, Operation: OpDecrypt, CryptoDuration: 9_000_000, TotalDuration: 12_000_000},
	}
	got := summarize(records)
	if len(got) != 2 {
		t.Fatalf("got %d summaries, want 2", len(got))
	}
	if got[0].Algorithm != crypto.AES || got[0].Operation != OpEncrypt || got[0].Count != 2 || got[0].CryptoMillis != 3 || got[0].TotalMillis != 6 {
		t.Errorf("first summary = %+v", got[0])
	}
	if got[1].Algorithm != crypto.DES || got[1].Operation != OpDecrypt || got[1].Count != 1 {
		t.Errorf("second summary = %+v", got[1])
	}
}
