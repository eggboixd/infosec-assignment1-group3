package benchmark

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
)

func TestMeasure(t *testing.T) {
	errBoom := errors.New("boom")
	tests := []struct {
		name       string
		cryptoTime time.Duration
		bytes      int64
		err        error
	}{
		{"success", 3 * time.Millisecond, 1024, nil},
		{"zero crypto time", 0, 0, nil},
		{"failure keeps partial record", time.Millisecond, 10, errBoom},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec, err := Measure(context.Background(), crypto.AES, OpEncrypt, func(ctx context.Context) (int64, error) {
				clock := crypto.ClockFrom(ctx)
				if clock == nil {
					t.Fatal("fn context carries no clock")
				}
				clock.Add(tt.cryptoTime)
				return tt.bytes, tt.err
			})
			if !errors.Is(err, tt.err) {
				t.Fatalf("err = %v, want %v", err, tt.err)
			}
			if rec.Algorithm != crypto.AES || rec.Operation != OpEncrypt {
				t.Errorf("rec = %+v, want aes/encrypt", rec)
			}
			if rec.Bytes != tt.bytes {
				t.Errorf("Bytes = %d, want %d", rec.Bytes, tt.bytes)
			}
			if rec.CryptoDuration != tt.cryptoTime {
				t.Errorf("CryptoDuration = %v, want %v", rec.CryptoDuration, tt.cryptoTime)
			}
			if rec.TotalDuration < 0 {
				t.Errorf("TotalDuration = %v, want >= 0", rec.TotalDuration)
			}
			if rec.CreatedAt.IsZero() {
				t.Error("CreatedAt is zero")
			}
		})
	}
}
