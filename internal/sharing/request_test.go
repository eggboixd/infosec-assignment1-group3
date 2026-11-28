package sharing

import (
	"errors"
	"testing"
	"time"
)

func TestEffectiveStatus(t *testing.T) {
	exp := time.Date(2026, 12, 1, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		stored Status
		now    time.Time
		want   Status
	}{
		{"pending just before expiry", StatusPending, exp.Add(-time.Nanosecond), StatusPending},
		{"pending at exactly expiry", StatusPending, exp, StatusExpired},
		{"approved before expiry", StatusApproved, exp.Add(-time.Hour), StatusApproved},
		{"approved after expiry", StatusApproved, exp.Add(time.Second), StatusExpired},
		{"rejected stays rejected", StatusRejected, exp.Add(time.Hour), StatusRejected},
		{"cancelled stays cancelled", StatusCancelled, exp.Add(time.Hour), StatusCancelled},
		{"revoked stays revoked", StatusRevoked, exp.Add(time.Hour), StatusRevoked},
		{"expired stays expired", StatusExpired, exp.Add(time.Hour), StatusExpired},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Request{Status: tt.stored, ExpiresAt: exp}
			if got := r.EffectiveStatus(tt.now); got != tt.want {
				t.Fatalf("EffectiveStatus = %q, want %q", got, tt.want)
			}
			wantOpen := tt.want == StatusPending || tt.want == StatusApproved
			if got := r.Open(tt.now); got != wantOpen {
				t.Fatalf("Open = %v, want %v", got, wantOpen)
			}
		})
	}
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{"1d", 24 * time.Hour, false},
		{"7d", 7 * 24 * time.Hour, false},
		{"", 7 * 24 * time.Hour, false},
		{"30d", 30 * 24 * time.Hour, false},
		{"2d", 0, true},
		{"7D", 0, true},
		{"-1d", 0, true},
		{"7d ", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseDuration(tt.in)
			if tt.wantErr {
				if !errors.Is(err, ErrBadDuration) {
					t.Fatalf("err = %v, want ErrBadDuration", err)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("ParseDuration(%q) = %v, %v; want %v", tt.in, got, err, tt.want)
			}
		})
	}
}
