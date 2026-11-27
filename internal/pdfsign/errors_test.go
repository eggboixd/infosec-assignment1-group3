package pdfsign

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestRateLimitErrorMatchesSentinel(t *testing.T) {
	err := fmt.Errorf("sign: %w", &RateLimitError{RetryAfter: 90 * time.Second})
	if !errors.Is(err, ErrRateLimited) {
		t.Fatal("errors.Is(err, ErrRateLimited) = false")
	}
	var rl *RateLimitError
	if !errors.As(err, &rl) || rl.RetryAfter != 90*time.Second {
		t.Fatalf("errors.As gave %+v", rl)
	}
	if errors.Is(err, ErrBadSignature) {
		t.Fatal("RateLimitError matches an unrelated sentinel")
	}
}

// Every exported error must be its own value, so errors.Is in the UI can
// tell them apart.
func TestErrorsAreDistinct(t *testing.T) {
	all := []error{
		ErrNotPDF, ErrEncrypted, ErrUnsupportedPDF, ErrTooLarge, ErrExistingSignatureInvalid,
		ErrTooManySignatures, ErrRateLimited, ErrBadSignature, ErrByteRange, ErrMalformedSignature,
		ErrUnsupportedFormat, ErrUnknownSigner, ErrKeyMismatch,
	}
	seen := map[string]bool{}
	for i, a := range all {
		if seen[a.Error()] {
			t.Errorf("duplicate error text %q", a)
		}
		seen[a.Error()] = true
		for j, b := range all {
			if i != j && errors.Is(a, b) {
				t.Errorf("errors.Is(%v, %v) = true", a, b)
			}
		}
	}
}
