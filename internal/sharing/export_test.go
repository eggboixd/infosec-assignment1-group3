package sharing

import "time"

// SetClock replaces the service's clock and the send limiter's clock.
func (s *Service) SetClock(f func() time.Time) {
	s.now = f
	s.limiter.now = f
}
