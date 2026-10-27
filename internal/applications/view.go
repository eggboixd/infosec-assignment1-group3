package applications

import "time"

// Card states, also used as CSS modifiers (card--submitted, ...).
const (
	StateGuest      = ""           // logged out: no status shown
	StateClosed     = "closed"     // past the deadline, not applied
	StateSubmitted  = "submitted"  // applied
	StateReady      = "ready"      // everything present, not applied yet
	StateIncomplete = "incomplete" // something is missing
)

// Card is one scholarship with the logged-in student's status, for the home
// grid and the detail page. The page data is built here so the templates
// hold no logic.
type Card struct {
	Scholarship
	State string
	// Missing is the number of missing items while State is incomplete.
	Missing     int
	SubmittedAt time.Time
}

// BuildCards returns one card per scholarship in catalogue order. With
// loggedIn false every card is StateGuest and the other arguments are unused.
func BuildCards(loggedIn bool, r Readiness, submitted map[string]time.Time, now time.Time) []Card {
	all := All()
	cards := make([]Card, len(all))
	for i, s := range all {
		cards[i] = buildCard(s, loggedIn, r, submitted, now)
	}
	return cards
}

func buildCard(s Scholarship, loggedIn bool, r Readiness, submitted map[string]time.Time, now time.Time) Card {
	c := Card{Scholarship: s}
	switch at, ok := submitted[s.ID]; {
	case !loggedIn:
		c.State = StateGuest
	case ok:
		c.State, c.SubmittedAt = StateSubmitted, at
	case !s.Open(now):
		c.State = StateClosed
	case r.Ready():
		c.State = StateReady
	default:
		c.State, c.Missing = StateIncomplete, r.MissingCount()
	}
	return c
}
