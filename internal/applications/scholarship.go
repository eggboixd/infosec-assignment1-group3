// Package applications lists the scholarships of the BeasiswaKu portal and
// stores each student's applications to them. Which scholarship a student
// applied to is private (a need-based scholarship implies a low family
// income), so it is encrypted with every algorithm like the profile fields.
package applications

import (
	"slices"
	"time"
)

// Scholarship is one programme students can apply to. The catalogue is fixed
// in code (docs/decisions.md D38); the programmes and their sponsor are
// fictional.
type Scholarship struct {
	// ID is the URL slug, and the value that is encrypted in an Application.
	ID      string
	Name    string
	Sponsor string
	// Kind is shown on the card ribbon: "Merit" or "Need-based".
	Kind   string
	Amount string
	// For says who may apply.
	For     string
	Summary string
	// Deadline is the last moment an application is accepted.
	Deadline time.Time
}

// Open reports whether applications are still accepted at now.
func (s Scholarship) Open(now time.Time) bool {
	return !now.After(s.Deadline)
}

// wib is Western Indonesia Time, in which the deadlines are announced.
var wib = time.FixedZone("WIB", 7*60*60)

const sponsor = "Yayasan Cendekia Nusantara"

// scholarships is the catalogue, in display order.
var scholarships = []Scholarship{
	{
		ID:       "prestasi-nusantara",
		Name:     "Beasiswa Prestasi Nusantara",
		Sponsor:  sponsor,
		Kind:     "Merit",
		Amount:   "Rp 6.000.000 per semester",
		For:      "Undergraduates with a GPA of at least 3.50",
		Summary:  "For students whose grades put them at the top of their year. Your academic transcript and a recommendation letter from a lecturer carry the most weight.",
		Deadline: time.Date(2027, time.January, 31, 23, 59, 59, 0, wib),
	},
	{
		ID:       "bakti-keluarga",
		Name:     "Beasiswa Bakti Keluarga",
		Sponsor:  sponsor,
		Kind:     "Need-based",
		Amount:   "Full tuition + Rp 1.500.000 per month",
		For:      "Undergraduates from low-income families",
		Summary:  "For students who could not continue their studies without support. Your parents' salary slip shows the family income the committee assesses.",
		Deadline: time.Date(2027, time.January, 31, 23, 59, 59, 0, wib),
	},
}

// All returns a copy of the catalogue in display order.
func All() []Scholarship {
	return slices.Clone(scholarships)
}

// Find returns the scholarship with the given ID.
func Find(id string) (Scholarship, bool) {
	for _, s := range scholarships {
		if s.ID == id {
			return s, true
		}
	}
	return Scholarship{}, false
}
