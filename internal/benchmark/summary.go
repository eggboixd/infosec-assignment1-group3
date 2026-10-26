package benchmark

import (
	"cmp"
	"math"
	"slices"
	"time"

	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
)

// SizeClass groups records by plaintext size, so a 1 KiB file and a 100 MiB
// video are not averaged together. Each class holds sizes up to and
// including Max; the benchmark script uses exactly those sizes.
type SizeClass struct {
	Label string
	Max   int64
}

// sizeClasses are ordered by Max. The last one catches everything larger.
var sizeClasses = []SizeClass{
	{"≤ 1 KiB", 1 << 10},
	{"1–64 KiB", 64 << 10},
	{"64 KiB–1 MiB", 1 << 20},
	{"1–16 MiB", 16 << 20},
	{"16–128 MiB", 128 << 20},
	{"> 128 MiB", math.MaxInt64},
}

// classOf returns the size class of n bytes.
func classOf(n int64) SizeClass {
	for _, c := range sizeClasses {
		if n <= c.Max {
			return c
		}
	}
	return sizeClasses[len(sizeClasses)-1]
}

// Durations summarises one set of durations.
type Durations struct {
	Sum  time.Duration
	Min  time.Duration
	Mean time.Duration
	// StdDev is the sample standard deviation, 0 for a single record.
	StdDev time.Duration

	// Welford's running mean and sum of squared deviations, in nanoseconds.
	mean, m2 float64
}

// MeanMS, StdDevMS and MinMS return the durations in milliseconds, for
// the page.
func (d Durations) MeanMS() float64   { return ms(d.Mean) }
func (d Durations) StdDevMS() float64 { return ms(d.StdDev) }
func (d Durations) MinMS() float64    { return ms(d.Min) }

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

func (d *Durations) add(n int, v time.Duration) {
	d.Sum += v
	if n == 1 || v < d.Min {
		d.Min = v
	}
	x := float64(v)
	delta := x - d.mean
	d.mean += delta / float64(n)
	d.m2 += delta * (x - d.mean)
	d.Mean = time.Duration(math.Round(d.mean))
	if n > 1 {
		d.StdDev = time.Duration(math.Round(math.Sqrt(d.m2 / float64(n-1))))
	}
}

// Stat is the summary of one group: one operation, file kind, size class
// and algorithm.
type Stat struct {
	Operation Operation
	// FileKind is empty for private-data (field) records.
	FileKind  string
	Size      SizeClass
	Algorithm crypto.Algorithm
	Count     int
	// Bytes is the total plaintext processed by the group.
	Bytes  int64
	Crypto Durations
	Total  Durations
}

// CryptoMiBPerSec is the group's throughput counting crypto time only: total
// bytes over total crypto time. It is 0 when no time was recorded.
func (s Stat) CryptoMiBPerSec() float64 { return mibPerSec(s.Bytes, s.Crypto.Sum) }

// TotalMiBPerSec is the throughput counting the whole operation, I/O included.
func (s Stat) TotalMiBPerSec() float64 { return mibPerSec(s.Bytes, s.Total.Sum) }

func mibPerSec(n int64, d time.Duration) float64 {
	if d <= 0 {
		return 0
	}
	return float64(n) / (1 << 20) / d.Seconds()
}

// Summarizer accumulates records into Stats one at a time, so a summary of
// many records never holds them all in memory.
type Summarizer struct {
	groups map[statKey]*Stat
}

type statKey struct {
	op   Operation
	kind string
	size int64
	alg  crypto.Algorithm
}

// Add counts r in its group.
func (s *Summarizer) Add(r Record) {
	if s.groups == nil {
		s.groups = map[statKey]*Stat{}
	}
	class := classOf(r.Bytes)
	k := statKey{r.Operation, r.FileKind, class.Max, r.Algorithm}
	st, ok := s.groups[k]
	if !ok {
		st = &Stat{Operation: r.Operation, FileKind: r.FileKind, Size: class, Algorithm: r.Algorithm}
		s.groups[k] = st
	}
	st.Count++
	st.Bytes += r.Bytes
	st.Crypto.add(st.Count, r.CryptoDuration)
	st.Total.add(st.Count, r.TotalDuration)
}

// Stats returns the groups in a stable order: operation (encrypt, decrypt,
// download), then file kind, size and algorithm, so the three algorithms of
// one comparison sit next to each other.
func (s *Summarizer) Stats() []Stat {
	out := make([]Stat, 0, len(s.groups))
	for _, st := range s.groups {
		out = append(out, *st)
	}
	slices.SortFunc(out, func(a, b Stat) int {
		return cmp.Or(
			cmp.Compare(opRank(a.Operation), opRank(b.Operation)),
			cmp.Compare(a.Operation, b.Operation),
			cmp.Compare(a.FileKind, b.FileKind),
			cmp.Compare(a.Size.Max, b.Size.Max),
			cmp.Compare(algRank(a.Algorithm), algRank(b.Algorithm)),
			cmp.Compare(a.Algorithm, b.Algorithm),
		)
	})
	return out
}

// Summarize is Summarizer for records already in memory.
func Summarize(records []Record) []Stat {
	var s Summarizer
	for _, r := range records {
		s.Add(r)
	}
	return s.Stats()
}

func opRank(op Operation) int {
	if i := slices.Index([]Operation{OpEncrypt, OpDecrypt, OpDownload}, op); i >= 0 {
		return i
	}
	return math.MaxInt
}

func algRank(a crypto.Algorithm) int {
	if i := slices.Index(crypto.All(), a); i >= 0 {
		return i
	}
	return math.MaxInt
}
