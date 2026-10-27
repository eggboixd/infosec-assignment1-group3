package benchmark

import (
	"cmp"
	"context"
	"encoding/csv"
	"fmt"
	"log/slog"
	"net/http"
	"slices"

	"github.com/gin-gonic/gin"

	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
)

type storeReader interface {
	List(context.Context, int64) ([]Record, error)
	Iterate(context.Context, func(Record) error) error
}

// Handler serves the benchmark views.
type Handler struct {
	store storeReader
}

// Summary is the average recorded time for one algorithm and operation.
type Summary struct {
	Algorithm    crypto.Algorithm
	Operation    Operation
	Count        int
	CryptoMillis float64
	TotalMillis  float64
}

const pageRecordLimit = 1000

// NewHandler returns a Handler reading from store.
func NewHandler(store storeReader) *Handler {
	return &Handler{store: store}
}

// index shows recent measurements and averages grouped by algorithm and
// operation.
func (h *Handler) index(c *gin.Context) {
	records, err := h.store.List(c.Request.Context(), pageRecordLimit)
	if err != nil {
		slog.Error("benchmark: list", "error", err)
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{
			"Title": "Benchmarks", "Status": http.StatusInternalServerError,
			"Message": "Measurements could not be loaded. Please try again.",
		})
		return
	}
	c.HTML(http.StatusOK, "benchmarks.html", gin.H{
		"Title": "Benchmarks", "Records": records, "Summaries": summarize(records),
	})
}

// exportCSV streams every measurement from MongoDB in newest-first order.
func (h *Handler) exportCSV(c *gin.Context) {
	c.Header("Content-Type", "text/csv; charset=utf-8")
	c.Header("Content-Disposition", `attachment; filename="benchmarks.csv"`)
	c.Header("Cache-Control", "no-store")
	w := csv.NewWriter(c.Writer)
	if err := w.Write([]string{"created_at", "algorithm", "operation", "file_kind", "bytes", "crypto_ns", "total_ns"}); err != nil {
		slog.Error("benchmark: write CSV header", "error", err)
		c.Abort()
		return
	}
	rows := 0
	err := h.store.Iterate(c.Request.Context(), func(r Record) error {
		if err := w.Write([]string{
			r.CreatedAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
			string(r.Algorithm), string(r.Operation), r.FileKind,
			fmt.Sprint(r.Bytes), fmt.Sprint(r.CryptoDuration.Nanoseconds()),
			fmt.Sprint(r.TotalDuration.Nanoseconds()),
		}); err != nil {
			return err
		}
		rows++
		if rows%256 == 0 {
			w.Flush()
			return w.Error()
		}
		return nil
	})
	if err != nil {
		slog.Error("benchmark: export CSV", "error", err)
		if rows == 0 {
			c.Writer.Header().Del("Content-Type")
			c.Writer.Header().Del("Content-Disposition")
			c.String(http.StatusInternalServerError, "Measurements could not be exported. Please try again.")
			return
		}
		w.Flush()
		c.Abort()
		return
	}
	w.Flush()
	if err := w.Error(); err != nil {
		slog.Error("benchmark: export CSV", "error", err)
		c.Abort()
	}
}

type aggregate struct {
	summary Summary
	crypto  float64
	total   float64
}

func summarize(records []Record) []Summary {
	groups := make(map[string]*aggregate)
	for _, r := range records {
		key := string(r.Algorithm) + ":" + string(r.Operation)
		g := groups[key]
		if g == nil {
			g = &aggregate{summary: Summary{Algorithm: r.Algorithm, Operation: r.Operation}}
			groups[key] = g
		}
		g.summary.Count++
		g.crypto += float64(r.CryptoDuration) / 1e6
		g.total += float64(r.TotalDuration) / 1e6
	}
	out := make([]Summary, 0, len(groups))
	for _, g := range groups {
		g.summary.CryptoMillis = g.crypto / float64(g.summary.Count)
		g.summary.TotalMillis = g.total / float64(g.summary.Count)
		out = append(out, g.summary)
	}
	order := map[crypto.Algorithm]int{crypto.AES: 0, crypto.DES: 1, crypto.RC4: 2}
	slices.SortFunc(out, func(a, b Summary) int {
		if order[a.Algorithm] != order[b.Algorithm] {
			return order[a.Algorithm] - order[b.Algorithm]
		}
		return cmp.Compare(string(a.Operation), string(b.Operation))
	})
	return out
}
