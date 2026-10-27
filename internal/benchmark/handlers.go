package benchmark

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/eggboixd/infosec-assignment1-group3/internal/auth"
)

// recentLimit is how many raw records the page shows under the summary.
const recentLimit = 100

// User-facing messages.
const (
	msgBadSince   = "The since value must be a time like 2026-10-27T09:00:00Z (RFC 3339)."
	msgLoadFailed = "The benchmark records could not be loaded. Please try again."
)

// recordSource is what the handler reads records from. *Store satisfies it.
type recordSource interface {
	List(ctx context.Context, since time.Time, limit int64) ([]Record, error)
	Each(ctx context.Context, since time.Time, fn func(Record) error) error
}

// Handler serves the benchmark views. Records are not per user: the page
// is a measurement tool for the report and shows every record (D34).
type Handler struct {
	src recordSource
}

// NewHandler returns a Handler reading from src.
func NewHandler(src recordSource) *Handler {
	return &Handler{src: src}
}

// index handles GET /benchmarks?since=: a summary per operation, file kind,
// size class and algorithm, followed by the latest raw records.
func (h *Handler) index(c *gin.Context) {
	user, _ := auth.CurrentUser(c)
	since, ok := parseSince(c)
	if !ok {
		renderError(c, http.StatusBadRequest, msgBadSince)
		return
	}
	ctx := c.Request.Context()
	var sum Summarizer
	err := h.src.Each(ctx, since, func(r Record) error {
		sum.Add(r)
		return nil
	})
	var recent []Record
	if err == nil {
		recent, err = h.src.List(ctx, since, recentLimit)
	}
	if err != nil {
		slog.Error("benchmark: load", "error", err)
		renderError(c, http.StatusInternalServerError, msgLoadFailed)
		return
	}
	stats := sum.Stats()
	c.HTML(http.StatusOK, "benchmarks.html", gin.H{
		"Title":        "Benchmarks",
		"User":         user,
		"JustLoggedIn": auth.JustLoggedIn(c),
		"Flash":        auth.TakeFlash(c),
		"Summary":      stats,
		"Total":        total(stats),
		"Records":      recent,
		"Since":        c.Query("since"),
	})
}

// exportCSV handles GET /benchmarks/export.csv?since=: every matching record,
// oldest first, streamed as CSV.
func (h *Handler) exportCSV(c *gin.Context) {
	since, ok := parseSince(c)
	if !ok {
		renderError(c, http.StatusBadRequest, msgBadSince)
		return
	}
	hdr := c.Writer.Header()
	hdr.Set("Content-Type", "text/csv; charset=utf-8")
	hdr.Set("Content-Disposition", `attachment; filename="benchmarks.csv"`)
	hdr.Set("Cache-Control", "no-store")

	// Rows are buffered by encoding/csv, so an error on the first query
	// usually happens before any byte is sent and can still be a 500.
	cw, err := NewCSVWriter(c.Writer)
	if err == nil {
		err = h.src.Each(c.Request.Context(), since, cw.Write)
	}
	if err == nil {
		err = cw.Flush()
	}
	switch {
	case err == nil:
	case c.Writer.Written():
		// Part of the file is already out; all we can do is cut it short.
		slog.Error("benchmark: export aborted mid-stream", "error", err)
		c.Abort()
	case errors.Is(err, context.Canceled):
		c.Abort()
	default:
		slog.Error("benchmark: export", "error", err)
		hdr.Del("Content-Disposition")
		renderError(c, http.StatusInternalServerError, msgLoadFailed)
	}
}

// parseSince reads ?since= as an RFC 3339 time. Empty means no bound.
func parseSince(c *gin.Context) (time.Time, bool) {
	s := strings.TrimSpace(c.Query("since"))
	if s == "" {
		return time.Time{}, true
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// total counts the records and bytes behind a summary.
func total(stats []Stat) Stat {
	var t Stat
	for _, s := range stats {
		t.Count += s.Count
		t.Bytes += s.Bytes
	}
	return t
}

func renderError(c *gin.Context, status int, msg string) {
	user, _ := auth.CurrentUser(c)
	c.Writer.Header().Del("Content-Type")
	c.HTML(status, "error.html", gin.H{
		"Title":   "Error",
		"User":    user,
		"Status":  status,
		"Message": msg,
	})
}
