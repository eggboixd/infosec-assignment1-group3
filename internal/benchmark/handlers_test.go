package benchmark

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/eggboixd/infosec-assignment1-group3/internal/auth"
	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
	"github.com/eggboixd/infosec-assignment1-group3/internal/web"
)

// memSource is an in-memory recordSource with the same since filtering
// and ordering as Store. failAfter > 0 makes Each fail after that many
// records; failList makes List fail.
type memSource struct {
	recs      []Record // oldest first
	failAfter int
	failList  bool
}

var errBoom = errors.New("memSource: boom")

func (m *memSource) Each(_ context.Context, since time.Time, fn func(Record) error) error {
	n := 0
	for _, r := range m.recs {
		if r.CreatedAt.Before(since) {
			continue
		}
		if m.failAfter > 0 && n == m.failAfter {
			return errBoom
		}
		if err := fn(r); err != nil {
			return err
		}
		n++
	}
	if m.failAfter < 0 {
		return errBoom
	}
	return nil
}

func (m *memSource) List(_ context.Context, since time.Time, limit int64) ([]Record, error) {
	if m.failList {
		return nil, errBoom
	}
	var out []Record
	for i := len(m.recs) - 1; i >= 0 && int64(len(out)) < limit; i-- {
		if !m.recs[i].CreatedAt.Before(since) {
			out = append(out, m.recs[i])
		}
	}
	return out, nil
}

var t0 = time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC)

// records returns n records one second apart starting at t0, cycling
// through the algorithms.
func records(n int) []Record {
	out := make([]Record, n)
	for i := range out {
		out[i] = Record{
			Algorithm: crypto.All()[i%3], Operation: OpDownload, FileKind: "video",
			Bytes: 1 << 20, CryptoDuration: time.Millisecond, TotalDuration: 2 * time.Millisecond,
			CreatedAt: t0.Add(time.Duration(i) * time.Second),
		}
	}
	return out
}

func newEngine(t *testing.T, src recordSource) *gin.Engine {
	t.Helper()
	user := &auth.User{ID: bson.NewObjectID(), Username: "budi"}
	engine, err := web.NewEngine(web.Options{
		Mode:         gin.TestMode,
		MaxBodyBytes: 1 << 20,
		Features:     []web.RouteRegistrar{NewHandler(src)},
		RequireAuth:  func(c *gin.Context) { auth.SetCurrentUser(c, user) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func get(engine *gin.Engine, target string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, httptest.NewRequest(http.MethodGet, target, nil))
	return w
}

func TestIndexShowsSummaryAndRecords(t *testing.T) {
	src := &memSource{recs: append(records(6), Record{
		Algorithm: crypto.DES, Operation: OpEncrypt, Bytes: 120,
		CryptoDuration: time.Millisecond, TotalDuration: time.Millisecond, CreatedAt: t0.Add(time.Hour),
	})}
	w := get(newEngine(t, src), "/benchmarks")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		"7 records", "AES-256", "DES", "RC4", "private data", "64 KiB–1 MiB",
		// 2 MiB per algorithm over 2 ms of crypto time.
		"1000.0", `href="/benchmarks/export.csv"`, `data-label="Crypto MiB/s"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	// Summary rows (4 groups) + latest records (7 rows) + 2 header rows.
	if got := strings.Count(body, "<tr>"); got != 4+7+2 {
		t.Errorf("%d table rows, want 13", got)
	}
}

func TestIndexSince(t *testing.T) {
	src := &memSource{recs: records(6)}
	w := get(newEngine(t, src), "/benchmarks?since=2026-10-27T09:00:03Z")
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, "3 records") {
		t.Errorf("got %d, page lacks '3 records'", w.Code)
	}
	if !strings.Contains(body, `href="/benchmarks/export.csv?since=2026-10-27T09%3A00%3A03Z"`) {
		t.Error("the export link does not keep the filter")
	}
	if !strings.Contains(body, `value="2026-10-27T09:00:03Z"`) {
		t.Error("the filter field does not show the current value")
	}
}

func TestIndexEmpty(t *testing.T) {
	w := get(newEngine(t, &memSource{}), "/benchmarks")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "No measurements yet.") {
		t.Errorf("got %d without the empty state", w.Code)
	}
}

func TestBadSince(t *testing.T) {
	for _, path := range []string{"/benchmarks", "/benchmarks/export.csv"} {
		for _, since := range []string{"yesterday", "2026-10-27", "2026-10-27T09:00:00"} {
			w := get(newEngine(t, &memSource{recs: records(3)}), path+"?since="+since)
			if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "RFC 3339") {
				t.Errorf("%s?since=%s: got %d, want 400 with the format hint", path, since, w.Code)
			}
			if w.Header().Get("Content-Disposition") != "" {
				t.Errorf("%s?since=%s: an error page is sent as a download", path, since)
			}
		}
	}
}

func TestIndexLoadErrors(t *testing.T) {
	for name, src := range map[string]*memSource{
		"each": {recs: records(3), failAfter: -1},
		"list": {recs: records(3), failList: true},
	} {
		w := get(newEngine(t, src), "/benchmarks")
		if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "boom") {
			t.Errorf("%s: got %d, want 500 without internal details", name, w.Code)
		}
	}
}

func TestExportCSV(t *testing.T) {
	src := &memSource{recs: records(5)}
	w := get(newEngine(t, src), "/benchmarks/export.csv?since=2026-10-27T09:00:02Z")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	for k, want := range map[string]string{
		"Content-Type":        "text/csv; charset=utf-8",
		"Content-Disposition": `attachment; filename="benchmarks.csv"`,
		"Cache-Control":       "no-store",
	} {
		if got := w.Header().Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	got, err := ReadCSV(w.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || !got[0].CreatedAt.Equal(t0.Add(2*time.Second)) || !got[2].CreatedAt.Equal(t0.Add(4*time.Second)) {
		t.Errorf("exported %d records, want the 3 since 09:00:02, oldest first", len(got))
	}
}

func TestExportCSVEmptyHasHeader(t *testing.T) {
	w := get(newEngine(t, &memSource{}), "/benchmarks/export.csv")
	if w.Code != http.StatusOK || w.Body.String() != "created_at,algorithm,operation,file_kind,bytes,crypto_ns,total_ns\n" {
		t.Errorf("got %d %q", w.Code, w.Body.String())
	}
}

func TestExportCSVErrorBeforeFirstByte(t *testing.T) {
	w := get(newEngine(t, &memSource{recs: records(3), failAfter: 1}), "/benchmarks/export.csv")
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status %d, want 500", w.Code)
	}
	if w.Header().Get("Content-Disposition") != "" || strings.HasPrefix(w.Header().Get("Content-Type"), "text/csv") {
		t.Error("the error page is labelled as a CSV download")
	}
	if strings.Contains(w.Body.String(), "created_at,") {
		t.Error("a partial CSV was sent with the error page")
	}
}

func TestExportCSVErrorMidStream(t *testing.T) {
	// Enough rows to overflow the CSV writer's buffer, so bytes are sent
	// before the failure.
	w := get(newEngine(t, &memSource{recs: records(500), failAfter: 400}), "/benchmarks/export.csv")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want the 200 already sent", w.Code)
	}
	if strings.Contains(w.Body.String(), "<html") {
		t.Error("an error page was appended to the CSV")
	}
	if _, err := ReadCSV(w.Body); err == nil {
		// The cut can land on a row boundary; it must at least be short.
		if n := strings.Count(w.Body.String(), "\n"); n >= 401 {
			t.Errorf("%d lines, want the export cut short", n)
		}
	}
}

func TestRoutesRequireLogin(t *testing.T) {
	engine, err := web.NewEngine(web.Options{
		Mode:         gin.TestMode,
		MaxBodyBytes: 1 << 20,
		Features:     []web.RouteRegistrar{NewHandler(&memSource{recs: records(3)})},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/benchmarks", "/benchmarks/export.csv"} {
		w := get(engine, path)
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
			t.Errorf("%s: got %d to %q, want 303 to /login", path, w.Code, w.Header().Get("Location"))
		}
	}
}
