package benchmark

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Handler serves the benchmark views.
type Handler struct {
	store *Store
}

// NewHandler returns a Handler reading from store.
func NewHandler(store *Store) *Handler {
	return &Handler{store: store}
}

// TODO(feature/benchmark): list records and render benchmarks.html with
// per-algorithm averages (TODO(feature/frontend) for the template).
func (h *Handler) index(c *gin.Context) {
	c.String(http.StatusNotImplemented, "not implemented")
}

// TODO(feature/benchmark): stream all records as CSV with encoding/csv
// (header: created_at,algorithm,operation,file_kind,bytes,crypto_ns,total_ns)
// and Content-Disposition: attachment.
func (h *Handler) exportCSV(c *gin.Context) {
	c.String(http.StatusNotImplemented, "not implemented")
}
