package benchmark

import "github.com/gin-gonic/gin"

// RegisterRoutes mounts the benchmark routes. All of them require login.
func (h *Handler) RegisterRoutes(_, protected *gin.RouterGroup) {
	protected.GET("/benchmarks", h.index)
	protected.GET("/benchmarks/export.csv", h.exportCSV)
}
