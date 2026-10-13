package web

import (
	"fmt"
	"html/template"
	"io/fs"
	"net/http"

	"github.com/gin-gonic/gin"
)

// templateFuncs are the helpers available in every template. Keep them
// pure formatting: no I/O and no access to request data.
var templateFuncs = template.FuncMap{
	"humanBytes": humanBytes,
}

// humanBytes formats a byte count with binary units, for example
// 1536 -> "1.5 KiB". Negative counts are treated as 0.
func humanBytes(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", max(n, 0))
	}
	v, exp := float64(n)/1024, 0
	// Move up a unit once the value would round to 1024, so 1 MiB - 1 B
	// prints "1.0 MiB" rather than "1024.0 KiB".
	for v >= 1023.95 && exp < 5 {
		v /= 1024
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", v, "KMGTPE"[exp])
}

// loadTemplates parses every embedded template. Each page template is
// defined under its file name (for example "login.html") and wraps itself
// in the "header" and "footer" templates from layout.html.
func loadTemplates() (*template.Template, error) {
	tmpl, err := template.New("").Funcs(templateFuncs).ParseFS(assets, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("web: parse templates: %w", err)
	}
	return tmpl, nil
}

// mountRendering installs the templates and the /static file server.
// Templates come from the embedded FS via SetHTMLTemplate; LoadHTMLGlob
// would read from the working directory at runtime instead.
func mountRendering(r *gin.Engine) error {
	tmpl, err := loadTemplates()
	if err != nil {
		return err
	}
	r.SetHTMLTemplate(tmpl)

	static, err := fs.Sub(assets, "static")
	if err != nil {
		return fmt.Errorf("web: static assets: %w", err)
	}
	r.StaticFS("/static", http.FS(static))
	return nil
}
