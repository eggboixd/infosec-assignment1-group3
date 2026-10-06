package web

import (
	"fmt"
	"html/template"
	"io/fs"
	"net/http"

	"github.com/gin-gonic/gin"
)

// loadTemplates parses every embedded template. Each page template is
// defined under its file name (for example "login.html") and wraps itself
// in the "header" and "footer" templates from layout.html.
func loadTemplates() (*template.Template, error) {
	tmpl, err := template.ParseFS(assets, "templates/*.html")
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
