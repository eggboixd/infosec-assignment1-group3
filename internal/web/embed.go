// Package web builds the Gin engine: global middleware, templates, static
// assets, the health check, and the feature route groups.
package web

import "embed"

// assets holds the HTML templates and static files compiled into the binary.
//
//go:embed templates static
var assets embed.FS
