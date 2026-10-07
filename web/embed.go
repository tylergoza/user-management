// Package web holds the HTML templates and static assets. They are embedded
// into the binary so a deployment is a single file plus the SQLite database.
package web

import "embed"

//go:embed templates static
var FS embed.FS
