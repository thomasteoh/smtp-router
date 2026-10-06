// Package web hosts the smtp-router admin web UI assets. The portal package
// imports this package so the single-page admin console can be embedded into
// the binary and served by the router alongside the OIDC login flow.
package web

import (
	"embed"
	"io/fs"
)

//go:embed index.html
var assets embed.FS

// FS returns the embedded admin UI file system.
func FS() fs.FS {
	return assets
}

// IndexHTML returns the rendered admin console page. It is a template
// ({{define "index"}}) executed by the portal with the signed-in admin's data.
func IndexHTML() []byte {
	b, _ := assets.ReadFile("index.html")
	return b
}
