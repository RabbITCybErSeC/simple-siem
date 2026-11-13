package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var build embed.FS

// Files returns the embedded frontend build, rooted at the dist directory.
func Files() fs.FS {
	dist, err := fs.Sub(build, "dist")
	if err != nil {
		// The embedded tree always contains dist, so this is a build mistake.
		panic(err)
	}
	return dist
}
