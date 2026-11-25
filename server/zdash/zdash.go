// Package zdash is Z-Dash itself, embedded: the copy in dist/ (written by
// Z-Dash's npm run build, never by hand) and the shell in shell/, the
// pages and modules every app on the server shares (sign-in, first
// password, account, tunnel settings).
//
// The server serves Dist under /z-dash/ (/z-dash/ds.min.css, ...) and Shell
// under /z-dash/server/ (/z-dash/server/shell.js, ...). Only what a page
// loads is embedded; the tools, the full stylesheet and the checksums stay
// in the module for tools/check-project.mjs (see Dir).
package zdash

import (
	"embed"
	"io/fs"
)

//go:embed dist/ds.min.css dist/ds.min.css.map dist/ds.min.js dist/fonts dist/themes dist/LICENSE dist/VERSION
var dist embed.FS

//go:embed shell
var shell embed.FS

// Dist is the embedded Z-Dash, rooted at its files (ds.min.css, fonts/...).
var Dist = mustSub(dist, "dist")

// Shell is the shell, rooted at its files (shell.js, index.html, ...).
var Shell = mustSub(shell, "shell")

func mustSub(f fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(f, dir)
	if err != nil {
		panic(err)
	}
	return sub
}
