package server

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
)

// assets serves embedded files from memory with strong ETags. Pages are
// always revalidated; scripts, styles and fonts may be kept for a few
// minutes and are revalidated after that, so an update shows within minutes
// without a build step that renames files.
type assets struct {
	prefix string // "/z-dash" for Z-Dash and the shell, "" for the app
	files  map[string]asset
}

type asset struct {
	data  []byte
	etag  string
	ctype string
}

func loadAssets(fsys fs.FS, prefix string) (*assets, error) {
	a := &assets{prefix: prefix, files: map[string]asset{}}
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		switch path.Ext(p) {
		case ".go", ".md":
			return nil
		}
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		a.files[prefix+"/"+p] = asset{data: b, etag: `"` + hex.EncodeToString(sum[:12]) + `"`, ctype: contentType(p)}
		return nil
	})
	return a, err
}

func contentType(p string) string {
	switch path.Ext(p) {
	case ".js", ".mjs":
		return "text/javascript; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".html":
		return "text/html; charset=utf-8"
	case ".json", ".map":
		return "application/json; charset=utf-8"
	case ".woff2":
		return "font/woff2"
	case ".svg":
		return "image/svg+xml"
	case ".webmanifest":
		return "application/manifest+json"
	}
	if ct := mime.TypeByExtension(path.Ext(p)); ct != "" {
		return ct
	}
	return "application/octet-stream"
}

func (a *assets) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	p := r.URL.Path
	if strings.HasSuffix(p, "/") {
		p += "index.html"
	}
	f, ok := a.files[p]
	if !ok {
		http.NotFound(w, r)
		return
	}
	h := w.Header()
	h.Set("Content-Type", f.ctype)
	h.Set("ETag", f.etag)
	if strings.HasSuffix(p, ".html") {
		h.Set("Cache-Control", "no-cache")
	} else {
		h.Set("Cache-Control", "public, max-age=300")
	}
	if match := r.Header.Get("If-None-Match"); match != "" && strings.Contains(match, f.etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(f.data)
}

// redirectToShell is / of an app without pages of its own: the shell's
// start page.
func (a *assets) redirectToShell() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "/z-dash/server/", http.StatusFound)
	})
}
