package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"

	"github.com/saschazesiger/Z-Dash/server/cloudflare"
)

// CSRFHeader must be on every request that changes something. A form on
// another site cannot set a header, and a script on another site cannot send
// one without a CORS approval the server never gives. The shell's fetch
// helper (api.js) sends it.
const CSRFHeader = "X-Z-Dash"

// Identity says who sent a request.
type Identity struct {
	// Via is "local" (the local listener, signed in with the password) or
	// "tunnel" (through Cloudflare, signed in by Cloudflare Access).
	Via string `json:"via"`
	// Email is the address Cloudflare Access vouches for; empty on the local
	// listener and on bypass paths.
	Email string `json:"email"`
}

type identityKey struct{}

// Who is the identity of a request.
func Who(r *http.Request) Identity {
	if id, ok := r.Context().Value(identityKey{}).(Identity); ok {
		return id
	}
	return Identity{Via: "local"}
}

func withIdentity(r *http.Request, id Identity) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), identityKey{}, id))
}

// Handler is the local listener's handler, for tests of the app.
func (a *App) Handler() http.Handler {
	local, _ := a.handlers()
	return local
}

// TunnelHandler is the tunnel listener's handler, for tests of the app.
func (a *App) TunnelHandler() http.Handler {
	_, tunnel := a.handlers()
	return tunnel
}

// handlers builds both listeners' handlers once.
func (a *App) handlers() (local, tunnel http.Handler) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.built {
		a.built = true
		a.local = a.mux()
		a.tunnel = a.mux()
	}
	return a.recover(a.localHost(a.headers(a.local))), a.recover(a.tunnelGate(a.headers(a.tunnel)))
}

// mux is one listener's routes: the server's own, the bypass paths, the
// app's.
func (a *App) mux() *http.ServeMux {
	mux := a.baseMux()
	for _, rt := range a.routes {
		mux.Handle(rt.pattern, rt.handler)
	}
	return mux
}

// baseMux is the server's own routes, the bypass paths and the app's files
// at / (ServeMux picks the most specific pattern, whatever the order).
func (a *App) baseMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("GET /api/session", a.session)
	mux.HandleFunc("POST /api/login", a.guard(a.login))
	mux.HandleFunc("POST /api/setup/password", a.guard(a.firstPassword))
	mux.HandleFunc("POST /api/logout", a.guard(a.logout))
	mux.Handle("POST /api/password", a.private(http.HandlerFunc(a.changePassword)))
	mux.Handle("GET /api/events", a.private(http.HandlerFunc(a.events)))

	mux.Handle("GET /api/cloudflare", a.private(http.HandlerFunc(a.cloudflareStatus)))
	mux.Handle("POST /api/cloudflare/check", a.private(http.HandlerFunc(a.cloudflareCheck)))
	mux.Handle("POST /api/cloudflare/setup", a.private(http.HandlerFunc(a.cloudflareSetup)))
	mux.Handle("PUT /api/cloudflare/emails", a.private(http.HandlerFunc(a.cloudflareEmails)))
	mux.Handle("DELETE /api/cloudflare", a.private(http.HandlerFunc(a.cloudflareRemove)))

	mux.Handle("/z-dash/", a.zdash)
	for path, h := range a.cfg.Bypass {
		p := strings.TrimSuffix(path, "/")
		mux.Handle(p, h)
		mux.Handle(p+"/", h)
	}
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		WriteError(w, http.StatusNotFound, "This API address does not exist.")
	})
	if a.cfg.Pages != nil {
		mux.Handle("/", a.cfg.Pages)
	} else if a.assets != nil {
		mux.Handle("/", a.assets)
	} else {
		mux.Handle("/", a.zdash.redirectToShell())
	}
	return mux
}

// --- middleware ---------------------------------------------------------------

// recover answers a panic with a 500 instead of a dropped connection, and
// logs it with its stack.
func (a *App) recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				a.logf("panic in %s %s: %v\n%s", r.Method, r.URL.Path, v, debug.Stack())
				WriteError(w, http.StatusInternalServerError, "Something went wrong on the server.")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// csp is the Content-Security-Policy of every answer: nothing from other
// origins, no inline script or style, no frames of this app elsewhere.
func (a *App) csp() string {
	directives := map[string]string{
		"default-src":     "'self'",
		"script-src":      "'self'",
		"style-src":       "'self'",
		"img-src":         "'self' data:",
		"font-src":        "'self'",
		"connect-src":     "'self'",
		"form-action":     "'self'",
		"frame-ancestors": "'none'",
		"base-uri":        "'none'",
		"object-src":      "'none'",
	}
	for k, v := range a.cfg.CSP {
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		if k == "" || v == "" || strings.ContainsAny(k+v, ";\r\n") {
			continue
		}
		if have := directives[k]; have != "" && have != "'none'" {
			directives[k] = have + " " + v
		} else {
			directives[k] = v
		}
	}
	keys := make([]string, 0, len(directives))
	for k := range directives {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + " " + directives[k]
	}
	return strings.Join(parts, "; ")
}

func (a *App) setSecurityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", a.csp())
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "same-origin")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	if strings.Contains(a.cspDirective("frame-ancestors"), "'self'") {
		// Framed by its own pages: X-Frame-Options follows frame-ancestors.
		h.Set("X-Frame-Options", "SAMEORIGIN")
	}
	if a.cfg.Headers != nil {
		a.cfg.Headers(h)
	}
}

// cspDirective is the value of one directive of the policy.
func (a *App) cspDirective(name string) string {
	for _, part := range strings.Split(a.csp(), "; ") {
		if k, v, ok := strings.Cut(part, " "); ok && k == name {
			return v
		}
	}
	return ""
}

func (a *App) headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.setSecurityHeaders(w)
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// localHost refuses requests whose Host header is a public-looking name.
// That is what a DNS rebinding attack looks like: a website the admin has
// open points its own name at this address to talk to the app as if it were
// the same site. Addresses, single-label and private names are fine; other
// names are listed in Config.Hosts.
func (a *App) localHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !localName(r.Host, a.cfg.Hosts) && !a.isUnguarded(r) {
			a.setSecurityHeaders(w)
			http.Error(w, a.cfg.Name+" does not know the name "+strconv.Quote(r.Host)+". Open it by its IP address, "+
				"or add the name to the environment variable "+a.cfg.Env+"_HOSTS.", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isUnguarded reports whether a request goes to a route of Unguarded.
func (a *App) isUnguarded(r *http.Request) bool {
	if a.unguarded == nil {
		return false
	}
	_, pattern := a.unguarded.Handler(r)
	return pattern != ""
}

func localName(hostport string, extra []string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSuffix(strings.Trim(host, "[]"), "."))
	if host == "" {
		return false
	}
	if net.ParseIP(host) != nil || !strings.Contains(host, ".") {
		return true
	}
	for _, suffix := range []string{".localhost", ".local", ".lan", ".internal", ".home.arpa", ".home", ".intranet", ".ts.net"} {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	for _, e := range extra {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "*" || e == host {
			return true
		}
	}
	return false
}

// tunnelGate is the front of the tunnel's listener. Only cloudflared reaches
// it, so the caller's address is the one Cloudflare names. Bypass paths go
// through as they are; every other request needs a valid Cloudflare Access
// token, which signs the person in.
func (a *App) tunnelGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(cloudflare.MarkerHeader, "1")
		r.RemoteAddr = "0.0.0.0:0"
		if ip := net.ParseIP(strings.TrimSpace(r.Header.Get("Cf-Connecting-Ip"))); ip != nil {
			r.RemoteAddr = net.JoinHostPort(ip.String(), "0")
		}
		if a.cf.Bypassed(r.URL.Path) {
			next.ServeHTTP(w, withIdentity(r, Identity{Via: "tunnel"}))
			return
		}
		email, err := a.cf.Authenticate(r)
		if err != nil || email == "" {
			a.logf("tunnel: refused %s %s: %v", r.Method, r.URL.Path, err)
			a.setSecurityHeaders(w)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, "Forbidden: sign in through Cloudflare Access with an e-mail address that may use "+a.cfg.Name+".\n"+
				"Signed in with another address? Sign out at "+accessLogout+" and try again.\n")
			return
		}
		next.ServeHTTP(w, withIdentity(r, Identity{Via: "tunnel", Email: email}))
	})
}

// accessLogout ends the browser's Cloudflare Access session.
const accessLogout = "/cdn-cgi/access/logout"

// guard refuses requests that change something and may come from another
// site: they must carry CSRFHeader, and an Origin, when the browser sends
// one, must be this host.
func (a *App) guard(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			if r.Header.Get(CSRFHeader) != "1" {
				WriteError(w, http.StatusForbidden, "This request was refused: it did not come from the "+a.cfg.Name+
					" interface. Reload the page and try again.")
				return
			}
			if o := r.Header.Get("Origin"); o != "" {
				u, err := url.Parse(o)
				if err != nil || !strings.EqualFold(u.Host, r.Host) {
					WriteError(w, http.StatusForbidden, "This request was refused: it came from another website.")
					return
				}
			}
		}
		h(w, r)
	}
}

// private is guard plus a signed-in person.
func (a *App) private(h http.Handler) http.Handler {
	return a.guard(func(w http.ResponseWriter, r *http.Request) {
		if !a.SignedIn(r) {
			WriteError(w, http.StatusUnauthorized, "You are not signed in. Reload the page and sign in.")
			return
		}
		h.ServeHTTP(w, r)
	})
}

// SignedIn reports whether a request comes from a signed-in person: through
// the tunnel with an Access identity, or locally with a session.
func (a *App) SignedIn(r *http.Request) bool {
	if a.cfg.Open {
		return true
	}
	if id := Who(r); id.Via == "tunnel" {
		return id.Email != ""
	}
	return a.auth.check(r)
}

// --- JSON helpers -----------------------------------------------------------

// APIError is the body of every failed request: one sentence for the
// person, and field errors where a form was checked.
type APIError struct {
	Error  string            `json:"error"`
	Fields map[string]string `json:"fields,omitempty"`
}

// WriteJSON answers v as JSON.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

// WriteError answers an error the person can read; the shell shows it.
func WriteError(w http.ResponseWriter, status int, msg string) {
	WriteJSON(w, status, APIError{Error: msg})
}

// WriteFieldError answers an error that belongs to one field of a form.
func WriteFieldError(w http.ResponseWriter, field, msg string) {
	WriteJSON(w, http.StatusBadRequest, APIError{Error: msg, Fields: map[string]string{field: msg}})
}

// Decode reads a JSON body of at most 1 MiB into v; on failure it has
// answered already and returns false.
func Decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil && !errors.Is(err, io.EOF) {
		WriteError(w, http.StatusBadRequest, "The request could not be read: "+err.Error())
		return false
	}
	return true
}

// Origin is the address the browser uses for the app: the tunnel's public
// https address, or the local one.
func Origin(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || Who(r).Via == "tunnel" {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// clientIP is the address a request came from, for rate limits.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func roundWait(seconds float64) string {
	if seconds < 60 {
		return fmt.Sprintf("%d seconds", int(seconds+0.99))
	}
	m := int(seconds/60 + 0.99)
	if m == 1 {
		return "a minute"
	}
	return fmt.Sprintf("%d minutes", m)
}
