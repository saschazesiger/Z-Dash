// Package server is the foundation of an admin app on Z-Dash: a Go HTTP
// server that brings everything but the app's own pages and API.
//
//   - Two listeners. The local one (the network the app runs in) signs in
//     with an admin password; the first visitor sets it. The tunnel's one is
//     reached only by cloudflared: whoever Cloudflare Access let in is signed
//     in by the e-mail address Access vouches for.
//   - The Cloudflare tunnel, set up from the interface with an API token:
//     tunnel, DNS record, Access applications, cloudflared supervised and
//     checked from outside (package cloudflare).
//   - The guards every page needs: a Host check against DNS rebinding on the
//     local listener, a CSRF guard on every request that changes something,
//     a strict Content-Security-Policy, panics answered with 500.
//   - Z-Dash itself under /z-dash/ (embedded, package zdash), the shell
//     (login, first password, account, tunnel settings) under
//     /z-dash/server/, and the app's own files at /.
//   - A SQLite database with numbered migrations (package store), sealed
//     secrets (package secret), live change notices over server-sent
//     events, a health check, a graceful shutdown.
//
// An app is a Config, its routes and its pages:
//
//	app, err := server.New(server.Config{Name: "Inventory", Assets: web.FS})
//	app.HandleFunc("GET /api/devices", listDevices)
//	err = app.Run(ctx)
package server

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/saschazesiger/Z-Dash/server/cloudflare"
	"github.com/saschazesiger/Z-Dash/server/secret"
	"github.com/saschazesiger/Z-Dash/server/store"
	"github.com/saschazesiger/Z-Dash/server/zdash"
)

// Config describes an app. Only Name is required; every other field has a
// default, and most can also come from the environment (see Env).
type Config struct {
	// Name is the app's name as people read it ("Inventory"). It names the
	// Cloudflare objects and appears in messages.
	Name string
	// Slug is the app's name in files, cookies and the tunnel's name
	// ("inventory"); it is made from Name when empty.
	Slug string
	// Env is the prefix of the environment variables the defaults are read
	// from ("INVENTORY" reads INVENTORY_DATA ...); it is made from Slug when
	// empty. The variables are listed at FromEnv.
	Env string
	// Version is shown by /api/session and the health check.
	Version string

	// DataDir holds the database, the secret key, the tunnel's socket and a
	// cloudflared the app downloaded ($ENV_DATA, default ./data).
	DataDir string
	// Listen is the local listener ($ENV_LISTEN, default ":8080").
	Listen string
	// TunnelListen is what cloudflared reaches ($ENV_TUNNEL_LISTEN): a
	// loopback address ("127.0.0.1:8081"), or empty for a Unix socket in
	// DataDir (on Windows, 127.0.0.1:8081). Nothing else should reach it.
	TunnelListen string
	// Hosts are names the local listener answers to besides addresses,
	// single-label and private names ($ENV_HOSTS, comma-separated; "*"
	// allows every name).
	Hosts []string
	// AdminPassword, when set, becomes the admin password at start and signs
	// everybody out ($ENV_ADMIN_PASSWORD): the way back in when it is lost.
	AdminPassword string
	// SecretKey is the key of the sealed secrets, 32 bytes in base64
	// ($ENV_SECRET_KEY); empty keeps it in DataDir/secret.key.
	SecretKey string
	// Cloudflared is the cloudflared to run ($ENV_CLOUDFLARED); empty takes
	// the one on the PATH, or downloads one into DataDir.
	Cloudflared string
	// Open signs every visitor in without a password: for demos and tests
	// only ($ENV_OPEN=1).
	Open bool

	// Bypass are handlers Cloudflare Access lets through without a login,
	// by path ("/webhook" covers /webhook and everything below it). They are
	// served on both listeners, without the CSRF guard and without a login:
	// each must check its caller itself (a signature, a token of its own).
	Bypass map[string]http.Handler
	// BypassLabel says what the bypass paths are ("webhooks"), for the name
	// of their Access policy.
	BypassLabel string
	// AccessSession is how long a Cloudflare Access login lasts ("24h",
	// "720h"; default 24h).
	AccessSession string

	// Assets are the app's own files, served at / (index.html for /). Nil
	// serves only Z-Dash, the shell and the API.
	Assets fs.FS
	// CSP adds sources to the Content-Security-Policy, by directive:
	// {"form-action": "https://github.com"}.
	CSP map[string]string

	// Migrations create and change the app's own tables in the database.
	Migrations []store.Migration
	// KV and Sealer replace the database's key-value table and the secret
	// box, for an app that keeps its own database. Both or neither.
	KV     KV
	Sealer Sealer
	// Tunnel replaces the Cloudflare tunnel: cloudflare.NewDemo for a demo
	// or a test, where nothing may reach Cloudflare.
	Tunnel Tunnel

	// Logf receives diagnostics; nil writes them with the log package.
	Logf func(format string, args ...any)
}

// KV is where the server keeps its own state: the password, the sessions,
// the tunnel. Get answers store.ErrNotFound for a missing key.
type KV interface {
	Get(key string) ([]byte, error)
	Set(key string, value []byte) error
	SetIfMissing(key string, value []byte) (bool, error)
	Delete(key string) error
}

// Sealer encrypts secrets; object is the name a value is stored under.
type Sealer interface {
	Seal(object string, plain []byte) ([]byte, error)
	Open(object string, sealed []byte) ([]byte, error)
}

// Tunnel is what the server needs of the Cloudflare tunnel:
// *cloudflare.Service, or *cloudflare.Demo in a demo.
type Tunnel interface {
	Status() cloudflare.Status
	TokenURL() string
	BypassPaths() []string
	Bypassed(path string) bool
	Check(ctx context.Context, token string) (cloudflare.TokenInfo, error)
	StartSetup(req cloudflare.SetupRequest) error
	SetEmails(ctx context.Context, emails []string) error
	StartRemove() error
	// Authenticate checks the Cloudflare Access token of a request that
	// came through the tunnel and returns the address it vouches for.
	Authenticate(r *http.Request) (string, error)
	// Allows reports whether an address may still sign in.
	Allows(email string) bool
	PublicURL() string
	Origin() string
	Run(ctx context.Context)
}

var (
	_ Tunnel = (*cloudflare.Service)(nil)
	_ Tunnel = (*cloudflare.Demo)(nil)
)

// FromEnv fills the fields of c that are empty from the environment, with
// the prefix c.Env (made from the slug: "inventory" -> "INVENTORY"):
//
//	_DATA, _LISTEN, _TUNNEL_LISTEN, _HOSTS, _ADMIN_PASSWORD, _SECRET_KEY,
//	_CLOUDFLARED, _OPEN
//
// New calls it; an app calls it itself only to look at the result first.
func (c *Config) FromEnv() {
	c.defaults()
	get := func(name string) string { return strings.TrimSpace(os.Getenv(c.Env + "_" + name)) }
	set := func(field *string, name string) {
		if *field == "" {
			*field = get(name)
		}
	}
	set(&c.DataDir, "DATA")
	set(&c.Listen, "LISTEN")
	set(&c.TunnelListen, "TUNNEL_LISTEN")
	set(&c.AdminPassword, "ADMIN_PASSWORD")
	set(&c.SecretKey, "SECRET_KEY")
	set(&c.Cloudflared, "CLOUDFLARED")
	if len(c.Hosts) == 0 {
		for _, h := range strings.Split(get("HOSTS"), ",") {
			if h = strings.TrimSpace(h); h != "" {
				c.Hosts = append(c.Hosts, h)
			}
		}
	}
	if !c.Open {
		c.Open = get("OPEN") == "1"
	}
}

func (c *Config) defaults() {
	c.Name = strings.TrimSpace(c.Name)
	if c.Name == "" {
		c.Name = "App"
	}
	if c.Slug == "" {
		c.Slug = slugOf(c.Name)
	}
	if c.Env == "" {
		c.Env = strings.ToUpper(strings.ReplaceAll(c.Slug, "-", "_"))
	}
}

// App is a running app's server.
type App struct {
	cfg    Config
	logf   func(string, ...any)
	db     *store.Store // nil when the app brought its own KV
	kv     KV
	sealer Sealer
	cf     Tunnel
	auth   *auth
	hub    *hub

	mu     sync.Mutex
	routes []route
	local  *http.ServeMux
	tunnel *http.ServeMux
	probe  *http.ServeMux // the routes so far, to find a conflict as it is registered
	built  bool

	assets *assets // the app's files
	zdash  *assets // Z-Dash and the shell

	startedAt time.Time
}

type route struct {
	pattern string
	handler http.Handler
}

// New builds an app: it opens the database (and runs its migrations), the
// secret box and the tunnel's state. Nothing listens until Run.
func New(cfg Config) (*App, error) {
	cfg.FromEnv()
	if cfg.DataDir == "" {
		cfg.DataDir = "data"
	}
	if cfg.Listen == "" {
		cfg.Listen = ":8080"
	}
	if cfg.TunnelListen == "" && runtime.GOOS == "windows" {
		cfg.TunnelListen = "127.0.0.1:8081"
	}
	if cfg.Version == "" {
		cfg.Version = "dev"
	}
	if (cfg.KV == nil) != (cfg.Sealer == nil) {
		return nil, errors.New("server: set both KV and Sealer, or neither")
	}
	if abs, err := filepath.Abs(cfg.DataDir); err == nil {
		cfg.DataDir = abs
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("the data directory %s cannot be created: %w", cfg.DataDir, err)
	}
	for path := range cfg.Bypass {
		if err := checkBypass(path); err != nil {
			return nil, err
		}
	}
	a := &App{cfg: cfg, logf: cfg.Logf, hub: newHub(), startedAt: time.Now()}
	if a.logf == nil {
		a.logf = log.Printf
	}
	if cfg.KV != nil {
		a.kv, a.sealer = cfg.KV, cfg.Sealer
	} else {
		db, err := store.Open(filepath.Join(cfg.DataDir, cfg.Slug+".db"), cfg.Migrations...)
		if err != nil {
			return nil, err
		}
		box, err := secret.Load(cfg.DataDir, cfg.SecretKey)
		if err != nil {
			db.Close()
			return nil, err
		}
		a.db, a.kv, a.sealer = db, db, box
	}
	a.auth = newAuth(a.kv, cookieName(cfg.Slug), a.logf)
	if cfg.AdminPassword != "" {
		// A password that cannot be set must stop the start: otherwise the
		// first visitor would set one.
		if err := a.auth.setPassword(cfg.AdminPassword); err != nil {
			a.close()
			return nil, fmt.Errorf("%s_ADMIN_PASSWORD cannot be the admin password: %w", cfg.Env, err)
		}
		a.auth.dropSessions("")
		a.logf("The admin password was set from %s_ADMIN_PASSWORD; everybody was signed out", cfg.Env)
	}
	bypass := make([]string, 0, len(cfg.Bypass))
	for path := range cfg.Bypass {
		bypass = append(bypass, path)
	}
	a.cf = cfg.Tunnel
	if a.cf == nil {
		a.cf = a.newTunnel(bypass)
	}
	var err error
	if cfg.Assets != nil {
		if a.assets, err = loadAssets(cfg.Assets, ""); err != nil {
			return nil, fmt.Errorf("the app's files: %w", err)
		}
	}
	if a.zdash, err = loadAssets(zdash.Dist, "/z-dash"); err != nil {
		return nil, fmt.Errorf("the embedded Z-Dash: %w", err)
	}
	shell, err := loadAssets(zdash.Shell, "/z-dash/server")
	if err != nil {
		return nil, fmt.Errorf("the embedded shell: %w", err)
	}
	for p, f := range shell.files {
		a.zdash.files[p] = f
	}
	return a, nil
}

func (a *App) newTunnel(bypass []string) *cloudflare.Service {
	cfg := a.cfg
	return cloudflare.New(cloudflare.Options{
		KV:              cfKV{a.kv},
		Sealer:          a.sealer,
		Origin:          a.tunnelOrigin(),
		BinDir:          filepath.Join(cfg.DataDir, "bin"),
		Name:            cfg.Name,
		Slug:            cfg.Slug,
		Bypass:          sortedPaths(bypass),
		BypassLabel:     cfg.BypassLabel,
		SessionDuration: cfg.AccessSession,
		Command:         cfg.Cloudflared,
		EnvPrefix:       cfg.Env + "_",
		Logf:            a.logf,
	})
}

// Config is the configuration the app runs with, defaults filled in.
func (a *App) Config() Config { return a.cfg }

// Store is the database, nil when the app brought its own KV.
func (a *App) Store() *store.Store { return a.db }

// Secrets seal and open the app's own secrets.
func (a *App) Secrets() Sealer { return a.sealer }

// Tunnel is the Cloudflare tunnel (or the stand-in of Config.Tunnel).
func (a *App) Tunnel() Tunnel { return a.cf }

// Logf writes a diagnostic line.
func (a *App) Logf(format string, args ...any) { a.logf(format, args...) }

// Notify tells every open page that something it shows changed: it
// refetches what belongs to the topics ("devices", "state").
func (a *App) Notify(topics ...string) { a.hub.notify(topics...) }

// Handle registers an API route or page of the app, for signed-in people
// only; a request that changes something must also pass the CSRF guard
// (the shell's fetch helper sends its header). pattern is a ServeMux
// pattern ("GET /api/devices/{id}").
func (a *App) Handle(pattern string, h http.Handler) {
	a.add(pattern, a.private(h))
}

// HandleFunc is Handle for a function.
func (a *App) HandleFunc(pattern string, h http.HandlerFunc) { a.Handle(pattern, h) }

// Public registers a route anybody may call, signed in or not, still behind
// the CSRF guard: a status page, a public form.
func (a *App) Public(pattern string, h http.HandlerFunc) {
	a.add(pattern, a.guard(h))
}

// Unguarded registers a route without the sign-in and without the CSRF
// guard: a page that takes a plain form post or a navigation from another
// site (a demo's stand-in pages, an OAuth return). The handler checks its
// caller itself. Through the tunnel it still needs the Cloudflare Access
// login, like every route that is not a bypass path.
func (a *App) Unguarded(pattern string, h http.HandlerFunc) {
	a.add(pattern, h)
}

// add keeps a route for both listeners. It is tried on a mux with the
// server's own routes at once, so a pattern that conflicts with them (or
// with another route) panics here, at its registration, as ServeMux does,
// rather than at Run.
func (a *App) add(pattern string, h http.Handler) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.built {
		panic("server: routes must be registered before Run or Handler")
	}
	if a.probe == nil {
		a.probe = a.baseMux()
	}
	func() {
		defer func() {
			if v := recover(); v != nil {
				panic(fmt.Sprintf("server: the route %q cannot be registered: %v", pattern, v))
			}
		}()
		a.probe.Handle(pattern, h)
	}()
	a.routes = append(a.routes, route{pattern, h})
}

// Run serves until ctx ends, then shuts down: it stops cloudflared, lets
// running requests finish for a few seconds and closes the database.
func (a *App) Run(ctx context.Context) error {
	local, tunnel := a.handlers()
	ln, err := net.Listen("tcp", a.cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", a.cfg.Listen, err)
	}
	listeners := []net.Listener{ln}
	servers := []*http.Server{{Handler: local, ReadHeaderTimeout: 20 * time.Second, ReadTimeout: time.Minute, IdleTimeout: 2 * time.Minute}}
	// A stand-in tunnel (a demo) has no origin: nothing reaches it, so
	// nothing listens for it.
	where := "no tunnel listener (" + a.cfg.Name + " runs with a stand-in tunnel)"
	if a.cf.Origin() != "" {
		tln, err := a.listenTunnel()
		if err != nil {
			ln.Close()
			return err
		}
		listeners = append(listeners, tln)
		servers = append(servers, &http.Server{Handler: tunnel, ReadHeaderTimeout: 20 * time.Second, ReadTimeout: time.Minute, IdleTimeout: 2 * time.Minute})
		where = "the tunnel reaches it at " + a.cf.Origin()
	}
	errs := make(chan error, len(listeners))
	for i, l := range listeners {
		go func(srv *http.Server, l net.Listener) {
			if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errs <- err
			}
		}(servers[i], l)
	}
	cfCtx, stopCF := context.WithCancel(context.Background())
	cfDone := make(chan struct{})
	go func() { defer close(cfDone); a.cf.Run(cfCtx) }()
	a.logf("%s %s listens on %s; %s", a.cfg.Name, a.cfg.Version, ln.Addr(), where)

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errs:
	}
	a.hub.close()
	stopCF()
	select {
	case <-cfDone:
	case <-time.After(12 * time.Second):
	}
	shut, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, srv := range servers {
		_ = srv.Shutdown(shut)
	}
	if a.db != nil {
		if err := a.db.Close(); err != nil && runErr == nil {
			runErr = err
		}
	}
	return runErr
}

// tunnelOrigin is what cloudflared sends the requests to.
func (a *App) tunnelOrigin() string {
	if a.cfg.TunnelListen != "" {
		return "http://" + a.cfg.TunnelListen
	}
	return "unix:" + a.socketPath()
}

func (a *App) socketPath() string { return filepath.Join(a.cfg.DataDir, "run", "tunnel.sock") }

func (a *App) listenTunnel() (net.Listener, error) {
	if a.cfg.TunnelListen != "" {
		host, _, err := net.SplitHostPort(a.cfg.TunnelListen)
		if ip := net.ParseIP(host); err != nil || ip == nil || !ip.IsLoopback() {
			return nil, fmt.Errorf("the tunnel's address %s must be a loopback address such as 127.0.0.1:8081: "+
				"whoever reaches it is trusted to be cloudflared", a.cfg.TunnelListen)
		}
		ln, err := net.Listen("tcp", a.cfg.TunnelListen)
		if err != nil {
			return nil, fmt.Errorf("listen for the tunnel on %s: %w", a.cfg.TunnelListen, err)
		}
		return ln, nil
	}
	return listenUnix(a.socketPath())
}

// listenUnix listens on a socket only this user may open. A socket left
// behind by a run that did not stop cleanly is replaced.
func listenUnix(path string) (net.Listener, error) {
	if len(path) > 100 {
		return nil, fmt.Errorf("the socket path %s is too long for a Unix socket; use a shorter data directory "+
			"or set a loopback address for the tunnel", path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		_ = os.Remove(path)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen for the tunnel on %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// checkBypass refuses a bypass path that would take the server's own paths
// or more than the app means: it is one or more plain segments ("/webhook",
// "/hooks/github"), below none of the server's roots.
func checkBypass(path string) error {
	p := strings.TrimSuffix(path, "/")
	if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "{}*?#%. \t") || strings.Contains(p, "//") {
		return fmt.Errorf("server: %q cannot be a bypass path: use a plain path such as /webhook", path)
	}
	for _, root := range []string{"/api", "/z-dash", "/healthz"} {
		if p == root || strings.HasPrefix(p, root+"/") {
			return fmt.Errorf("server: %q cannot be a bypass path: %s belongs to the server", path, root)
		}
	}
	return nil
}

// close releases what New opened, when New fails after opening it.
func (a *App) close() {
	if a.db != nil {
		a.db.Close()
	}
}

// slugOf makes a slug of a name: "My App" -> "my-app".
func slugOf(name string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9':
			b.WriteRune(r)
			dash = false
		case !dash && b.Len() > 0:
			b.WriteByte('-')
			dash = true
		}
	}
	if out := strings.TrimSuffix(b.String(), "-"); out != "" {
		return out
	}
	return "app"
}

// cookieName is the session cookie of an app: "my-app" -> "my_app_session".
func cookieName(slug string) string { return strings.ReplaceAll(slug, "-", "_") + "_session" }

func sortedPaths(paths []string) []string {
	out := append([]string(nil), paths...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// cfKV is the KV as the tunnel keeps its state in it: strings, "" for a
// missing key.
type cfKV struct{ kv KV }

func (k cfKV) GetKV(key string) (string, error) {
	v, err := k.kv.Get(key)
	if errors.Is(err, store.ErrNotFound) {
		return "", nil
	}
	return string(v), err
}

func (k cfKV) SetKV(key, value string) error { return k.kv.Set(key, []byte(value)) }
func (k cfKV) DeleteKV(key string) error     { return k.kv.Delete(key) }
