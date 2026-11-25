package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/saschazesiger/Z-Dash/server/cloudflare"
	"github.com/saschazesiger/Z-Dash/server/secret"
	"github.com/saschazesiger/Z-Dash/server/store"
)

func newApp(t *testing.T, cfg Config) *App {
	t.Helper()
	if cfg.Name == "" {
		cfg.Name = "Example"
	}
	if cfg.DataDir == "" {
		cfg.DataDir = t.TempDir()
	}
	cfg.Logf = t.Logf
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if a.db != nil {
			a.db.Close()
		}
	})
	return a
}

// do sends a request to h as the interface would: with the CSRF header on
// writes, and the cookies of jar.
func do(t *testing.T, h http.Handler, method, path, body string, jar map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, "http://192.168.1.5:8080"+path, strings.NewReader(body))
	if method != http.MethodGet {
		r.Header.Set(CSRFHeader, "1")
		r.Header.Set("Content-Type", "application/json")
	}
	for k, v := range jar {
		r.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if jar != nil {
		for _, c := range w.Result().Cookies() {
			if c.MaxAge < 0 {
				delete(jar, c.Name)
			} else {
				jar[c.Name] = c.Value
			}
		}
	}
	return w
}

func sessionOf(t *testing.T, h http.Handler, jar map[string]string) SessionInfo {
	t.Helper()
	var info SessionInfo
	if err := json.Unmarshal(do(t, h, "GET", "/api/session", "", jar).Body.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	return info
}

// First run: the first visitor sets the password and is signed in; a
// second one cannot set it again; the password signs in later, a wrong one
// does not, and signing out ends the session.
func TestPasswordFlow(t *testing.T) {
	a := newApp(t, Config{})
	a.HandleFunc("GET /api/things", func(w http.ResponseWriter, r *http.Request) { WriteJSON(w, 200, []string{"a"}) })
	h := a.Handler()
	jar := map[string]string{}

	if info := sessionOf(t, h, jar); info.SignedIn || !info.NeedsPassword || info.Name != "Example" || info.Via != "local" {
		t.Fatalf("first session = %+v", info)
	}
	if w := do(t, h, "GET", "/api/things", "", jar); w.Code != 401 {
		t.Fatalf("an app route before the password: %d", w.Code)
	}
	if w := do(t, h, "POST", "/api/setup/password", `{"password":"short"}`, jar); w.Code != 400 || !strings.Contains(w.Body.String(), `"password"`) {
		t.Fatalf("short password: %d %s", w.Code, w.Body)
	}
	if w := do(t, h, "POST", "/api/setup/password", `{"password":"correct horse battery"}`, jar); w.Code != 200 {
		t.Fatalf("first password: %d %s", w.Code, w.Body)
	}
	if _, ok := jar["example_session"]; !ok {
		t.Fatalf("no session cookie: %v", jar)
	}
	if w := do(t, h, "GET", "/api/things", "", jar); w.Code != 200 {
		t.Fatalf("an app route after the password: %d", w.Code)
	}
	if w := do(t, h, "POST", "/api/setup/password", `{"password":"another password!"}`, map[string]string{}); w.Code != 409 {
		t.Fatalf("a second first password: %d", w.Code)
	}

	other := map[string]string{}
	if w := do(t, h, "POST", "/api/login", `{"password":"wrong password"}`, other); w.Code != 400 {
		t.Fatalf("wrong password: %d", w.Code)
	}
	if w := do(t, h, "POST", "/api/login", `{"password":"correct horse battery"}`, other); w.Code != 200 {
		t.Fatalf("login: %d %s", w.Code, w.Body)
	}
	if !sessionOf(t, h, other).SignedIn {
		t.Fatal("not signed in after the login")
	}
	if w := do(t, h, "POST", "/api/logout", `{}`, other); w.Code != 200 {
		t.Fatalf("logout: %d", w.Code)
	}
	if sessionOf(t, h, other).SignedIn {
		t.Fatal("still signed in after signing out")
	}

	// Sessions survive a restart: a new App on the same data directory.
	b := newApp(t, Config{DataDir: a.cfg.DataDir})
	a.db.Close()
	if !sessionOf(t, b.Handler(), jar).SignedIn {
		t.Fatal("the session did not survive a restart")
	}
}

func TestLoginRateLimit(t *testing.T) {
	a := newApp(t, Config{AdminPassword: "correct horse battery"})
	h := a.Handler()
	for i := 0; i < 5; i++ {
		do(t, h, "POST", "/api/login", `{"password":"wrong password"}`, map[string]string{})
	}
	if w := do(t, h, "POST", "/api/login", `{"password":"correct horse battery"}`, map[string]string{}); w.Code != 429 {
		t.Fatalf("the sixth attempt: %d", w.Code)
	}
}

// Changing something needs the CSRF header and, when the browser names it,
// the same origin.
func TestCSRFGuard(t *testing.T) {
	a := newApp(t, Config{Open: true})
	a.HandleFunc("POST /api/things", func(w http.ResponseWriter, r *http.Request) { WriteJSON(w, 200, "ok") })
	h := a.Handler()
	r := httptest.NewRequest("POST", "http://192.168.1.5:8080/api/things", strings.NewReader("{}"))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Errorf("without the header: %d", w.Code)
	}
	r = httptest.NewRequest("POST", "http://192.168.1.5:8080/api/things", strings.NewReader("{}"))
	r.Header.Set(CSRFHeader, "1")
	r.Header.Set("Origin", "https://evil.example")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Errorf("from another origin: %d", w.Code)
	}
	if w := do(t, h, "POST", "/api/things", "{}", nil); w.Code != 200 {
		t.Errorf("from the interface: %d", w.Code)
	}
}

func TestLocalHostGuard(t *testing.T) {
	for host, want := range map[string]bool{
		"192.168.1.5:8080": true, "[::1]:8080": true, "nas:8080": true, "nas.local": true, "box.ts.net": true,
		"evil.example.com": false, "app.example.org": true, "": false,
	} {
		if got := localName(host, []string{"app.example.org"}); got != want {
			t.Errorf("localName(%q) = %v", host, got)
		}
	}
	a := newApp(t, Config{})
	r := httptest.NewRequest("GET", "http://evil.example.com/api/session", nil)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	if w.Code != 403 || w.Header().Get("Content-Security-Policy") == "" {
		t.Errorf("a public name: %d", w.Code)
	}
}

// The tunnel's listener: without an Access token only the bypass paths
// answer, and they carry the marker the check from outside looks for.
func TestTunnelGate(t *testing.T) {
	hook := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if Who(r).Via != "tunnel" || Who(r).Email != "" {
			t.Errorf("identity on a bypass path = %+v", Who(r))
		}
		io.WriteString(w, "hook")
	})
	a := newApp(t, Config{Bypass: map[string]http.Handler{"/webhook": hook}})
	h := a.TunnelHandler()
	r := httptest.NewRequest("POST", "https://app.example.com/webhook", strings.NewReader("{}"))
	r.Header.Set("Cf-Connecting-Ip", "203.0.113.9")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || w.Body.String() != "hook" || w.Header().Get(cloudflare.MarkerHeader) == "" {
		t.Errorf("webhook: %d %q", w.Code, w.Body)
	}
	for _, path := range []string{"/", "/api/session", "/z-dash/ds.min.css", "/webhookx"} {
		r := httptest.NewRequest("GET", "https://app.example.com"+path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 || w.Header().Get(cloudflare.MarkerHeader) == "" {
			t.Errorf("%s without Access: %d", path, w.Code)
		}
	}
	if got := a.cf.BypassPaths(); len(got) != 1 || got[0] != "/webhook" {
		t.Errorf("bypass = %v", got)
	}
}

func TestBypassPathsMustBeSafe(t *testing.T) {
	for _, path := range []string{"/", "/api/hook", "/z-dash/x", "hook"} {
		if _, err := New(Config{Name: "X", DataDir: t.TempDir(), Bypass: map[string]http.Handler{path: http.NotFoundHandler()}}); err == nil {
			t.Errorf("%q was accepted as a bypass path", path)
		}
	}
}

func TestAssets(t *testing.T) {
	files := fstest.MapFS{
		"index.html": {Data: []byte("<!doctype html><title>App</title>")},
		"app.js":     {Data: []byte("export {};")},
	}
	a := newApp(t, Config{Open: true, Assets: files})
	h := a.Handler()
	w := do(t, h, "GET", "/", "", nil)
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-cache" || !strings.Contains(w.Body.String(), "<title>App") {
		t.Fatalf("/: %d %q", w.Code, w.Header())
	}
	w = do(t, h, "GET", "/app.js", "", nil)
	if w.Header().Get("Content-Type") != "text/javascript; charset=utf-8" || w.Header().Get("ETag") == "" {
		t.Fatalf("app.js: %q", w.Header())
	}
	r := httptest.NewRequest("GET", "http://192.168.1.5/app.js", nil)
	r.Header.Set("If-None-Match", w.Header().Get("ETag"))
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, r)
	if w2.Code != 304 {
		t.Errorf("revalidation: %d", w2.Code)
	}
	for _, path := range []string{"/z-dash/ds.min.css", "/z-dash/ds.min.js", "/z-dash/themes/dark.css", "/z-dash/server/"} {
		if w := do(t, h, "GET", path, "", nil); w.Code != 200 {
			t.Errorf("%s: %d", path, w.Code)
		}
	}
	for _, path := range []string{"/z-dash/tools/verify.mjs", "/z-dash/SHA256SUMS", "/nothing.js"} {
		if w := do(t, h, "GET", path, "", nil); w.Code != 404 {
			t.Errorf("%s: %d", path, w.Code)
		}
	}
	if w := do(t, h, "GET", "/api/nothing", "", nil); w.Code != 404 || !strings.Contains(w.Body.String(), `"error"`) {
		t.Errorf("/api/nothing: %d %s", w.Code, w.Body)
	}
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe-inline") {
		t.Errorf("csp = %q", csp)
	}
}

func TestCSPAdditions(t *testing.T) {
	a := newApp(t, Config{CSP: map[string]string{"form-action": "https://github.com", "frame-ancestors": "https://x.example", "bad;": "x"}})
	csp := a.csp()
	if !strings.Contains(csp, "form-action 'self' https://github.com") || !strings.Contains(csp, "frame-ancestors https://x.example") || strings.Contains(csp, "bad") {
		t.Errorf("csp = %q", csp)
	}
}

func TestPanicIsAnError(t *testing.T) {
	a := newApp(t, Config{Open: true})
	a.HandleFunc("GET /api/boom", func(http.ResponseWriter, *http.Request) { panic("boom") })
	if w := do(t, a.Handler(), "GET", "/api/boom", "", nil); w.Code != 500 || !strings.Contains(w.Body.String(), `"error"`) {
		t.Errorf("panic: %d %s", w.Code, w.Body)
	}
}

func TestAdminPasswordResets(t *testing.T) {
	dir := t.TempDir()
	a := newApp(t, Config{DataDir: dir, AdminPassword: "first password!"})
	jar := map[string]string{}
	do(t, a.Handler(), "POST", "/api/login", `{"password":"first password!"}`, jar)
	a.db.Close()
	b := newApp(t, Config{DataDir: dir, AdminPassword: "second password"})
	h := b.Handler()
	if sessionOf(t, h, jar).SignedIn {
		t.Error("a reset password kept the old sessions")
	}
	if w := do(t, h, "POST", "/api/login", `{"password":"second password"}`, map[string]string{}); w.Code != 200 {
		t.Errorf("the reset password: %d", w.Code)
	}
}

func TestFromEnv(t *testing.T) {
	t.Setenv("MY_APP_LISTEN", "127.0.0.1:9000")
	t.Setenv("MY_APP_HOSTS", "a.example, b.example")
	t.Setenv("MY_APP_OPEN", "1")
	c := Config{Name: "My App"}
	c.FromEnv()
	if c.Slug != "my-app" || c.Env != "MY_APP" || c.Listen != "127.0.0.1:9000" || len(c.Hosts) != 2 || !c.Open {
		t.Errorf("config = %+v", c)
	}
	if cookieName(c.Slug) != "my_app_session" {
		t.Error(cookieName(c.Slug))
	}
}

func TestStoreMigrations(t *testing.T) {
	dir := t.TempDir()
	m1 := func(tx *sql.Tx) error {
		_, err := tx.Exec(`CREATE TABLE devices (id INTEGER PRIMARY KEY, name TEXT)`)
		return err
	}
	m2 := func(tx *sql.Tx) error { _, err := tx.Exec(`ALTER TABLE devices ADD COLUMN room TEXT`); return err }
	s, err := store.Open(dir+"/x.db", m1)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Set("k", []byte("v")); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = store.Open(dir+"/x.db", m1, m2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec(`INSERT INTO devices(name, room) VALUES('a', 'b')`); err != nil {
		t.Fatal(err)
	}
	if v, err := s.Get("k"); err != nil || string(v) != "v" {
		t.Fatalf("kv = %q, %v", v, err)
	}
	if won, _ := s.SetIfMissing("k", []byte("w")); won {
		t.Error("SetIfMissing overwrote")
	}
	if _, err := s.Get("missing"); err != store.ErrNotFound {
		t.Errorf("missing key: %v", err)
	}
	s.Close()
	if _, err := store.Open(dir+"/x.db", m1); err == nil {
		t.Error("an older version opened a newer database")
	}
}

func TestSecretBox(t *testing.T) {
	dir := t.TempDir()
	b, err := secret.Load(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	sealed, _ := b.Seal("a", []byte("token"))
	again, err := secret.Load(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if plain, err := again.Open("a", sealed); err != nil || string(plain) != "token" {
		t.Fatalf("open = %q, %v", plain, err)
	}
	if _, err := again.Open("b", sealed); err == nil {
		t.Error("a sealed value opened under another name")
	}
	if _, err := secret.Load(dir, "not base64"); err == nil {
		t.Error("a bad key was accepted")
	}
}

// Notify reaches an open event stream as one coalesced "change".
func TestEvents(t *testing.T) {
	a := newApp(t, Config{Open: true})
	srv := httptest.NewServer(a.Handler())
	defer srv.Close()
	req, _ := http.NewRequest("GET", srv.URL+"/api/events", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("content type %q", resp.Header.Get("Content-Type"))
	}
	go func() {
		time.Sleep(100 * time.Millisecond)
		a.Notify("devices")
		a.Notify("devices", "state")
	}()
	buf := make([]byte, 0, 512)
	tmp := make([]byte, 256)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(string(buf), "state") {
		n, err := resp.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			break
		}
	}
	if !strings.Contains(string(buf), `event: change`) || !strings.Contains(string(buf), `{"topics":["devices","state"]}`) {
		t.Errorf("stream = %q", buf)
	}
}

// A demo tunnel runs the whole setup through the API without Cloudflare.
func TestDemoTunnel(t *testing.T) {
	demo := cloudflare.NewDemo("Example", nil)
	demo.Step = time.Millisecond
	a := newApp(t, Config{Open: true, Tunnel: demo})
	h := a.Handler()
	if w := do(t, h, "POST", "/api/cloudflare/check", `{"apiToken":"short"}`, nil); w.Code != 400 || !strings.Contains(w.Body.String(), `"apiToken"`) {
		t.Fatalf("short token: %d %s", w.Code, w.Body)
	}
	body := `{"apiToken":"0123456789abcdefghijkl","zoneId":"zone-example-com","hostname":"app.example.com","emails":["a@example.com"]}`
	if w := do(t, h, "POST", "/api/cloudflare/setup", body, nil); w.Code != 200 {
		t.Fatalf("setup: %d %s", w.Code, w.Body)
	}
	deadline := time.Now().Add(5 * time.Second)
	for demo.Status().Job.Running && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if st := demo.Status(); !st.Configured || !st.Job.OK || st.PublicURL != "https://app.example.com" {
		t.Fatalf("status = %+v", st)
	}
	if info := sessionOf(t, h, nil); info.Tunnel != "https://app.example.com" {
		t.Errorf("session = %+v", info)
	}
	if w := do(t, h, "PUT", "/api/cloudflare/emails", `{"emails":["not an address"]}`, nil); w.Code != 400 {
		t.Errorf("bad address: %d", w.Code)
	}
	if w := do(t, h, "DELETE", "/api/cloudflare", "", nil); w.Code != 200 {
		t.Fatalf("remove: %d %s", w.Code, w.Body)
	}
	for demo.Status().Job.Running && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if st := demo.Status(); st.Configured || !st.Job.OK {
		t.Fatalf("after removal = %+v", st)
	}
}

// Review findings: a conflicting route panics where it is registered, a bad
// admin password stops the start, a set password costs no hash, the first
// password is rate-limited, and IPv6 clients are limited by their /64.
func TestHardening(t *testing.T) {
	a := newApp(t, Config{})
	func() {
		defer func() {
			if v := recover(); v == nil || !strings.Contains(fmt.Sprint(v), "/z-dash/") {
				t.Errorf("a conflicting route: %v", v)
			}
		}()
		a.HandleFunc("GET /{dir}/items", func(http.ResponseWriter, *http.Request) {})
	}()
	func() {
		defer func() {
			if v := recover(); v == nil {
				t.Error("a second /api/session was accepted")
			}
		}()
		a.HandleFunc("GET /api/session", func(http.ResponseWriter, *http.Request) {})
	}()
	a.Unguarded("POST /demo/form", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") })
	r := httptest.NewRequest("POST", "http://192.168.1.5/demo/form", strings.NewReader("a=b"))
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Errorf("an unguarded form post: %d", w.Code)
	}

	if _, err := New(Config{Name: "X", DataDir: t.TempDir(), AdminPassword: "short"}); err == nil {
		t.Error("a password too short to set did not stop the start")
	}
	for _, p := range []string{"/api", "/z-dash", "/healthz", "/{x}", "/a b", "/x/../api"} {
		if _, err := New(Config{Name: "X", DataDir: t.TempDir(), Bypass: map[string]http.Handler{p: http.NotFoundHandler()}}); err == nil {
			t.Errorf("%q was accepted as a bypass path", p)
		}
	}

	b := newApp(t, Config{AdminPassword: "correct horse battery"})
	if w := do(t, b.Handler(), "POST", "/api/setup/password", `{"password":"another long one"}`, nil); w.Code != 409 {
		t.Errorf("a first password over a set one: %d", w.Code)
	}
	if limitKey("2001:db8:1:2:3:4:5:6") != limitKey("2001:db8:1:2:ffff::1") || limitKey("2001:db8:1:3::1") == limitKey("2001:db8:1:2::1") {
		t.Error("IPv6 clients are not limited by their /64")
	}
	if limitKey("192.0.2.1") != "192.0.2.1" {
		t.Error(limitKey("192.0.2.1"))
	}
}

// An unguarded route answers under any host name (an API with keys of its
// own); everything else keeps the Host check.
func TestUnguardedSkipsTheHostCheck(t *testing.T) {
	a := newApp(t, Config{})
	a.Unguarded("/v1/", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "model") })
	h := a.Handler()
	for path, want := range map[string]int{"/v1/models": 200, "/api/session": 403, "/": 403} {
		r := httptest.NewRequest("GET", "http://models.example.com"+path, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Errorf("%s under a public name: %d, want %d", path, w.Code, want)
		}
	}
}
