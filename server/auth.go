package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"

	"github.com/saschazesiger/Z-Dash/server/store"
)

// The keys of the server's own state in the KV. Their format is the one the
// first apps on this server used, so an app that moves onto it keeps its
// password and sessions.
const (
	keyPassword = "auth.password"
	keySessions = "auth.sessions"
)

const (
	sessionMaxAge  = 30 * 24 * time.Hour
	minPasswordLen = 10
	maxPasswordLen = 256
)

// passwordHash is the stored form of the admin password (Argon2id).
type passwordHash struct {
	Salt    []byte `json:"salt"`
	Hash    []byte `json:"hash"`
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"` // KiB
	Threads uint8  `json:"threads"`
}

// Parameters after OWASP's recommendation for Argon2id; they are stored
// with every hash, so they can grow later without breaking old ones.
const (
	argonTime    = 2
	argonMemory  = 19 * 1024
	argonThreads = 1
	argonKeyLen  = 32
)

func hashPassword(pw string) passwordHash {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}
	return passwordHash{
		Salt: salt, Time: argonTime, Memory: argonMemory, Threads: argonThreads,
		Hash: argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen),
	}
}

func (p passwordHash) matches(pw string) bool {
	// A damaged record must not make Argon2 allocate without bounds.
	if len(p.Hash) == 0 || p.Memory == 0 || p.Memory > 1<<20 || p.Time == 0 || p.Time > 16 || p.Threads == 0 {
		return false
	}
	got := argon2.IDKey([]byte(pw), p.Salt, p.Time, p.Memory, p.Threads, uint32(len(p.Hash)))
	return subtle.ConstantTimeCompare(got, p.Hash) == 1
}

func checkNewPassword(pw string) error {
	switch {
	case utf8.RuneCountInString(pw) < minPasswordLen:
		return fmt.Errorf("Use at least %d characters.", minPasswordLen)
	case len(pw) > maxPasswordLen:
		return fmt.Errorf("Use at most %d characters.", maxPasswordLen)
	}
	return nil
}

// session is one signed-in browser. Only the SHA-256 of its token is kept,
// so a copy of the database lets nobody in.
type session struct {
	Expires int64 `json:"expires"` // Unix ms
}

// auth holds the password, the sessions and the login limits.
type auth struct {
	kv     KV
	cookie string
	logf   func(string, ...any)

	mu       sync.Mutex
	sessions map[string]session // by token hash
	attempts map[string]*attempt
	now      func() time.Time
}

type attempt struct {
	fails int
	until time.Time // no attempt before this
	last  time.Time
}

func newAuth(kv KV, cookie string, logf func(string, ...any)) *auth {
	a := &auth{kv: kv, cookie: cookie, logf: logf, sessions: map[string]session{}, attempts: map[string]*attempt{}, now: time.Now}
	// Sessions survive a restart, so an update does not sign everybody out.
	if raw, err := kv.Get(keySessions); err == nil {
		if err := json.Unmarshal(raw, &a.sessions); err != nil {
			logf("sessions: %v", err)
		}
	} else if !errors.Is(err, store.ErrNotFound) {
		logf("sessions: %v", err)
	}
	if a.sessions == nil {
		a.sessions = map[string]session{}
	}
	return a
}

func (a *auth) hasPassword() bool {
	_, err := a.kv.Get(keyPassword)
	return err == nil
}

// hash is hashPassword within the bound on Argon2 runs at once.
func hash(pw string) passwordHash {
	hashing <- struct{}{}
	defer func() { <-hashing }()
	return hashPassword(pw)
}

func (a *auth) setPassword(pw string) error {
	if err := checkNewPassword(pw); err != nil {
		return err
	}
	raw, err := json.Marshal(hash(pw))
	if err != nil {
		return err
	}
	return a.kv.Set(keyPassword, raw)
}

// setFirstPassword sets the password only if none is set, atomically, so
// two first visitors cannot both win.
func (a *auth) setFirstPassword(pw string) (bool, error) {
	if err := checkNewPassword(pw); err != nil {
		return false, err
	}
	// Set already: no hash is spent on a request that cannot win.
	if a.hasPassword() {
		return false, nil
	}
	raw, err := json.Marshal(hash(pw))
	if err != nil {
		return false, err
	}
	return a.kv.SetIfMissing(keyPassword, raw)
}

// hashing bounds the Argon2 runs at once: each takes memory on purpose, and
// a flood of logins must not exhaust the machine.
var hashing = make(chan struct{}, 4)

func (a *auth) verify(pw string) bool {
	hashing <- struct{}{}
	defer func() { <-hashing }()
	var h passwordHash
	raw, err := a.kv.Get(keyPassword)
	if err == nil {
		err = json.Unmarshal(raw, &h)
	}
	if err != nil {
		// Spend the same time, so a missing password is not visible.
		hashPassword(pw)
		return false
	}
	return h.matches(pw)
}

// limited reports how long a client still has to wait before the next
// attempt. Five failures are free, then the wait doubles from 30 seconds up
// to 15 minutes. The attempt counts before the password is checked, so
// guesses sent in parallel cannot all slip through; success forgets it.
func (a *auth) limited(ip string) time.Duration {
	ip = limitKey(ip)
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	if at := a.attempts[ip]; at != nil {
		if d := at.until.Sub(now); d > 0 {
			return d
		}
	}
	at := a.attempts[ip]
	if at == nil || now.Sub(at.last) > time.Hour {
		at = &attempt{}
		a.attempts[ip] = at
	}
	at.fails++
	at.last = now
	if at.fails >= 5 {
		d := 30 * time.Second << min(at.fails-5, 10)
		if d > 15*time.Minute {
			d = 15 * time.Minute
		}
		at.until = now.Add(d)
	}
	// Keep the map small: forget clients that went quiet, and past a hard
	// cap those that are not waiting out a pause.
	if len(a.attempts) > 1000 {
		for k, v := range a.attempts {
			if now.Sub(v.last) > time.Hour || (len(a.attempts) > 10000 && !v.until.After(now)) {
				delete(a.attempts, k)
			}
		}
	}
	return 0
}

// limitKey is what the login limit counts by: the address, and for IPv6 its
// /64, which one client usually holds whole.
func limitKey(ip string) string {
	if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() == nil {
		return parsed.Mask(net.CIDRMask(64, 128)).String() + "/64"
	}
	return ip
}

func (a *auth) succeeded(ip string) {
	ip = limitKey(ip)
	a.mu.Lock()
	delete(a.attempts, ip)
	a.mu.Unlock()
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// startSession creates a session and sets its cookie.
func (a *auth) startSession(w http.ResponseWriter, r *http.Request) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	token := base64.RawURLEncoding.EncodeToString(b)
	exp := a.now().Add(sessionMaxAge)
	a.mu.Lock()
	a.sessions[tokenHash(token)] = session{Expires: exp.UnixMilli()}
	a.saveLocked()
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: a.cookie, Value: token, Path: "/", Expires: exp, MaxAge: int(sessionMaxAge / time.Second),
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil,
	})
}

func (a *auth) endSession(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(a.cookie); err == nil {
		a.mu.Lock()
		delete(a.sessions, tokenHash(c.Value))
		a.saveLocked()
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: a.cookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
		SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil})
}

// dropSessions signs everybody out except the session of keepToken.
func (a *auth) dropSessions(keepToken string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	keep := ""
	if keepToken != "" {
		keep = tokenHash(keepToken)
	}
	for k := range a.sessions {
		if k != keep {
			delete(a.sessions, k)
		}
	}
	a.saveLocked()
}

func (a *auth) check(r *http.Request) bool {
	c, err := r.Cookie(a.cookie)
	if err != nil || c.Value == "" {
		return false
	}
	h := tokenHash(c.Value)
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[h]
	if !ok {
		return false
	}
	if s.Expires < a.now().UnixMilli() {
		delete(a.sessions, h)
		a.saveLocked()
		return false
	}
	return true
}

func (a *auth) saveLocked() {
	now := a.now().UnixMilli()
	for k, s := range a.sessions {
		if s.Expires < now {
			delete(a.sessions, k)
		}
	}
	raw, err := json.Marshal(a.sessions)
	if err == nil {
		err = a.kv.Set(keySessions, raw)
	}
	if err != nil {
		a.logf("save sessions: %v", err)
	}
}

// HasPassword reports whether the admin password is set (the first visitor
// sets it on the local listener).
func (a *App) HasPassword() bool { return a.auth.hasPassword() }

// --- handlers ----------------------------------------------------------------

// SessionInfo is what GET /api/session answers; the shell starts from it.
type SessionInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	// Env is the prefix of the app's environment variables ("INVENTORY"),
	// for hints such as INVENTORY_ADMIN_PASSWORD.
	Env string `json:"env"`
	// Pages: the app has pages of its own at /; without them / leads to the
	// shell's settings.
	Pages    bool `json:"pages"`
	SignedIn bool `json:"signedIn"`
	// NeedsPassword: first run on the local listener, nobody set the
	// password yet; the shell asks for one.
	NeedsPassword bool   `json:"needsPassword"`
	Via           string `json:"via"`
	Email         string `json:"email"`
	Open          bool   `json:"open"`
	// Tunnel is the public address once the tunnel is set up.
	Tunnel string `json:"tunnel"`
	// Logout is where signing out goes: "" for the password session,
	// Cloudflare Access's logout for a tunnel session.
	Logout string `json:"logout"`
}

func (a *App) session(w http.ResponseWriter, r *http.Request) {
	id := Who(r)
	info := SessionInfo{Name: a.cfg.Name, Version: a.cfg.Version, Env: a.cfg.Env, Pages: a.assets != nil,
		Via: id.Via, Email: id.Email, Open: a.cfg.Open}
	info.SignedIn = a.SignedIn(r)
	if id.Via == "local" && !a.cfg.Open {
		info.NeedsPassword = !a.auth.hasPassword()
	}
	if id.Via == "tunnel" {
		info.Logout = accessLogout
	}
	if info.SignedIn {
		info.Tunnel = a.cf.PublicURL()
	}
	WriteJSON(w, http.StatusOK, info)
}

type passwordReq struct {
	Password string `json:"password"`
	Current  string `json:"current"`
}

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	if Who(r).Via == "tunnel" {
		WriteError(w, http.StatusForbidden, "Through Cloudflare you sign in with Cloudflare Access, not with the password.")
		return
	}
	ip := clientIP(r)
	if d := a.auth.limited(ip); d > 0 {
		WriteError(w, http.StatusTooManyRequests, "Too many wrong passwords. Wait "+roundWait(d.Seconds())+" and try again.")
		return
	}
	var req passwordReq
	if !Decode(w, r, &req) {
		return
	}
	if !a.auth.hasPassword() {
		WriteError(w, http.StatusConflict, "No password is set yet. Reload the page to set one.")
		return
	}
	if !a.auth.verify(req.Password) {
		a.logf("login: wrong password from %s", ip)
		WriteFieldError(w, "password", "The password is wrong.")
		return
	}
	a.auth.succeeded(ip)
	a.auth.startSession(w, r)
	WriteJSON(w, http.StatusOK, map[string]bool{"signedIn": true})
}

func (a *App) firstPassword(w http.ResponseWriter, r *http.Request) {
	if Who(r).Via == "tunnel" {
		WriteError(w, http.StatusForbidden, "Set the password on the local address.")
		return
	}
	if a.auth.hasPassword() {
		WriteError(w, http.StatusConflict, "A password was set already. Sign in with it.")
		return
	}
	ip := clientIP(r)
	if d := a.auth.limited(ip); d > 0 {
		WriteError(w, http.StatusTooManyRequests, "Too many attempts. Wait "+roundWait(d.Seconds())+" and try again.")
		return
	}
	var req passwordReq
	if !Decode(w, r, &req) {
		return
	}
	won, err := a.auth.setFirstPassword(req.Password)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			err = errors.New("The password could not be saved.")
		}
		WriteFieldError(w, "password", err.Error())
		return
	}
	if !won {
		WriteError(w, http.StatusConflict, "A password was set already. Sign in with it.")
		return
	}
	a.auth.succeeded(ip)
	a.logf("The admin password was set by the first visitor (%s)", ip)
	a.auth.startSession(w, r)
	WriteJSON(w, http.StatusOK, map[string]bool{"signedIn": true})
}

func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	a.auth.endSession(w, r)
	next := ""
	if Who(r).Via == "tunnel" {
		next = accessLogout
	}
	WriteJSON(w, http.StatusOK, map[string]any{"signedIn": false, "next": next})
}

func (a *App) changePassword(w http.ResponseWriter, r *http.Request) {
	var req passwordReq
	if !Decode(w, r, &req) {
		return
	}
	if err := checkNewPassword(req.Password); err != nil {
		WriteFieldError(w, "password", err.Error())
		return
	}
	// Through the tunnel, Cloudflare Access vouched for the person: the
	// current password is not needed. Locally it is.
	if Who(r).Via != "tunnel" && a.auth.hasPassword() {
		ip := clientIP(r)
		if d := a.auth.limited(ip); d > 0 {
			WriteError(w, http.StatusTooManyRequests, "Too many wrong passwords. Wait "+roundWait(d.Seconds())+" and try again.")
			return
		}
		if !a.auth.verify(req.Current) {
			WriteFieldError(w, "current", "The current password is wrong.")
			return
		}
		a.auth.succeeded(ip)
	}
	if err := a.auth.setPassword(req.Password); err != nil {
		a.logf("password: %v", err)
		WriteError(w, http.StatusInternalServerError, "The password could not be saved.")
		return
	}
	keep := ""
	if c, err := r.Cookie(a.auth.cookie); err == nil {
		keep = c.Value
	}
	a.auth.dropSessions(keep)
	WriteJSON(w, http.StatusOK, map[string]string{"message": "Password changed. Other browsers were signed out."})
}
