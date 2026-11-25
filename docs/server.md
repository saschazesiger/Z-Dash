# Server

Z-Dash can be used two ways. **Only the design**: vendor `dist/` into any project ([Install](install.md)), whatever
it is written in. **The design with its server**: a Go module that brings everything an admin app needs around its
own pages, so an app is little more than its routes, its tables and its views:

| Ready in the module | What it does |
|---|---|
| Two listeners | the local one (the network the app runs in) signs in with an admin password, which the first visitor sets; the tunnel's one is reached only by `cloudflared`, and whoever Cloudflare Access let in is signed in by the e-mail address Access vouches for |
| Cloudflare tunnel | set up from the interface with an API token: tunnel, DNS record, Access applications and policies, one-time PIN login; `cloudflared` downloaded if missing, supervised, restarted, checked from outside; repair, change who may sign in, remove |
| Guards | a Host check against DNS rebinding on the local listener, a CSRF guard on every request that changes something, a strict Content-Security-Policy, rate-limited logins, panics answered with 500 |
| Z-Dash | the design system embedded and served at `/z-dash/` (`ds.min.css`, `ds.min.js`, fonts, themes): nothing to vendor |
| Shell | the pages and modules every app shares, at `/z-dash/server/`: sign-in, first password, account and sign-out, the tunnel settings, the password |
| Data | a SQLite database (pure Go, no cgo) with numbered migrations, sealed secrets (AES-256-GCM, the key outside the database) |
| Live updates | server-sent events: the app calls `Notify("devices")`, every open page refetches what it shows |
| Operations | `GET /healthz`, a graceful shutdown, configuration from the environment, a Dockerfile and workflows to copy |

The module is `github.com/saschazesiger/Z-Dash/server`, in the `server/` folder of this repository ([`server.go`](../server/server.go) describes it).
It needs Go 1.26 or newer and has two dependencies: `modernc.org/sqlite` and `golang.org/x/crypto`.

## A new app

```sh
go mod init example.com/inventory
go get github.com/saschazesiger/Z-Dash/server@main
```

```go
package main

import (
	"context"
	"database/sql"
	"embed"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/saschazesiger/Z-Dash/server"
	"github.com/saschazesiger/Z-Dash/server/store"
)

//go:embed web
var web embed.FS

func main() {
	files, _ := fs.Sub(web, "web")
	app, err := server.New(server.Config{
		Name:   "Inventory",
		Assets: files,
		Migrations: []store.Migration{
			func(tx *sql.Tx) error {
				_, err := tx.Exec(`CREATE TABLE devices (id INTEGER PRIMARY KEY, name TEXT NOT NULL)`)
				return err
			},
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	app.HandleFunc("GET /api/devices", func(w http.ResponseWriter, r *http.Request) {
		// app.Store().DB() is the database; server.WriteJSON answers.
	})
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := app.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
```

`web/` holds the app's `index.html`, its scripts and its stylesheet. They are served to anybody who reaches the local
listener (through the tunnel: after the Access login), signed in or not, so they hold no data: data comes from the
API. The page loads Z-Dash and the shell from the
server, lays out its frame with the documented markup ([Components](components.md)) and starts the shell, which
signs the person in before the app draws anything. [`server/example/`](../server/example/main.go) is a complete app of this
kind (a list of devices); copy it to start.

## Routes

| Method | What it registers |
|---|---|
| `app.Handle(pattern, h)`, `app.HandleFunc(pattern, f)` | a route for signed-in people; a request that changes something must also pass the CSRF guard (the shell's `api.js` sends the header `X-Z-Dash: 1`). `pattern` is a `net/http` pattern: `"GET /api/devices/{id}"` |
| `app.Public(pattern, f)` | a route anybody on the local network may call, still behind the CSRF guard; through the tunnel it needs the Cloudflare Access login like every route that is not a bypass path |
| `app.Unguarded(pattern, f)` | no sign-in, no CSRF guard and no Host check: a page that takes a plain form post or a navigation from another site, or an API with keys of its own that clients call by any name; the handler checks its caller itself and never relies on the session cookie |
| `Config.Bypass` | handlers Cloudflare Access lets through without a login, by path (`"/webhook"`): no CSRF guard, no sign-in; each checks its caller itself (a signature, a token of its own) |

A route that conflicts with the server's own (`/api/session`, `/z-dash/`, a bypass path, the files at `/`) or with
another route panics where it is registered, as `net/http` does. The database has one connection: inside
`app.Store().Tx` use only the transaction it hands over.

Helpers for handlers: `server.Who(r)` (`Via` is `"local"` or `"tunnel"`, `Email` the Access address),
`server.WriteJSON`, `server.WriteError` (a sentence the shell shows), `server.WriteFieldError` (an error under one
field), `server.Decode` (a JSON body of at most 1 MiB), `server.Origin(r)` (the address the browser uses),
`app.Notify(topics...)`, `app.Store()`, `app.Secrets()`, `app.Logf`.

The server's own routes:

| Route | |
|---|---|
| `GET /healthz` | `ok` while the process serves |
| `GET /api/session` | `{name, version, env, pages, signedIn, needsPassword, via, email, open, tunnel, logout}` |
| `POST /api/setup/password`, `POST /api/login`, `POST /api/logout`, `POST /api/password` | the first password, sign-in (five tries, then a wait that doubles from 30 seconds to 15 minutes), sign-out (`next` is Cloudflare Access's logout through the tunnel), a new password (signs every other browser out) |
| `GET /api/events` | the event stream: `change` with `{"topics": [...]}` |
| `GET /api/cloudflare`, `POST /api/cloudflare/check`, `POST /api/cloudflare/setup`, `PUT /api/cloudflare/emails`, `DELETE /api/cloudflare` | the tunnel: its state and job, a token's domains, the setup (in the background), who may sign in, the removal |
| `/z-dash/`, `/z-dash/server/` | Z-Dash and the shell |

## Configuration

Every field of `server.Config` has a default; most can come from the environment, with the prefix made from the
app's name (`Inventory` reads `INVENTORY_DATA` ...; `Config.Env` sets another).

| Field | Environment | Default | |
|---|---|---|---|
| `Name` | | `App` | the name people read; it names the Cloudflare objects |
| `DataDir` | `_DATA` | `./data` | the database, `secret.key`, the tunnel's socket, a downloaded `cloudflared` |
| `Listen` | `_LISTEN` | `:8080` | the local listener |
| `TunnelListen` | `_TUNNEL_LISTEN` | a Unix socket in `DataDir` (Windows: `127.0.0.1:8081`) | what `cloudflared` reaches; a loopback address or the socket, nothing else |
| `Hosts` | `_HOSTS` | | names the local listener answers to besides addresses and private names (comma-separated, `*` for any) |
| `AdminPassword` | `_ADMIN_PASSWORD` | | sets the admin password at start and signs everybody out: the way back in |
| `SecretKey` | `_SECRET_KEY` | `DataDir/secret.key` | the key of the sealed secrets, 32 bytes in base64 |
| `Cloudflared` | `_CLOUDFLARED` | the one on the `PATH`, else downloaded | |
| `Open` | `_OPEN=1` | | everybody is signed in: demos and tests only |
| `Bypass`, `BypassLabel` | | | paths without the Access login (above) and what they are, for their Access policy's name |
| `AccessSession` | | `24h` | how long a Cloudflare Access login lasts |
| `ReadTimeout` | | a minute | how long a request may take to arrive, body included; more for large uploads over slow links, negative for no bound |
| `Assets` | | | the app's files at `/` |
| `CSP` | | | sources to add, by directive: `{"form-action": "https://github.com"}` |
| `Migrations` | | | the app's tables |
| `KV`, `Sealer` | | the database's `kv` table, the secret box | for an app that keeps a database of its own (below) |
| `Pages` | | | a handler for `/` instead of `Assets`, for an app that serves and gates its own pages (sign-in page, redirects) |
| `Headers` | | | adjusts the security headers of every answer (a handler may still change its own) |
| `SameSite` | | Strict | the session cookie's mode; Lax lets a link from another app open a page signed in |
| `LegacyPassword` | | | an admin password the app stored in a format of its own before (below) |
| `OnSignOut` | | | called when sessions end, so the app ends its own long-lived streams |
| `OwnSetup` | | | the app sets the first password on its own first-run page (`app.SetFirstPassword`); `POST /api/setup/password` is not served |

Keep `secret.key` out of the backups of the database, or set `_SECRET_KEY` from a secret store: with both, a stolen
backup opens the tunnel's token.

## The tunnel

Settings, or the shell's page `/z-dash/server/`, set it up in three steps: create an API token on Cloudflare (the
link fills in the permissions), pick the domain and the subdomain, list who may sign in. The server creates the
tunnel (`<slug>-<hostname>`), the DNS record (marked "Managed by <Name>"), an allow policy for the addresses and the
Access application, enables the one-time PIN login, runs `cloudflared` and checks from outside that the address asks
for a login (and that each bypass path reaches the app). A name that is taken on Cloudflare stops the setup until
the person agrees to replace it. Running the setup again repairs what is missing; the state survives restarts.

Through the tunnel, Cloudflare Access signs the person in; the password is only for the local listener, which
keeps working whatever happens to the tunnel. The server checks the Access token (`Cf-Access-Jwt-Assertion`, RS256
only, the application's audience, the team's issuer, the expiry) and the address against its own list on every
request, so a person taken off the list is out at once.

## The shell

The shell is plain ES modules on Z-Dash, served at `/z-dash/server/` from `server/zdash/shell/`. An app's
`index.html` loads Z-Dash from the server, holds its own layout with the documented markup, hidden until someone is
signed in, and starts the shell:

```html
<link rel="stylesheet" href="/z-dash/fonts/fonts.css">
<link rel="stylesheet" href="/z-dash/ds.min.css">
<link rel="stylesheet" href="/z-dash/themes/dark.css" media="(prefers-color-scheme: dark)">
<script src="/z-dash/ds.min.js" defer></script>
<script type="module" src="app.js"></script>
...
<div class="ds-app ds-app--drawer" data-ds-shell="inventory" hidden>
  ... <span class="ds-brand__name" data-zs-name></span> ... <div class="ds-account ds-account--capsule" data-zs-account></div> ...
</div>
<div class="ds-toasts"></div>
```

```js
import { start, on } from '/z-dash/server/shell.js';
import { get } from '/z-dash/server/api.js';

await start();          // the sign-in or first-password card until someone is signed in
on('devices', load);    // the server's Notify("devices"), from any browser
load();
```

| Module | Exports |
|---|---|
| `shell.js` | `start({ onReady })` (the session once someone is signed in; fills `[data-zs-name]`, `[data-zs-version]` and the `.ds-account[data-zs-account]` capsule with its sign-out, shows `body > .ds-app`, attaches the ripple and the tooltips), `on(topic, fn)` (also after a reconnect or a new sign-in; returns a stop function), `current()`, `signOut()` |
| `api.js` | `get`, `post`, `put`, `del`, `request` (with the CSRF header; an `ApiError` carries the server's sentence and its `fields`), `whenSignedOut(fn)`, `live(onTopics, onStatus)`, `isOffline`, `errorMessage` |
| `ui.js` | `html` (escaping), `raw`, `esc`, `icon`, `morph` (`DS.dom.morphHtml`), `faces`, `busy`, `toast`, `confirm`, `alertHtml`, `setFieldError`, `fieldErrors`, `passwordField`, `sentence` |
| `tunnel.js` | `mountTunnel(host, { level, log, onChange })`: the tunnel's settings in a card of the app's own settings page (with `/z-dash/server/shell.css`) |
| `password.js` | `mountPassword(host, session)`: the password form |

Its page `/z-dash/server/` is the server's settings (tunnel and password) for apps that have none of their own; link
it from the drawer. [`server/example/`](../server/example/main.go) uses all of the above.

## Checking a project

The module carries a full copy of Z-Dash's tools, so `tools/check-project.mjs` runs on an app as on a vendored
copy:

```sh
go mod download github.com/saschazesiger/Z-Dash/server
ZD="$(go list -m -f '{{.Dir}}' github.com/saschazesiger/Z-Dash/server)/zdash/dist"
rm -rf web/.z-dash && cp -R "$ZD" web/.z-dash && chmod -R u+w web/.z-dash
node web/.z-dash/tools/check-project.mjs --config web/ds-check.json
```

with `"vendor": ".z-dash"` in `web/ds-check.json` and `web/.z-dash/` in `.gitignore`. The copy is verified against
its `SHA256SUMS` like any other; the Go checksum database already guarantees the module itself.

## Updating

`go get github.com/saschazesiger/Z-Dash/server@main` takes the latest `main` (server and Z-Dash together), like the
nightly copy of `dist/` does for other projects. `server/templates/` holds what an app
copies:

| File | |
|---|---|
| [`update-z-dash-server.yml`](../server/templates/update-z-dash-server.yml) | the nightly update: `go get …@main`, the app's checks and tests, commit, then the build workflow |
| [`release.yml`](../server/templates/release.yml) | build the image on every push to `main` and push it to the GitHub Container Registry |
| [`Dockerfile`](../server/templates/Dockerfile) | a static binary on Alpine, with a pinned and checksummed `cloudflared`, as a user without rights |

## Moving an existing app

An app with a database of its own passes it as `Config.KV` (`Get`, `Set`, `SetIfMissing`, `Delete` on a key-value
table; `Get` answers `store.ErrNotFound` for a missing key) and a `Config.Sealer`. The server keeps its state under
the keys `auth.password` (an Argon2id hash as JSON), `auth.sessions` and `cloudflare:*`; an app whose password and
sessions sit under the same keys in the same format keeps them. The session cookie is `<slug>_session`
(`my-app` → `my_app_session`).

An app whose old password is in another format gives `Config.LegacyPassword` (`Has`, `Verify`, `Drop`): it keeps
signing in, the first sign-in that matches stores it in the server's format, whatever its length, and drops the old
one; while it exists nobody can set a first password. Sessions of an earlier version carry over when the app writes
them into `auth.sessions` before `server.New`: a JSON object from the hex SHA-256 of each cookie value to
`{"expires": <Unix ms>}`, and the cookie keeps its name. An app with a first-run page of its own (one that asks for
more than the password) calls `app.SetFirstPassword` and `app.StartSession`; a WebSocket or stream of its own checks
`app.StillSignedIn(r)` now and then and ends in `Config.OnSignOut`.
