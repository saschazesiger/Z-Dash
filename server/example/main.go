// Command example is the smallest app on the server: a list of devices
// in the database, its page on the shell, and the tunnel from its settings.
//
//	go run ./example                       # http://localhost:8080
//	EXAMPLE_DATA=/tmp/example go run ./example
//
// Everything else (sign-in, first password, the tunnel, Z-Dash itself)
// comes from the server.
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
	"strings"
	"syscall"

	"github.com/saschazesiger/Z-Dash/server"
	"github.com/saschazesiger/Z-Dash/server/store"
)

//go:embed web
var web embed.FS

var version = "dev"

func main() {
	files, _ := fs.Sub(web, "web")
	app, err := server.New(server.Config{
		Name:    "Example",
		Version: version,
		Assets:  files,
		Migrations: []store.Migration{
			func(tx *sql.Tx) error {
				_, err := tx.Exec(`CREATE TABLE devices (id INTEGER PRIMARY KEY, name TEXT NOT NULL, room TEXT NOT NULL DEFAULT '')`)
				return err
			},
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	db := app.Store().DB()

	app.HandleFunc("GET /api/devices", func(w http.ResponseWriter, r *http.Request) {
		rows, err := db.QueryContext(r.Context(), `SELECT id, name, room FROM devices ORDER BY name`)
		if err != nil {
			server.WriteError(w, http.StatusInternalServerError, "The devices could not be read.")
			return
		}
		defer rows.Close()
		type device struct {
			ID   int64  `json:"id"`
			Name string `json:"name"`
			Room string `json:"room"`
		}
		list := []device{}
		for rows.Next() {
			var d device
			if rows.Scan(&d.ID, &d.Name, &d.Room) == nil {
				list = append(list, d)
			}
		}
		server.WriteJSON(w, http.StatusOK, list)
	})
	app.HandleFunc("POST /api/devices", func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Name, Room string }
		if !server.Decode(w, r, &body) {
			return
		}
		if body.Name = strings.TrimSpace(body.Name); body.Name == "" {
			server.WriteFieldError(w, "name", "Enter a name.")
			return
		}
		if _, err := db.ExecContext(r.Context(), `INSERT INTO devices(name, room) VALUES(?, ?)`, body.Name, strings.TrimSpace(body.Room)); err != nil {
			server.WriteError(w, http.StatusInternalServerError, "The device could not be saved.")
			return
		}
		app.Notify("devices")
		server.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
	app.HandleFunc("DELETE /api/devices/{id}", func(w http.ResponseWriter, r *http.Request) {
		if _, err := db.ExecContext(r.Context(), `DELETE FROM devices WHERE id = ?`, r.PathValue("id")); err != nil {
			server.WriteError(w, http.StatusInternalServerError, "The device could not be removed.")
			return
		}
		app.Notify("devices")
		server.WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := app.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
