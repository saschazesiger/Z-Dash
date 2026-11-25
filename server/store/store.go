// Package store is the SQLite database of an app: one file in the data
// directory, a key-value table the server keeps its own state in (the
// password, the sessions, the tunnel), and the app's own tables, created
// and changed by numbered migrations.
//
// It uses modernc.org/sqlite (pure Go, no cgo), so the binary builds with
// CGO_ENABLED=0 for every platform.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// ErrNotFound is returned by Get for a key that is not there.
var ErrNotFound = errors.New("store: not found")

// Migration changes the schema by one step. Migrations run in order, each
// in a transaction of its own; the number of those that ran is the
// database's user_version, so each runs once.
type Migration func(tx *sql.Tx) error

// base are the server's own migrations; the app's follow them, so its first
// migration is number len(base)+1 in user_version. Never change or reorder
// one: add a new one.
var base = []Migration{
	func(tx *sql.Tx) error {
		_, err := tx.Exec(`CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value BLOB NOT NULL)`)
		return err
	},
}

// Store is the open database.
type Store struct {
	db *sql.DB
}

// Open opens (or creates) the database at path and runs the migrations
// that have not run yet. A database written by a newer version of the app
// (more migrations than it knows) is refused rather than misread.
func Open(path string, migrations ...Migration) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(FULL)")
	q.Add("_pragma", "busy_timeout(10000)")
	q.Add("_pragma", "foreign_keys(ON)")
	db, err := sql.Open("sqlite", "file:"+path+"?"+q.Encode())
	if err != nil {
		return nil, err
	}
	// One connection: SQLite has one writer anyway, and this makes every
	// transaction see the one before it without busy retries.
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(append(append([]Migration{}, base...), migrations...)); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate(all []Migration) error {
	var have int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&have); err != nil {
		return fmt.Errorf("store: read the schema version: %w", err)
	}
	if have > len(all) {
		return fmt.Errorf("store: the database has schema version %d, but this version of the app knows only %d; "+
			"run the newer version again, or restore a backup", have, len(all))
	}
	for i := have; i < len(all); i++ {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if err := all[i](tx); err != nil {
			tx.Rollback()
			return fmt.Errorf("store: migration %d: %w", i+1, err)
		}
		// PRAGMA takes no parameters; i+1 is a number we made.
		if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, i+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// DB is the database for the app's own tables.
func (s *Store) DB() *sql.DB { return s.db }

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Tx runs fn in a transaction, committed when fn returns nil.
func (s *Store) Tx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// Get reads a key; ErrNotFound when it is not there.
func (s *Store) Get(key string) ([]byte, error) {
	var v []byte
	err := s.db.QueryRow(`SELECT value FROM kv WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return v, err
}

// Set writes a key.
func (s *Store) Set(key string, value []byte) error {
	_, err := s.db.Exec(`INSERT INTO kv(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// SetIfMissing writes a key only when it is not there, atomically, and
// reports whether it wrote.
func (s *Store) SetIfMissing(key string, value []byte) (bool, error) {
	res, err := s.db.Exec(`INSERT INTO kv(key, value) VALUES(?, ?) ON CONFLICT(key) DO NOTHING`, key, value)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// Delete removes a key; a missing key is no error.
func (s *Store) Delete(key string) error {
	_, err := s.db.Exec(`DELETE FROM kv WHERE key = ?`, key)
	return err
}
