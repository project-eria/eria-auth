package main

import (
	"database/sql"
	"time"

	_ "modernc.org/sqlite"
)

// Store is the state of auth (AUTH-DESIGN §4.2): profiles, terminals and
// their keys, sessions, validation requests, revocations. The journal lives
// in the same file but is not part of the state.
type Store struct {
	db      *sql.DB
	now     func() time.Time // overridable by tests
	changed func()           // called after each change of the state (backup)
}

func OpenStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // ponytail: one writer at a time is plenty for a household
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS profiles (
			id         INTEGER PRIMARY KEY,
			name       TEXT NOT NULL UNIQUE,
			level      INTEGER NOT NULL CHECK (level BETWEEN 0 AND 9),
			secret     TEXT NOT NULL DEFAULT '' -- PIN (levels 1-9) or passphrase (level 0), argon2id
		);
		CREATE TABLE IF NOT EXISTS terminals (
			id           TEXT PRIMARY KEY,
			name         TEXT NOT NULL UNIQUE,
			type         TEXT NOT NULL CHECK (type IN ('fixed', 'phone', 'computer')),
			zone         TEXT NOT NULL DEFAULT '',
			floor        INTEGER NOT NULL DEFAULT 1 CHECK (floor BETWEEN 1 AND 9),
			room_only    INTEGER NOT NULL DEFAULT 0,
			owner        INTEGER REFERENCES profiles(id) ON DELETE SET NULL,
			status       TEXT NOT NULL CHECK (status IN ('new', 'pending', 'active', 'blocked')),
			enrolled     INTEGER NOT NULL DEFAULT 0,
			last_seen    INTEGER NOT NULL DEFAULT 0,
			pin_failures INTEGER NOT NULL DEFAULT 0,
			pin_until    INTEGER NOT NULL DEFAULT 0, -- no PIN tried before this time
			pin_last     INTEGER NOT NULL DEFAULT 0  -- last failure
		);
		-- Typed key records (§1.1): identity and bio keys of a terminal, and
		-- the admin's validator keys (YubiKey, phone).
		CREATE TABLE IF NOT EXISTS keys (
			kid      TEXT PRIMARY KEY,
			role     TEXT NOT NULL CHECK (role IN ('identity', 'bio', 'validator')),
			alg      TEXT NOT NULL,
			raw      BLOB NOT NULL,
			terminal TEXT REFERENCES terminals(id) ON DELETE CASCADE,
			name     TEXT NOT NULL DEFAULT '',
			status   TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('pending', 'active'))
		);
		CREATE TABLE IF NOT EXISTS enrollments (
			terminal TEXT PRIMARY KEY REFERENCES terminals(id) ON DELETE CASCADE,
			secret   TEXT NOT NULL UNIQUE, -- sha256 of the QR secret
			code     TEXT NOT NULL UNIQUE, -- sha256 of the short code
			expires  INTEGER NOT NULL,
			attempts INTEGER NOT NULL DEFAULT 0
		);
		CREATE TABLE IF NOT EXISTS sessions (
			id       TEXT PRIMARY KEY,
			terminal TEXT NOT NULL REFERENCES terminals(id) ON DELETE CASCADE,
			profile  INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
			admin    INTEGER NOT NULL DEFAULT 0,
			opened   INTEGER NOT NULL,
			gesture  INTEGER NOT NULL -- last gesture
		);
		CREATE TABLE IF NOT EXISTS admin_requests (
			id        TEXT PRIMARY KEY,
			terminal  TEXT NOT NULL REFERENCES terminals(id) ON DELETE CASCADE,
			profile   INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
			expires   INTEGER NOT NULL,
			validated TEXT NOT NULL DEFAULT '' -- kid of the validator key
		);
		CREATE TABLE IF NOT EXISTS revocations (
			subject TEXT PRIMARY KEY, -- term:<id>, sub:<profile>, service:<kid>
			before  INTEGER NOT NULL  -- tokens issued before this time fall
		);
		CREATE TABLE IF NOT EXISTS state (
			key   TEXT PRIMARY KEY,
			value INTEGER NOT NULL
		);
		CREATE TABLE IF NOT EXISTS bootstrap (
			code    TEXT PRIMARY KEY, -- sha256 of the one-time code
			expires INTEGER NOT NULL
		);
		CREATE TABLE IF NOT EXISTS journal (
			id     INTEGER PRIMARY KEY,
			at     INTEGER NOT NULL,
			event  TEXT NOT NULL,
			detail TEXT NOT NULL DEFAULT ''
		);`)
	if err != nil {
		return nil, err
	}
	return &Store{db: db, now: time.Now, changed: func() {}}, nil
}

// log adds a journal line after a change of the state, and asks for a
// backup. Never a PIN, a passphrase or a code.
func (s *Store) log(event, detail string) {
	s.db.Exec(`INSERT INTO journal (at, event, detail) VALUES (?, ?, ?)`, s.now().Unix(), event, detail)
	s.changed()
}
