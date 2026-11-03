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
			device       TEXT NOT NULL DEFAULT '', -- told by the app at enrollment: shown, never trusted
			validator    INTEGER NOT NULL DEFAULT 0, -- a phone whose bio key validates the admin's requests
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
		-- Enrollment requests of terminals (§1.2): their keys, waiting for
		-- the admin to type the code they show.
		CREATE TABLE IF NOT EXISTS requests (
			id      TEXT PRIMARY KEY,
			code    TEXT NOT NULL UNIQUE,
			alg     TEXT NOT NULL,
			raw     BLOB NOT NULL,
			bio_alg TEXT NOT NULL DEFAULT '',
			bio_raw BLOB,
			device  TEXT NOT NULL DEFAULT '',
			created INTEGER NOT NULL,
			expires INTEGER NOT NULL
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
			subject TEXT PRIMARY KEY, -- term:<id>, sub:<profile>, sub:app:<id>
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
		-- Things and their requirements (§2.4, §2.5): the last TD's
		-- functions, the capabilities adopted, the rooms, the admin's rules
		-- (state '') and the overrides of each state.
		CREATE TABLE IF NOT EXISTS things (
			id         TEXT PRIMARY KEY,
			title      TEXT NOT NULL DEFAULT '',
			types      TEXT NOT NULL DEFAULT '[]', -- capabilities adopted: the defaults
			seen_types TEXT NOT NULL DEFAULT '[]', -- capabilities of the last TD
			functions  TEXT NOT NULL DEFAULT '[]',
			zones      TEXT NOT NULL DEFAULT '[]',
			adopted    INTEGER NOT NULL DEFAULT 0,
			seen       INTEGER NOT NULL DEFAULT 0,
			version    INTEGER NOT NULL DEFAULT 0 -- of its table, time in ms
		);
		CREATE TABLE IF NOT EXISTS rules (
			thing   TEXT NOT NULL REFERENCES things(id) ON DELETE CASCADE,
			state   TEXT NOT NULL DEFAULT '',
			key     TEXT NOT NULL,
			l0      INTEGER NOT NULL, -- local, 0 = None
			l1      INTEGER NOT NULL, -- remote
			l2      INTEGER NOT NULL, -- outside
			confirm TEXT NOT NULL DEFAULT '',
			PRIMARY KEY (thing, state, key)
		);
		-- App keys (§1.3): registered by the master, kid '' once retired. The
		-- id is the app's identity (sub app:<id>), kept across its keys.
		CREATE TABLE IF NOT EXISTS apps (
			id         TEXT PRIMARY KEY,
			name       TEXT NOT NULL UNIQUE, -- label: the app's name in the deployment
			node       TEXT NOT NULL DEFAULT '',
			kid        TEXT NOT NULL DEFAULT '',
			raw        BLOB, -- Ed25519 public key
			version    INTEGER NOT NULL, -- of the master's last message, ms
			registered INTEGER NOT NULL,
			last_token INTEGER NOT NULL DEFAULT 0
		);
		CREATE UNIQUE INDEX IF NOT EXISTS apps_kid ON apps (kid) WHERE kid != '';
		CREATE TABLE IF NOT EXISTS active_states (
			state TEXT PRIMARY KEY
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
	// Databases made before the column: the error once it exists is expected.
	db.Exec(`ALTER TABLE terminals ADD COLUMN device TEXT NOT NULL DEFAULT ''`)
	db.Exec(`ALTER TABLE terminals ADD COLUMN validator INTEGER NOT NULL DEFAULT 0`)
	db.Exec(`ALTER TABLE keys ADD COLUMN since INTEGER NOT NULL DEFAULT 0`)  // a pending bio key: when it came
	db.Exec(`ALTER TABLE things ADD COLUMN app TEXT NOT NULL DEFAULT ''`)    // id of the app that signs its TD (step 3d)
	db.Exec(`ALTER TABLE apps ADD COLUMN grants TEXT NOT NULL DEFAULT '[]'`) // accepted by the admin (step 4)
	st := &Store{db: db, now: time.Now, changed: func() {}}
	if err := st.migrateConfig(); err != nil {
		return nil, err
	}
	return st, nil
}

// log adds a journal line after a change of the state, and asks for a
// backup. Never a PIN, a passphrase or a code.
func (s *Store) log(event, detail string) {
	s.db.Exec(`INSERT INTO journal (at, event, detail) VALUES (?, ?, ?)`, s.now().Unix(), event, detail)
	s.changed()
}
