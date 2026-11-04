package main

import (
	"strings"
	"time"
)

// Journal (AUTH-DESIGN §4.5, step 5e-1): one schema for every source, so that
// the jti links a token's issue, its use and its refusal. Never a PIN, a
// passphrase, a code, a whole token, a key, a challenge nor a client's IP.

// Entry is a journal line.
type Entry struct {
	At      int64  `json:"at"`                // unix seconds, auth's clock
	Source  string `json:"source"`            // auth; the others from step 5e-3
	Type    string `json:"type"`              // session.open, token.service…
	Subject string `json:"subject,omitempty"` // who: profil:<id>, term:<id>, app:<id>, kid
	Object  string `json:"object,omitempty"`  // on what: a Thing, a terminal, a session
	Result  string `json:"result"`            // ok, denied
	Reason  string `json:"reason,omitempty"`  // why denied: a short code
	Jti     string `json:"jti,omitempty"`
	Detail  string `json:"detail,omitempty"`
	Keep    int    `json:"keep"` // days kept (§4.5): keepLong or keepShort
}

// Retention classes (§4.5), in days: confirmed commands, administration and
// PIN failures a year; sessions and comfort a month.
const (
	keepLong  = 365
	keepShort = 30
)

// shortKept are the comfort types; every other one is administration.
var shortKept = []string{"session.", "token.service", "proof.", "revocation.ack", "auth.start",
	"thing.alert", "thing.td", "enroll.request", "enroll.cancelled", "document."}

func keepOf(typ string) int {
	for _, p := range shortKept {
		if strings.HasPrefix(typ, p) {
			return keepShort
		}
	}
	return keepLong
}

// record adds a journal line, the time, source, result and class filled in
// when empty. Not a change of the state: no backup asked.
func (s *Store) record(e Entry) {
	if e.At == 0 {
		e.At = s.now().Unix()
	}
	if e.Source == "" {
		e.Source = "auth"
	}
	if e.Result == "" {
		e.Result = "ok"
	}
	if e.Keep == 0 {
		e.Keep = keepOf(e.Type)
	}
	s.db.Exec(`INSERT INTO journal (at, source, event, subject, object, result, reason, jti, detail, keep)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.At, e.Source, e.Type, e.Subject, e.Object, e.Result, e.Reason, e.Jti, e.Detail, e.Keep)
}

// log adds a journal line after a change of the state, and asks for a
// backup.
func (s *Store) log(event, detail string) {
	s.record(Entry{Type: event, Detail: detail})
	s.changed()
}

// Journal returns the lines from since (unix seconds), oldest first.
func (s *Store) Journal(since int64) ([]Entry, error) {
	rows, err := s.db.Query(`SELECT at, source, event, subject, object, result, reason, jti, detail, keep
		FROM journal WHERE at >= ? ORDER BY id`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.At, &e.Source, &e.Type, &e.Subject, &e.Object, &e.Result, &e.Reason, &e.Jti, &e.Detail, &e.Keep); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// purge drops the lines past their class, by whole days: a line goes on
// the day after its last kept day, with every line of its day.
func (s *Store) purge() {
	now := s.now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).Unix()
	s.db.Exec(`DELETE FROM journal WHERE at < ? - keep * 86400`, today)
}

// PurgeJournal purges at start then every day until stop closes.
func (s *Store) PurgeJournal(stop <-chan struct{}) {
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		s.purge()
		select {
		case <-stop:
			return
		case <-t.C:
		}
	}
}

// Started journals a start of auth; a database with profiles and no
// journal comes from a backup (the journal is left out of it): a
// restoration, alerted (§4.5).
func (s *Service) Started() {
	var lines, profiles int
	s.store.db.QueryRow(`SELECT count(*) FROM journal`).Scan(&lines)
	s.store.db.QueryRow(`SELECT count(*) FROM profiles`).Scan(&profiles)
	if lines == 0 && profiles > 0 {
		s.store.record(Entry{Type: "auth.restored", Keep: keepLong})
		s.notify("Restauration d'auth")
	}
	s.store.record(Entry{Type: "auth.start"})
}
