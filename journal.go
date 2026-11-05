package main

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/project-eria/go-wot/auth"
)

// Journal (AUTH-DESIGN §4.5, step 5e-1): one schema for every source, so that
// the jti links a token's issue, its use and its refusal. Never a PIN, a
// passphrase, a code, a whole token, a key, a challenge nor a client's IP.

// Entry is a journal line.
type Entry struct {
	ID      int64  `json:"id"`                // order in auth's database
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

// shortKept are the comfort types; every other one is administration. The
// Things' lines are comfort, but for the commands of a confirmable function
// and the switches of mode (longKept).
var (
	shortKept = []string{"session.", "relay.", "guard.", "token.service", "proof.", "revocation.ack", "auth.start",
		"thing.alert", "thing.td", "enroll.request", "enroll.cancelled", "document."}
	longKept = []string{"guard.confirmable", "guard.mode"}
)

func keepOf(typ string) int {
	if slices.Contains(longKept, typ) {
		return keepLong
	}
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
	select {
	case s.written <- struct{}{}:
	default:
	}
}

// log adds a journal line after a change of the state, and asks for a
// backup.
func (s *Store) log(event, detail string) {
	s.record(Entry{Type: event, Detail: detail})
	s.changed()
}

// Journal returns the lines from since (unix seconds), oldest first.
func (s *Store) Journal(since int64) ([]Entry, error) {
	return s.journalWhere(`at >= ?`, 0, since)
}

// journalWhere returns at most limit lines (0: all) matching where, in the
// order of the copy: time, then id.
func (s *Store) journalWhere(where string, limit int, args ...any) ([]Entry, error) {
	rows, err := s.db.Query(`SELECT id, at, source, event, subject, object, result, reason, jti, detail, keep
		FROM journal WHERE `+where+` ORDER BY at, id LIMIT ?`, append(args, cmp.Or(limit, -1))...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.ID, &e.At, &e.Source, &e.Type, &e.Subject, &e.Object, &e.Result, &e.Reason, &e.Jti, &e.Detail, &e.Keep); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// purge drops the lines past their class, by whole UTC days (the master's
// copy alike): a line goes on the day after its last kept day, with every
// line of its day.
func (s *Store) purge() {
	today := s.now().Unix() / 86400 * 86400
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

// Sources that hand auth their lines (steps 5e-3, 5e-4); each writes its
// own types only: order.* for the master, relay.* for eria-ui-server,
// guard.* for the Things of an app.
const (
	sourceMaster = "maitre"
	sourceRelay  = "eria-ui-server-" // + interieur or exterieur
	sourceApp    = auth.AppSubject   // + the app's id
)

func prefixOf(source string) string {
	switch {
	case source == sourceMaster:
		return "order."
	case strings.HasPrefix(source, sourceApp):
		return "guard."
	}
	return "relay."
}

// ReceiveJournal takes a batch of lines signed by one of keys for source,
// once: a batch whose seq isn't above the last taken is skipped. The line's
// time is auth's (the copy on the master goes in auth's order), the
// source's kept in the detail when they differ by more than a minute.
func (s *Service) ReceiveJournal(source string, keys []auth.PublicKey, doc auth.Signed) error {
	var b auth.JournalBatch
	if err := doc.Open(auth.JournalPrefix, keys, &b); err != nil {
		s.store.record(Entry{Type: "document.refused", Subject: source, Result: "denied", Reason: "signature"})
		s.alertOnce("signature:"+source, "Signature invalide : "+source)
		return ErrDenied
	}
	prefix := prefixOf(source)
	var last int64
	s.store.db.QueryRow(`SELECT seq FROM journal_sources WHERE source = ?`, source).Scan(&last)
	if b.Seq <= last {
		return nil // sent again, its answer lost
	}
	now := s.now().Unix()
	for _, l := range b.Lines {
		if !strings.HasPrefix(l.Type, prefix) {
			s.store.record(Entry{Type: "document.refused", Subject: source, Result: "denied", Reason: "type"})
			continue
		}
		if l.Result != "denied" {
			l.Result = "ok"
		}
		if d := l.At - now; d > 60 || d < -60 {
			l.Detail = strings.TrimSpace(fmt.Sprintf("%s (at %d)", l.Detail, l.At))
		}
		s.store.record(Entry{Source: source, Type: l.Type, Subject: l.Subject, Object: l.Object,
			Result: l.Result, Reason: l.Reason, Jti: l.Jti, Detail: l.Detail})
		if l.Reason == "reused" { // a confirmation used twice, on a Thing
			s.alertOnce("reused:"+source, "Jeton réutilisé : "+s.thingOf(source, l.Object))
		}
	}
	_, err := s.store.db.Exec(`INSERT INTO journal_sources (source, seq) VALUES (?, ?)
		ON CONFLICT (source) DO UPDATE SET seq = excluded.seq`, source, b.Seq)
	return err
}

// ReceiveThingJournal takes a batch of an app's Things, signed by its key.
func (s *Service) ReceiveThingJournal(signed auth.SignedBy) error {
	id, pub, err := s.appKey(signed.Kid)
	if err != nil {
		return ErrDenied
	}
	return s.ReceiveJournal(sourceApp+id, []auth.PublicKey{pub}, signed.Signed)
}

// thingOf names a Thing in an alert: its id when the source's app owns it,
// else the app's name, never other text from the source (G16).
func (s *Service) thingOf(source, thing string) string {
	app := strings.TrimPrefix(source, sourceApp)
	var owned int
	s.store.db.QueryRow(`SELECT count(*) FROM things WHERE id = ? AND app = ?`, thing, app).Scan(&owned)
	if owned == 0 {
		return s.appName(app)
	}
	return thing
}
