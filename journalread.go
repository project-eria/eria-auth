package main

import (
	"fmt"
	"regexp"
	"time"

	"github.com/project-eria/go-wot/auth"
)

// Reading and erasing the journal (AUTH-DESIGN §4.5, step 5e-6): the admin
// reads it, each reading journaled; whole days are erased by the master's
// validated order, here and in its copy.

const maxReadSpan = 2 * 86400 // a local day spans two UTC days

var sessionID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// ReadJournal returns the lines from `from` to `to` (unix seconds, two days
// at most), or those of one session: its opening, its tokens' uses and
// refusals, its closing.
func (s *Service) ReadJournal(by Caller, from, to int64, session string) ([]Entry, error) {
	var lines []Entry
	var err error
	switch {
	case session != "":
		if !sessionID.MatchString(session) {
			return nil, Invalid("bad session")
		}
		// Prefixes compared exactly: "_" would be a wildcard for LIKE.
		dot, word := session+".", "session "+session+" "
		lines, err = s.store.journalWhere(`jti = ? OR substr(jti, 1, ?) = ? OR substr(detail, 1, ?) = ? OR detail = ?`, 1000,
			session, len(dot), dot, len(word), word, "session "+session)
	case to > from && to-from <= maxReadSpan:
		lines, err = s.store.journalWhere(`at >= ? AND at < ?`, 0, from, to)
	default:
		return nil, Invalid("a period of two days at most")
	}
	if err != nil {
		return nil, err
	}
	what := fmt.Sprintf("%d %d", from, to)
	if session != "" {
		what = "session " + session
	}
	s.store.record(Entry{Type: "journal.read", Subject: by.Sub, Jti: by.Jti, Detail: what, Keep: keepLong})
	if lines == nil {
		lines = []Entry{}
	}
	return lines, nil
}

// EraseJournal erases whole UTC days up to the order's day, signed by the
// master once the admin validated it; never today nor a message replayed.
func (s *Service) EraseJournal(doc auth.Signed) error {
	var e auth.JournalErase
	if err := doc.Open(auth.JournalErasePrefix, s.deploy, &e); err != nil {
		s.store.record(Entry{Type: "document.refused", Subject: sourceMaster, Object: "erase", Result: "denied", Reason: "signature"})
		s.alertOnce("signature:"+sourceMaster, "Signature invalide : "+sourceMaster)
		return ErrDenied
	}
	now := s.now()
	var last int64
	s.store.db.QueryRow(`SELECT value FROM state WHERE key = 'journal_erase'`).Scan(&last)
	if e.At <= last || now.Sub(time.Unix(e.At, 0)).Abs() > 5*time.Minute {
		return ErrDenied
	}
	day, err := time.Parse(time.DateOnly, e.Until)
	end := day.Unix() + 86400
	if err != nil || end > now.Unix()/86400*86400 {
		return Invalid("whole days before today only")
	}
	where := `at < ? AND keep = ?`
	args := []any{end, keepShort}
	if e.All {
		where, args = `at < ?`, []any{end}
	}
	res, err := s.store.db.Exec(`DELETE FROM journal WHERE `+where, args...)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	s.store.db.Exec(`INSERT INTO state (key, value) VALUES ('journal_erase', ?)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value`, e.At)
	s.store.record(Entry{Type: "journal.erased", Subject: sourceMaster, Object: e.Until,
		Detail: fmt.Sprintf("all %t, %d lines", e.All, n), Keep: keepLong})
	return nil
}
