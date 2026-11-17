package main

import (
	"fmt"
	"slices"
	"strings"
	"time"

	eria "github.com/project-eria/eria-core"
)

// Daily summary (AUTH-DESIGN §4.5, step 5e-5): yesterday's UTC day, sent by
// ntfy each morning even when empty: it stands for a canary (F074), its
// absence is the alert. Things by their id, terminals and people by their
// record's name, never text from a Thing.
//
// ponytail: the expiry of the iOS profiles is not known to auth: left out.

const (
	summaryHour   = 6 // UTC: sent from 6:00, 7:00 or 8:00 in France
	soonExpiry    = 7 * 24 * time.Hour
	certSoon      = 30 * 24 * time.Hour
	mutedFixed    = 24 * time.Hour // a fixed screen renews its token every 6 h
	mutedPortable = 7 * 24 * time.Hour
)

// SendSummaries sends the summary of each day once, checked every minute
// until stop closes.
func (s *Service) SendSummaries(stop <-chan struct{}) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		s.sendSummary()
		select {
		case <-stop:
			return
		case <-t.C:
		}
	}
}

// sendSummary sends yesterday's summary once it is time and not yet sent.
func (s *Service) sendSummary() {
	now := s.now().UTC()
	if now.Hour() < summaryHour {
		return
	}
	day := now.Truncate(24 * time.Hour).AddDate(0, 0, -1)
	var sent int64
	s.store.db.QueryRow(`SELECT value FROM state WHERE key = 'summary'`).Scan(&sent)
	if sent >= day.Unix() {
		return
	}
	text, err := s.Summary(day.Format(time.DateOnly))
	if err != nil {
		return // again in a minute
	}
	s.store.db.Exec(`INSERT INTO state (key, value) VALUES ('summary', ?)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value`, day.Unix())
	s.store.record(Entry{Type: "summary.sent", Object: day.Format(time.DateOnly)})
	s.notify(text)
}

// Summary is the text of a UTC day's summary.
func (s *Service) Summary(day string) (string, error) {
	d, err := time.Parse(time.DateOnly, day)
	if err != nil {
		return "", err
	}
	from, to := d.Unix(), d.Unix()+86400
	lines, err := s.store.journalWhere(`at >= ? AND at < ?`, 0, from, to)
	if err != nil {
		return "", err
	}
	things, err := s.Things()
	if err != nil {
		return "", err
	}
	known := map[string]bool{}
	for _, t := range things {
		known[t.ID] = true
	}
	names := s.profileNames()
	var b strings.Builder
	fmt.Fprintf(&b, "Résumé quotidien du %s (UTC)\n", day)

	// Refusals, per person and per Thing.
	byPerson, byThing := counter{}, counter{}
	refused := 0
	for _, l := range lines {
		if l.Result != "denied" {
			continue
		}
		refused++
		if name, ok := names[l.Subject]; ok {
			byPerson.add(name)
		}
		if (l.Type == "guard.denied" || l.Type == "relay.denied") && known[l.Object] {
			byThing.add(l.Object)
		}
	}
	fmt.Fprintf(&b, "Refus : %d\n", refused)
	byPerson.write(&b, "par personne")
	byThing.write(&b, "par appareil")

	// Confirmed commands, from outside, and the first use of a grant.
	confirmed, outside := 0, 0
	var firsts []string
	for _, l := range lines {
		if l.Type != "guard.confirmable" {
			continue
		}
		confirmed++
		fields := strings.Fields(l.Detail)
		if slices.Contains(fields, "outside") {
			outside++
		}
		for _, f := range fields {
			grant, ok := strings.CutPrefix(f, "grant:")
			if ok && s.firstGrantUse(l, f, from) {
				firsts = append(firsts, fmt.Sprintf("%s : %s sur %s", cmpName(names, l.Subject), grant, l.Object))
			}
		}
	}
	fmt.Fprintf(&b, "Commandes confirmables : %d (dont %d hors de la maison)\n", confirmed, outside)
	list(&b, "Premier usage d'un accès accordé", "aucun", firsts)

	// Unclassified functions of the adopted Things.
	var unclassified []string
	for _, t := range things {
		if !t.Adopted {
			continue
		}
		n := 0
		for _, f := range t.Functions {
			// A function of a model not set is closed, not classified.
			if r, ok := t.Defaults[f]; !ok || r.Levels == [3]int{} {
				if _, ok := t.Rules[f]; !ok {
					n++
				}
			}
		}
		if n > 0 {
			unclassified = append(unclassified, fmt.Sprintf("%s : %d", t.ID, n))
		}
	}
	list(&b, "Fonctions non classées", "aucune", unclassified)

	list(&b, "Écrans muets", "aucun", s.mutedTerminals())
	list(&b, "Expirations proches", "aucune", s.expiries())

	// Versions, and the digests of the day (the coordinator's copy compares them).
	var revocation int64
	s.store.db.QueryRow(`SELECT value FROM state WHERE key = 'revocations'`).Scan(&revocation)
	s.mu.Lock()
	lagging := 0
	for _, a := range s.acks {
		if !a.lagging.IsZero() {
			lagging++
		}
	}
	s.mu.Unlock()
	fmt.Fprintf(&b, "Versions : auth %s, révocations %d, appareils en retard %d\n", eria.AppVersion, revocation, lagging)
	digests, err := s.store.dayDigests(day)
	if err != nil {
		return "", err
	}
	for _, keep := range []string{"30", "365"} {
		fmt.Fprintf(&b, "Empreinte %s j : %s\n", keep, cmpOr(digests[keep], "aucune ligne"))
	}
	return strings.TrimSpace(b.String()), nil
}

// firstGrantUse tells whether no confirmable command used this grant for
// this subject before the day.
func (s *Service) firstGrantUse(l Entry, grant string, before int64) bool {
	var n int
	s.store.db.QueryRow(`SELECT count(*) FROM journal WHERE event = 'guard.confirmable' AND subject = ? AND at < ?
		AND (' ' || detail || ' ') LIKE ?`, l.Subject, before, "% "+grant+" %").Scan(&n)
	return n == 0
}

// profileNames maps profil:<id> to the profile's name.
func (s *Service) profileNames() map[string]string {
	out := map[string]string{}
	rows, err := s.store.db.Query(`SELECT id, name FROM profiles`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var name string
		rows.Scan(&id, &name)
		out[fmt.Sprintf("profil:%d", id)] = name
	}
	return out
}

// mutedTerminals are the active terminals silent for too long.
func (s *Service) mutedTerminals() []string {
	now := s.now().Unix()
	rows, err := s.store.db.Query(`SELECT name FROM terminals WHERE status = 'active'
		AND last_seen < CASE type WHEN 'fixed' THEN ? ELSE ? END ORDER BY name`,
		now-int64(mutedFixed.Seconds()), now-int64(mutedPortable.Seconds()))
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		rows.Scan(&name)
		out = append(out, name)
	}
	return out
}

// expiries are the grants ending within a week, the enrollments and new
// Face ID keys waiting for the admin, the iPhones' profiles and auth's
// certificate.
func (s *Service) expiries() []string {
	now := s.now()
	var out []string
	rows, err := s.store.db.Query(`SELECT p.name, g.grant, g.expires FROM grants g JOIN profiles p ON p.id = g.profile
		WHERE g.expires > ? AND g.expires <= ? ORDER BY g.expires`, now.Unix(), now.Add(soonExpiry).Unix())
	if err == nil {
		for rows.Next() {
			var name, grant string
			var expires int64
			rows.Scan(&name, &grant, &expires)
			out = append(out, fmt.Sprintf("accès %s de %s le %s", grant, name, time.Unix(expires, 0).UTC().Format(time.DateOnly)))
		}
		rows.Close()
	}
	var requests, keys int
	s.store.db.QueryRow(`SELECT count(*) FROM requests WHERE expires > ?`, now.Unix()).Scan(&requests)
	s.store.db.QueryRow(`SELECT count(*) FROM keys WHERE status = 'pending'`).Scan(&keys)
	if requests > 0 {
		out = append(out, fmt.Sprintf("enrôlements en attente : %d", requests))
	}
	if keys > 0 {
		out = append(out, fmt.Sprintf("nouvelles clés Face ID en attente : %d", keys))
	}
	rows, err = s.store.db.Query(`SELECT name, profile_expires FROM terminals
		WHERE status = 'active' AND profile_expires > 0 AND profile_expires <= ? ORDER BY profile_expires`, now.Add(certSoon).Unix())
	if err == nil {
		for rows.Next() {
			var name string
			var expires int64
			rows.Scan(&name, &expires)
			out = append(out, fmt.Sprintf("profil iOS de %s le %s (réinstaller l'app)", name, time.Unix(expires, 0).UTC().Format(time.DateOnly)))
		}
		rows.Close()
	}
	if !s.certExpiry.IsZero() && s.certExpiry.Sub(now) < certSoon {
		out = append(out, "certificat d'auth le "+s.certExpiry.UTC().Format(time.DateOnly))
	}
	return out
}

// counter counts names, written by decreasing count.
type counter map[string]int

func (c counter) add(name string) { c[name]++ }

func (c counter) write(b *strings.Builder, label string) {
	if len(c) == 0 {
		return
	}
	keys := make([]string, 0, len(c))
	for k := range c {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(x, y string) int {
		if c[x] != c[y] {
			return c[y] - c[x]
		}
		return strings.Compare(x, y)
	})
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s %d", k, c[k])
	}
	fmt.Fprintf(b, "- %s : %s\n", label, strings.Join(parts, ", "))
}

// list writes label and its items, none without.
func list(b *strings.Builder, label, none string, items []string) {
	if len(items) == 0 {
		fmt.Fprintf(b, "%s : %s\n", label, none)
		return
	}
	fmt.Fprintf(b, "%s :\n", label)
	for _, it := range items {
		fmt.Fprintf(b, "- %s\n", it)
	}
}

func cmpName(names map[string]string, subject string) string {
	return cmpOr(names[subject], subject)
}

func cmpOr(s, or string) string {
	if s == "" {
		return or
	}
	return s
}
