package main

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/project-eria/go-wot/auth"
)

// Grants of the people (AUTH-DESIGN §2.6, step 4c): given by the admin to a
// profile, carried by its person tokens. A grant raises its holder to level
// 1 on what it covers, never past None. One on a confirmable command expires
// after grantMaxAge; removing one makes the profile's tokens fall.

// grantMaxAge bounds a person's grant on a confirmable command (« quelques
// mois »): seen again by the admin at least that often.
const grantMaxAge = 90 * 24 * time.Hour

// Grant is a person's grant as the admin screens show it.
type Grant struct {
	Grant       string `json:"grant"`
	Expires     int64  `json:"expires"` // unix, 0: never
	Added       int64  `json:"added"`
	Confirmable bool   `json:"confirmable"` // covers a confirmable command today
}

// ProfileGrants lists a profile's grants, expired ones included.
func (s *Service) ProfileGrants(id int64) ([]Grant, error) {
	if _, _, err := s.profile(id); err != nil {
		return nil, err
	}
	rows, err := s.store.db.Query(`SELECT grant, expires, added FROM grants WHERE profile = ? ORDER BY grant`, id)
	if err != nil {
		return nil, err
	}
	list := []Grant{}
	for rows.Next() {
		var g Grant
		rows.Scan(&g.Grant, &g.Expires, &g.Added)
		list = append(list, g)
	}
	rows.Close() // one connection: read the tables after
	for i := range list {
		list[i].Confirmable = s.grantsConfirmable([]string{list[i].Grant})
	}
	return list, rows.Err()
}

// AddGrant gives a profile a grant, or renews it. expires 0 is never, except
// on a confirmable command: grantMaxAge at most, the default there.
func (s *Service) AddGrant(id int64, grant string, expires int64) (Grant, error) {
	p, _, err := s.profile(id)
	if err != nil {
		return Grant{}, err
	}
	if p.Level == 0 {
		return Grant{}, Invalid("level 0 needs no grant")
	}
	if auth.ValidGrants([]string{grant}) != nil {
		return Grant{}, Invalid("grant: <thing|room>:<selector>:<read|write|invoke|*>")
	}
	now := s.now()
	g := Grant{Grant: grant, Expires: expires, Added: now.Unix(), Confirmable: s.grantsConfirmable([]string{grant})}
	if g.Confirmable && (g.Expires == 0 || g.Expires > now.Add(grantMaxAge).Unix()) {
		g.Expires = now.Add(grantMaxAge).Unix()
	}
	if g.Expires != 0 && g.Expires <= now.Unix() {
		return Grant{}, Invalid("expires in the past")
	}
	var n int
	s.store.db.QueryRow(`SELECT count(*) FROM grants WHERE profile = ? AND grant != ?`, id, grant).Scan(&n)
	if n >= auth.MaxGrants {
		return Grant{}, Invalid(fmt.Sprintf("%d grants at most", auth.MaxGrants))
	}
	if _, err := s.store.db.Exec(`INSERT INTO grants (profile, grant, expires, added) VALUES (?, ?, ?, ?)
		ON CONFLICT (profile, grant) DO UPDATE SET expires = excluded.expires, added = excluded.added`,
		id, grant, g.Expires, g.Added); err != nil {
		return Grant{}, err
	}
	s.store.log("grant.add", fmt.Sprintf("profile %d: %s until %d", id, grant, g.Expires))
	return g, nil
}

// RemoveGrant takes a grant back: the profile's tokens fall (dated
// revocation, §2.10), the next one comes without it.
func (s *Service) RemoveGrant(id int64, grant string) error {
	res, err := s.store.db.Exec(`DELETE FROM grants WHERE profile = ? AND grant = ?`, id, grant)
	if n, _ := res.RowsAffected(); err != nil || n == 0 {
		return ErrNotFound
	}
	s.revoke(fmt.Sprintf("sub:profil:%d", id))
	s.store.log("grant.remove", fmt.Sprintf("profile %d: %s", id, grant))
	return nil
}

// personGrants are the grants a person token carries: none on a terminal
// whose floor is above 1 (§2.5), the expired ones left out.
func (s *Service) personGrants(profile int64, t Terminal) []string {
	if t.Floor > 1 {
		return nil
	}
	rows, err := s.store.db.Query(`SELECT grant FROM grants WHERE profile = ? AND (expires = 0 OR expires > ?) ORDER BY grant`,
		profile, s.now().Unix())
	if err != nil {
		return nil
	}
	defer rows.Close()
	var grants []string
	for rows.Next() {
		var g string
		rows.Scan(&g)
		grants = append(grants, g)
	}
	return grants
}

// roomGranted tells whether a grant of a person or an app covers the room:
// a Thing entering it falls in that wildcard, the admin is alerted (§2.6).
func (s *Service) roomGranted(zone string) bool {
	prefix := "room:" + zone + ":"
	var n int
	s.store.db.QueryRow(`SELECT count(*) FROM grants WHERE substr(grant, 1, ?) = ?`, len(prefix), prefix).Scan(&n)
	if n > 0 {
		return true
	}
	rows, err := s.store.db.Query(`SELECT grants FROM apps WHERE kid != ''`)
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		rows.Scan(&raw)
		if strings.Contains(raw, `"`+prefix) {
			return true
		}
	}
	return false
}

// alertRooms alerts once when a Thing enters rooms some grant covers.
func (s *Service) alertRooms(id string, before, after []string) {
	for _, z := range after {
		if !slices.Contains(before, z) && s.roomGranted(z) {
			s.notify("Un appareil entre dans une pièce couverte par un droit")
			s.store.log("grant.room", fmt.Sprintf("%s enters %s", id, z))
			return
		}
	}
}
