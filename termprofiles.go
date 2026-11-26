package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"slices"
	"strconv"
	"strings"

	"github.com/project-eria/go-wot/auth"
	"github.com/project-eria/go-wot/auth/authz"
)

// Terminal profiles (eria-ui-app PLAN, « Profils de terminal »): a set of
// pages with its start page, drawn in one theme and aspect, for one format of
// screen. The admin gives a terminal a profile of its screen's format; a
// terminal without one shows the default profile. Not to be confused with the
// profiles of the people (table `profiles`).

type TerminalProfile struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Format   string `json:"format"`   // desktop (fits the window) | phone | tablet | wall-tablet | tv; fixed at creation
	Theme    string `json:"theme"`    // "" = Base; fixed at creation
	Aspect   string `json:"aspect"`   // fixed at creation
	HomePage string `json:"homePage"` // one of its pages, "" = its first
	// What its terminals are for (CONTEXT-PAGES-DESIGN §4.1): personal (a person's phone), room,
	// shared (the hall's wall tablet), task; set by the admin, by default from the format.
	Role string `json:"role"`
}

// profileRoles are the roles of a terminal profile.
var profileRoles = []string{"personal", "room", "shared", "task"}

// roleOf is a profile's role: the one set, else the default of its format.
func roleOf(role, format string) string {
	if role != "" {
		return role
	}
	switch format {
	case "phone":
		return "personal"
	case "wall-tablet", "tv":
		return "shared"
	}
	return "room"
}

const defaultProfile = "default"

// profileFormats are the formats of a profile: the screens but the watch.
var profileFormats = []string{"desktop", "phone", "tablet", "wall-tablet", "tv"}

func (s *Store) migrateProfiles() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS terminal_profiles (
			id        TEXT PRIMARY KEY,
			name      TEXT NOT NULL,
			format    TEXT NOT NULL,
			theme     TEXT NOT NULL DEFAULT '',
			aspect    TEXT NOT NULL DEFAULT '',
			home_page TEXT NOT NULL DEFAULT ''
		)`); err != nil {
		return err
	}
	for _, table := range []string{"pages", "terminals"} {
		var n int
		s.db.QueryRow(`SELECT count(*) FROM pragma_table_info(?) WHERE name = 'terminal_profile'`, table).Scan(&n)
		if n == 0 {
			if _, err := s.db.Exec(`ALTER TABLE ` + table + ` ADD COLUMN terminal_profile TEXT NOT NULL DEFAULT ''`); err != nil {
				return err
			}
		}
	}
	var hasRole int
	s.db.QueryRow(`SELECT count(*) FROM pragma_table_info('terminal_profiles') WHERE name = 'role'`).Scan(&hasRole)
	if hasRole == 0 {
		if _, err := s.db.Exec(`ALTER TABLE terminal_profiles ADD COLUMN role TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	// The default profile, made once from what there was: every page, the
	// house's start page, and the theme and aspect of that page (else of the first).
	var n int
	s.db.QueryRow(`SELECT count(*) FROM terminal_profiles WHERE id = ?`, defaultProfile).Scan(&n)
	if n == 0 {
		var home, theme, aspect string
		s.db.QueryRow(`SELECT value FROM options WHERE key = 'homePage'`).Scan(&home)
		if s.db.QueryRow(`SELECT theme, aspect FROM pages WHERE id = ?`, home).Scan(&theme, &aspect) != nil {
			s.db.QueryRow(`SELECT theme, aspect FROM pages ORDER BY title LIMIT 1`).Scan(&theme, &aspect)
		}
		if _, err := s.db.Exec(`INSERT INTO terminal_profiles (id, name, format, theme, aspect, home_page) VALUES (?, 'Ordinateur', 'desktop', ?, ?, ?)`,
			defaultProfile, theme, aspect, home); err != nil {
			return err
		}
	}
	_, err := s.db.Exec(`UPDATE pages SET terminal_profile = ? WHERE terminal_profile = ''`, defaultProfile)
	return err
}

func scanProfile(row interface{ Scan(...any) error }) (TerminalProfile, error) {
	var p TerminalProfile
	err := row.Scan(&p.ID, &p.Name, &p.Format, &p.Theme, &p.Aspect, &p.HomePage, &p.Role)
	p.Role = roleOf(p.Role, p.Format)
	return p, err
}

func (s *Service) terminalProfile(id string) (TerminalProfile, error) {
	p, err := scanProfile(s.store.db.QueryRow(`SELECT id, name, format, theme, aspect, home_page, role FROM terminal_profiles WHERE id = ?`, id))
	if err != nil {
		return p, ErrNotFound
	}
	return p, nil
}

// terminalProfiles lists them, the default one first.
func (s *Service) terminalProfiles() ([]TerminalProfile, error) {
	rows, err := s.store.db.Query(`SELECT id, name, format, theme, aspect, home_page, role FROM terminal_profiles
		ORDER BY id != ?, name`, defaultProfile)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []TerminalProfile{}
	for rows.Next() {
		p, err := scanProfile(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, p)
	}
	return list, rows.Err()
}

// SaveTerminalProfile creates a profile (empty id) or renames it and sets its
// start page; format, theme and aspect stay as created.
func (s *Service) SaveTerminalProfile(in TerminalProfile) (TerminalProfile, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" || len(name) > maxPageTitle {
		return TerminalProfile{}, Invalid("a name is needed (100 characters at most)")
	}
	if in.Role != "" && !slices.Contains(profileRoles, in.Role) {
		return TerminalProfile{}, Invalid("unknown role")
	}
	if in.ID == "" {
		if !slices.Contains(profileFormats, in.Format) {
			return TerminalProfile{}, Invalid("unknown format")
		}
		raw := make([]byte, 10)
		rand.Read(raw)
		in.ID = strings.ToLower(base64.RawURLEncoding.EncodeToString(raw))
		if _, err := s.store.db.Exec(`INSERT INTO terminal_profiles (id, name, format, theme, aspect, home_page, role) VALUES (?, ?, ?, ?, ?, '', ?)`,
			in.ID, name, in.Format, in.Theme, in.Aspect, in.Role); err != nil {
			return TerminalProfile{}, err
		}
		s.configChanged("profile.create", in.ID)
		return s.terminalProfile(in.ID)
	}
	stored, err := s.terminalProfile(in.ID)
	if err != nil {
		return stored, err
	}
	if in.Format != stored.Format || in.Theme != stored.Theme || in.Aspect != stored.Aspect {
		return TerminalProfile{}, Invalid("format, theme and aspect are fixed at creation")
	}
	if in.HomePage != "" {
		if p, err := s.page(in.HomePage); err != nil || p.TerminalProfile != in.ID {
			return TerminalProfile{}, Invalid("the start page must be a page of the profile")
		}
	}
	role := in.Role
	if role == "" {
		role = stored.Role
	}
	s.store.db.Exec(`UPDATE terminal_profiles SET name = ?, home_page = ?, role = ? WHERE id = ?`, name, in.HomePage, role, in.ID)
	s.configChanged("profile.update", in.ID)
	return s.terminalProfile(in.ID)
}

// DeleteTerminalProfile removes a profile and its pages; its terminals show
// the default profile again. The default profile stays.
func (s *Service) DeleteTerminalProfile(id string) error {
	if id == defaultProfile {
		return Invalid("the default profile stays")
	}
	tx, err := s.store.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, _ := tx.Exec(`DELETE FROM terminal_profiles WHERE id = ?`, id)
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	tx.Exec(`DELETE FROM pages WHERE terminal_profile = ?`, id)
	tx.Exec(`UPDATE terminals SET terminal_profile = '' WHERE terminal_profile = ?`, id)
	if err := tx.Commit(); err != nil {
		return err
	}
	s.configChanged("profile.delete", id)
	return nil
}

// pageWriter is who may write the pages of a profile (§3.6): the admin and
// a signed-in person of level ≤ 1 every profile; another person only the
// profile given to their own terminal, on that terminal. Never from outside.
func (s *Service) pageWriter(token string, outside bool) func(profile string) bool {
	never := func(string) bool { return false }
	if outside {
		return never
	}
	if _, err := s.asAdmin(token); err == nil {
		return func(string) bool { return true }
	}
	c, err := s.authenticate(token, authz.Relay)
	if err != nil || c.Profile != auth.ProfilePerson {
		return never
	}
	if *c.Lvl <= 1 {
		return func(string) bool { return true }
	}
	return func(profile string) bool { return s.ownsProfile(c.Sub, c.Term, profile) }
}

// ownsProfile: the person (`profil:<id>`, the token's sub) owns the terminal, and the profile is the one given to it.
func (s *Service) ownsProfile(person, terminal, profile string) bool {
	var owner sql.NullInt64
	var given string
	if profile == "" || terminal == "" ||
		s.store.db.QueryRow(`SELECT owner, terminal_profile FROM terminals WHERE id = ?`, terminal).Scan(&owner, &given) != nil {
		return false
	}
	return owner.Valid && "profil:"+strconv.FormatInt(owner.Int64, 10) == person && given == profile
}
