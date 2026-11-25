package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"
)

// The configuration of the interfaces (AUTH-DESIGN §3.6, op config): pages,
// start pages, contexts offered, hidden Things, Things added by address, and
// the screen of each terminal. Kept by auth with its state; the relays only
// serve it. Moved from eria-ui-server, whose pages they were.

func (s *Store) migrateConfig() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS pages (
			id       TEXT PRIMARY KEY,
			title    TEXT NOT NULL,
			theme    TEXT NOT NULL DEFAULT '',
			aspect   TEXT NOT NULL DEFAULT '',
			layout   TEXT NOT NULL DEFAULT '',
			version  INTEGER NOT NULL,
			elements TEXT NOT NULL,
			options  TEXT NOT NULL
		);
		CREATE TABLE IF NOT EXISTS contexts (
			id       TEXT PRIMARY KEY,
			label    TEXT NOT NULL,
			position INTEGER NOT NULL
		);
		CREATE TABLE IF NOT EXISTS hidden (pattern TEXT PRIMARY KEY);
		CREATE TABLE IF NOT EXISTS manual_things (id TEXT PRIMARY KEY, url TEXT NOT NULL);
		CREATE TABLE IF NOT EXISTS options (key TEXT PRIMARY KEY, value TEXT NOT NULL);`)
	if err != nil {
		return err
	}
	// The screen of a terminal (watch, phone, tablet…), apart from its kind.
	for _, column := range []string{"screen", "detected_screen", "home_page"} {
		var n int
		s.db.QueryRow(`SELECT count(*) FROM pragma_table_info('terminals') WHERE name = ?`, column).Scan(&n)
		if n == 0 {
			if _, err := s.db.Exec(`ALTER TABLE terminals ADD COLUMN ` + column + ` TEXT NOT NULL DEFAULT ''`); err != nil {
				return err
			}
		}
	}
	return nil
}

// configChanged bumps the version the relays poll.
func (s *Service) configChanged(event, detail string) {
	s.bumpConfig()
	s.store.log(event, detail)
}

// bumpConfig tells the relays to read the configuration again: also after
// a change of the terminals it lists (the active ones).
func (s *Service) bumpConfig() {
	s.store.db.Exec(`INSERT INTO state (key, value) VALUES ('config', ?)
		ON CONFLICT (key) DO UPDATE SET value = max(value + 1, excluded.value)`, s.now().UnixMilli())
}

func (s *Service) configVersion() int64 {
	v := int64(1)
	s.store.db.QueryRow(`SELECT value FROM state WHERE key = 'config'`).Scan(&v)
	return v
}

// --- Pages (eria-ui-app PLAN §5.000) ---

type Page struct {
	ID       string          `json:"id"`
	Title    string          `json:"title"`
	Theme    string          `json:"theme"`   // "" = Base; fixed at creation
	Aspect   string          `json:"aspect"`  // fixed at creation
	Layout   string          `json:"layout"`  // fixed at creation
	Version  int             `json:"version"` // +1 at each save, checked against conflicts
	Elements []Element       `json:"elements"`
	Options  json.RawMessage `json:"options"`
	// The terminal profile it belongs to; fixed at creation.
	TerminalProfile string `json:"terminalProfile"`
}

// Element is one function of a page; its fields depend on its type.
type Element struct {
	ID         string          `json:"id"`
	Type       string          `json:"type"` // service | property | action | event | app
	Thing      string          `json:"thing,omitempty"`
	Capability string          `json:"capability,omitempty"`
	Name       string          `json:"name,omitempty"`
	Input      json.RawMessage `json:"input,omitempty"`
	Label      string          `json:"label,omitempty"`
	Hidden     bool            `json:"hidden,omitempty"`
	Widget     string          `json:"widget,omitempty"`
	Options    json.RawMessage `json:"options,omitempty"`
}

const (
	maxElements  = 200
	maxPageTitle = 100
)

var errPageStale = Invalid("this page was changed meanwhile: reload it")

func validPage(p Page) error {
	if t := strings.TrimSpace(p.Title); t == "" || len(t) > maxPageTitle {
		return Invalid("a title is needed (100 characters at most)")
	}
	if len(p.Elements) > maxElements {
		return Invalid("too many elements")
	}
	if !isObject(p.Options) {
		return Invalid("options must be an object")
	}
	ids := map[string]bool{}
	for _, e := range p.Elements {
		ok := e.ID != "" && !ids[e.ID] && isObject(e.Options) && (len(e.Input) == 0 || json.Valid(e.Input))
		ids[e.ID] = true
		switch e.Type {
		case "service":
			ok = ok && e.Thing != "" && e.Capability != ""
		case "property", "action", "event":
			ok = ok && e.Thing != "" && e.Name != ""
		case "app":
			ok = ok && e.Name != ""
		default:
			ok = false
		}
		if !ok {
			return Invalid(fmt.Sprintf("invalid element %q", e.ID))
		}
	}
	return nil
}

// isObject accepts a JSON object, or nothing (absent or null).
func isObject(raw json.RawMessage) bool {
	var v map[string]json.RawMessage
	return len(raw) == 0 || string(raw) == "null" || json.Unmarshal(raw, &v) == nil && v != nil
}

const pageColumns = `id, title, theme, aspect, layout, version, elements, options, terminal_profile`

func scanPage(row interface{ Scan(...any) error }) (Page, error) {
	var p Page
	var elements, options string
	if err := row.Scan(&p.ID, &p.Title, &p.Theme, &p.Aspect, &p.Layout, &p.Version, &elements, &options, &p.TerminalProfile); err != nil {
		return p, err
	}
	json.Unmarshal([]byte(elements), &p.Elements)
	p.Options = json.RawMessage(options)
	return p, nil
}

func (s *Service) page(id string) (Page, error) {
	p, err := scanPage(s.store.db.QueryRow(`SELECT `+pageColumns+` FROM pages WHERE id = ?`, id))
	if err != nil {
		return Page{}, ErrNotFound
	}
	return p, nil
}

func (s *Service) pages() ([]Page, error) {
	rows, err := s.store.db.Query(`SELECT ` + pageColumns + ` FROM pages ORDER BY title`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []Page{}
	for rows.Next() {
		p, err := scanPage(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, p)
	}
	return list, rows.Err()
}

// SavePage creates a page (empty id) or updates it (same version as stored;
// theme, aspect and layout kept as created).
func (s *Service) SavePage(in Page) (Page, error) {
	if err := validPage(in); err != nil {
		return Page{}, err
	}
	if in.Elements == nil {
		in.Elements = []Element{}
	}
	if len(in.Options) == 0 || string(in.Options) == "null" {
		in.Options = json.RawMessage("{}")
	}
	elements, _ := json.Marshal(in.Elements)
	title := strings.TrimSpace(in.Title)
	if in.ID == "" {
		// A new page joins a profile (the default one when none is named), in its theme and aspect.
		if in.TerminalProfile == "" {
			in.TerminalProfile = defaultProfile
		}
		profile, err := s.terminalProfile(in.TerminalProfile)
		if err != nil {
			return Page{}, Invalid("unknown terminal profile")
		}
		in.Theme, in.Aspect = profile.Theme, profile.Aspect
		raw := make([]byte, 10)
		rand.Read(raw)
		in.ID = strings.ToLower(base64.RawURLEncoding.EncodeToString(raw))
		_, err = s.store.db.Exec(`INSERT INTO pages (id, title, theme, aspect, layout, version, elements, options, terminal_profile)
			VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)`, in.ID, title, in.Theme, in.Aspect, in.Layout, string(elements), string(in.Options), in.TerminalProfile)
		if err != nil {
			return Page{}, err
		}
		s.configChanged("page.create", in.ID)
		return s.page(in.ID)
	}
	stored, err := s.page(in.ID)
	switch {
	case err != nil:
		return Page{}, err
	case stored.Version != in.Version:
		return Page{}, errPageStale
	case in.Theme != stored.Theme || in.Aspect != stored.Aspect || in.Layout != stored.Layout ||
		in.TerminalProfile != "" && in.TerminalProfile != stored.TerminalProfile:
		return Page{}, Invalid("theme, aspect, layout and profile are fixed at creation")
	}
	res, err := s.store.db.Exec(`UPDATE pages SET title = ?, version = version + 1, elements = ?, options = ?
		WHERE id = ? AND version = ?`, title, string(elements), string(in.Options), in.ID, in.Version)
	if err != nil {
		return Page{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return Page{}, errPageStale
	}
	s.configChanged("page.update", in.ID)
	return s.page(in.ID)
}

func (s *Service) DeletePage(id string) error {
	res, err := s.store.db.Exec(`DELETE FROM pages WHERE id = ?`, id)
	if n, _ := res.RowsAffected(); err != nil || n == 0 {
		return ErrNotFound
	}
	s.store.db.Exec(`UPDATE terminal_profiles SET home_page = '' WHERE home_page = ?`, id)
	s.configChanged("page.delete", id)
	return nil
}

// knownPage accepts "" (no choice) or an existing page.
func (s *Service) knownPage(id string) error {
	if id == "" {
		return nil
	}
	if _, err := s.page(id); err != nil {
		return Invalid("unknown page")
	}
	return nil
}

// --- Settings ---

type Context struct {
	ID    string `json:"id" yaml:"id"`
	Label string `json:"label" yaml:"label"`
}

type ManualThing struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

// TerminalScreen is what the interfaces need of a terminal.
type TerminalScreen struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Screen         string `json:"screen"`         // "" = detected
	DetectedScreen string `json:"detectedScreen"` // reported by the app
	HomePage       string `json:"homePage"`       // "" = the house's start page
	// The profile the admin gave it ("" = the default one), and its owner (a phone's person, 0: none).
	TerminalProfile string `json:"terminalProfile"`
	Owner           int64  `json:"owner"`
}

// Screens are the sizes of terminal, smallest to largest (PLAN §5.4).
var screens = []string{"watch", "phone", "tablet", "wall-tablet", "desktop", "tv"}

// InterfaceConfig is the whole configuration, read by the relays.
type InterfaceConfig struct {
	Version   int64            `json:"version"`
	Pages     []Page           `json:"pages"`
	HomePage  string           `json:"homePage"`
	Contexts  []Context        `json:"contexts"`
	Levels    []Level          `json:"levels"`
	Hidden    []string         `json:"hidden"`
	Manual    []ManualThing    `json:"manual"`
	Terminals []TerminalScreen `json:"terminals"`
	// Terminal profiles, the default one first.
	TerminalProfiles []TerminalProfile `json:"terminalProfiles"`
	// Set point delays chosen by the admin, in seconds, by Thing (only those set).
	SetpointTimeouts map[string]int `json:"setpointTimeouts"`
}

func (s *Service) Config() (InterfaceConfig, error) {
	c := InterfaceConfig{Version: s.configVersion(), Contexts: []Context{}, Levels: []Level{}, Hidden: []string{}, Manual: []ManualThing{},
		Terminals: []TerminalScreen{}, SetpointTimeouts: map[string]int{}}
	var err error
	if c.Pages, err = s.pages(); err != nil {
		return c, err
	}
	if c.TerminalProfiles, err = s.terminalProfiles(); err != nil {
		return c, err
	}
	s.store.db.QueryRow(`SELECT value FROM options WHERE key = 'homePage'`).Scan(&c.HomePage)
	query := func(q string, scan func(*sql.Rows)) error {
		rows, err := s.store.db.Query(q)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			scan(rows)
		}
		return rows.Err()
	}
	return c, errors.Join(
		query(`SELECT id, label FROM contexts ORDER BY position`, func(r *sql.Rows) {
			var x Context
			r.Scan(&x.ID, &x.Label)
			c.Contexts = append(c.Contexts, x)
		}),
		query(`SELECT level, name FROM levels ORDER BY level`, func(r *sql.Rows) {
			var l Level
			r.Scan(&l.Level, &l.Name)
			c.Levels = append(c.Levels, l)
		}),
		query(`SELECT pattern FROM hidden ORDER BY pattern`, func(r *sql.Rows) {
			var p string
			r.Scan(&p)
			c.Hidden = append(c.Hidden, p)
		}),
		query(`SELECT id, url FROM manual_things ORDER BY id`, func(r *sql.Rows) {
			var m ManualThing
			r.Scan(&m.ID, &m.URL)
			c.Manual = append(c.Manual, m)
		}),
		query(`SELECT id, name, screen, detected_screen, home_page, terminal_profile, coalesce(owner, 0) FROM terminals WHERE status = 'active' ORDER BY name`, func(r *sql.Rows) {
			var t TerminalScreen
			r.Scan(&t.ID, &t.Name, &t.Screen, &t.DetectedScreen, &t.HomePage, &t.TerminalProfile, &t.Owner)
			c.Terminals = append(c.Terminals, t)
		}),
		query(`SELECT id, setpoint_timeout FROM things WHERE setpoint_timeout > 0`, func(r *sql.Rows) {
			var id string
			var seconds int
			r.Scan(&id, &seconds)
			c.SetpointTimeouts[id] = seconds
		}))
}

func (s *Service) SetHomePage(id string) error {
	if err := s.knownPage(id); err != nil {
		return err
	}
	s.store.db.Exec(`INSERT INTO options (key, value) VALUES ('homePage', ?)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value`, id)
	s.configChanged("config.homePage", id)
	return nil
}

// SetContexts replaces the list, in display order: manager-contexts' (its
// TD, contextsOfTD), never edited here.
func (s *Service) SetContexts(list []Context) error {
	seen := map[string]bool{}
	for _, c := range list {
		if strings.TrimSpace(c.ID) == "" || strings.TrimSpace(c.Label) == "" || seen[c.ID] {
			return Invalid("each context needs a unique id and a label")
		}
		seen[c.ID] = true
	}
	tx, err := s.store.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	tx.Exec(`DELETE FROM contexts`)
	for i, c := range list {
		if _, err := tx.Exec(`INSERT INTO contexts (id, label, position) VALUES (?, ?, ?)`, c.ID, strings.TrimSpace(c.Label), i); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.configChanged("config.contexts", "")
	return nil
}

// SetHidden replaces the glob patterns of the Things never shown.
func (s *Service) SetHidden(patterns []string) error {
	for _, p := range patterns {
		if _, err := path.Match(p, ""); err != nil || p == "" {
			return Invalid("bad pattern " + p)
		}
	}
	tx, err := s.store.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	tx.Exec(`DELETE FROM hidden`)
	for _, p := range patterns {
		tx.Exec(`INSERT OR IGNORE INTO hidden (pattern) VALUES (?)`, p)
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.configChanged("config.hidden", "")
	return nil
}

func (s *Service) AddManual(m ManualThing) error {
	if m.ID == "" || !strings.HasPrefix(m.URL, "http") || len(m.URL) > 512 {
		return ErrInvalid
	}
	s.store.db.Exec(`INSERT INTO manual_things (id, url) VALUES (?, ?)
		ON CONFLICT (id) DO UPDATE SET url = excluded.url`, m.ID, m.URL)
	s.configChanged("config.manual.add", m.ID)
	return nil
}

func (s *Service) RemoveManual(id string) error {
	res, _ := s.store.db.Exec(`DELETE FROM manual_things WHERE id = ?`, id)
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	s.configChanged("config.manual.remove", id)
	return nil
}

// SetScreen is the admin's choice of screen and start page for a terminal.
func (s *Service) SetScreen(id string, screen, homePage, profile string) error {
	if screen != "" && !slices.Contains(screens, screen) {
		return Invalid("unknown screen")
	}
	if err := s.knownPage(homePage); err != nil {
		return err
	}
	// A profile only of the terminal's screen format (the one chosen, else detected).
	if profile != "" {
		p, err := s.terminalProfile(profile)
		if err != nil {
			return Invalid("unknown terminal profile")
		}
		effective := screen
		if effective == "" {
			s.store.db.QueryRow(`SELECT detected_screen FROM terminals WHERE id = ?`, id).Scan(&effective)
		}
		if p.Format != effective {
			return Invalid("the profile is not for this terminal's screen")
		}
	}
	res, _ := s.store.db.Exec(`UPDATE terminals SET screen = ?, home_page = ?, terminal_profile = ? WHERE id = ?`, screen, homePage, profile, id)
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	s.configChanged("terminal.screen", id)
	return nil
}

// ReportScreen records the screen the app deduced, on its own token.
func (s *Service) ReportScreen(term, detected string) error {
	if !slices.Contains(screens, detected) {
		return ErrInvalid
	}
	var old string
	s.store.db.QueryRow(`SELECT detected_screen FROM terminals WHERE id = ?`, term).Scan(&old)
	if old == detected {
		return nil
	}
	s.store.db.Exec(`UPDATE terminals SET detected_screen = ? WHERE id = ?`, detected, term)
	s.configChanged("terminal.detected", term)
	return nil
}

// Level names a level for the interfaces (AUTH-DESIGN §2.1): display only,
// the tokens and the rules carry the number. Level 0 is always the admin.
type Level struct {
	Level int    `json:"level" yaml:"level"`
	Name  string `json:"name" yaml:"name"`
}

// defaultLevels are AUTH-DESIGN §2.1's meanings, for a config without levels.
var defaultLevels = []Level{{1, "Parents"}, {2, "Enfants"}, {3, "Amis"}, {4, "Prestataires"}, {9, "Invité"}}

// SetLevels replaces the names of the levels 1 to 9; a level left out has none.
func (s *Service) SetLevels(list []Level) error {
	seen := map[int]bool{}
	for i, l := range list {
		list[i].Name = strings.TrimSpace(l.Name)
		if l.Level < 1 || l.Level > 9 || seen[l.Level] || list[i].Name == "" || len([]rune(list[i].Name)) > 32 {
			return Invalid("each level 1 to 9 at most once, with a name of 1 to 32 characters")
		}
		seen[l.Level] = true
	}
	tx, err := s.store.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	tx.Exec(`DELETE FROM levels`)
	for _, l := range list {
		if _, err := tx.Exec(`INSERT INTO levels (level, name) VALUES (?, ?)`, l.Level, l.Name); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.configChanged("config.levels", "")
	return nil
}

// SeedLevels copies the first level names (the config's, else the defaults),
// once: a house started before the names gets them at its first update.
func (s *Service) SeedLevels(levels []Level) error {
	var n int
	s.store.db.QueryRow(`SELECT count(*) FROM options WHERE key = 'levels_seeded'`).Scan(&n)
	if n > 0 {
		return nil
	}
	if len(levels) == 0 {
		levels = defaultLevels
	}
	if err := s.SetLevels(append([]Level(nil), levels...)); err != nil {
		return err
	}
	_, err := s.store.db.Exec(`INSERT INTO options (key, value) VALUES ('levels_seeded', '1')`)
	return err
}

// RenameCoordinator moves a hidden pattern of the master to the coordinator
// it became (2026-11-13: urn:eria:manager:1 → urn:eria:coordinator:1), once.
// ponytail: one-off migration, remove once every house runs past it.
func (s *Service) RenameCoordinator() error {
	res, err := s.store.db.Exec(`UPDATE OR IGNORE hidden SET pattern = 'urn:eria:coordinator:1' WHERE pattern = 'urn:eria:manager:1'`)
	if err != nil {
		return err
	}
	s.store.db.Exec(`DELETE FROM hidden WHERE pattern = 'urn:eria:manager:1'`) // the new one was already there
	if n, _ := res.RowsAffected(); n > 0 {
		s.configChanged("config.hidden", "urn:eria:coordinator:1")
	}
	return nil
}

// SeedConfig copies the first hidden patterns of the config file, once (the
// contexts come from manager-contexts' TD).
func (s *Service) SeedConfig(hidden []string) error {
	var n int
	s.store.db.QueryRow(`SELECT count(*) FROM options WHERE key = 'seeded'`).Scan(&n)
	if n > 0 {
		return nil
	}
	if err := s.SetHidden(hidden); err != nil {
		return err
	}
	_, err := s.store.db.Exec(`INSERT INTO options (key, value) VALUES ('seeded', '1')`)
	return err
}
