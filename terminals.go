package main

import (
	"database/sql"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/project-eria/go-wot/auth"
)

// TerminalChange are the admin's settings of a terminal (§2.5).
type TerminalChange struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Zone     string `json:"zone"`
	Floor    int    `json:"floor"`
	RoomOnly bool   `json:"roomOnly"`
	Owner    int64  `json:"owner"`
}

func (c TerminalChange) valid() bool {
	return strings.TrimSpace(c.Name) != "" && len(c.Name) <= 64 && len(c.Zone) <= 64 &&
		slices.Contains([]string{"fixed", "phone", "computer"}, c.Type) &&
		c.Floor >= 1 && c.Floor <= 9 && (c.Type == "fixed" || (c.Zone == "" && !c.RoomOnly))
}

// UpdateTerminal changes the settings of a terminal; its tokens fall.
func (s *Service) UpdateTerminal(id string, c TerminalChange) error {
	t, err := s.terminal(id)
	if err != nil {
		return err
	}
	if c.Type = t.Type; !c.valid() {
		return ErrInvalid
	}
	var owner any
	if c.Owner != 0 {
		owner = c.Owner
	}
	if _, err := s.store.db.Exec(`UPDATE terminals SET name = ?, zone = ?, floor = ?, room_only = ?, owner = ? WHERE id = ?`,
		strings.TrimSpace(c.Name), c.Zone, c.Floor, c.RoomOnly, owner, id); err != nil {
		return ErrInvalid
	}
	s.revoke("term:" + id)
	s.bumpConfig()
	s.store.log("terminal.update", id)
	return nil
}

// KeyIn is a public key sent by an app: typed by alg, never by its length.
type KeyIn struct {
	Alg string `json:"alg"`
	Key []byte `json:"key"`
}

func (k KeyIn) parse() (auth.PublicKey, error) { return auth.ParsePublicKey(auth.Alg(k.Alg), k.Key) }

// --- Enrollment requests (§1.2) ---
//
// A terminal asks to enroll: auth keeps its keys and gives it a code of 5
// characters, unique among the open requests (10 min, 5 at most), that it
// shows. The admin types the code read on the terminal's screen into that
// very request: the terminal is active at once, with a new record or as an
// existing one (enrolled again). The code is no secret: it names a request
// whose keys auth already holds, and only the admin types codes.

// Request is an enrollment request; its code goes to the terminal only.
type Request struct {
	ID      string `json:"id"`
	Code    string `json:"code,omitempty"`
	Device  string `json:"device,omitempty"`
	Created int64  `json:"created"`
	Expires int64  `json:"expires"`
}

const (
	maxRequests = 5
	codeLength  = 5
)

// Ask records a terminal's request with its keys. Only through the inner
// relay. Past maxRequests open ones, the oldest falls (and the admin is told).
func (s *Service) Ask(identity KeyIn, bio *KeyIn, device string, out bool) (Request, error) {
	if out {
		return Request{}, ErrDenied
	}
	idKey, err := identity.parse()
	if err != nil {
		return Request{}, ErrInvalid
	}
	var bioAlg string
	var bioRaw []byte
	if bio != nil {
		k, err := bio.parse()
		if err != nil || k.Alg() != auth.P256 {
			return Request{}, ErrInvalid // a bio key is hardware-held
		}
		bioAlg, bioRaw = string(k.Alg()), k.Bytes()
	}
	s.mu.Lock() // one request at a time: codes stay unique
	defer s.mu.Unlock()
	s.sweepRequests()
	var open int
	s.store.db.QueryRow(`SELECT count(*) FROM requests`).Scan(&open)
	if open >= maxRequests {
		s.store.db.Exec(`DELETE FROM requests WHERE id IN (SELECT id FROM requests ORDER BY created LIMIT ?)`, open-maxRequests+1)
		s.notify("Trop de demandes d'enrôlement : les plus anciennes sont tombées")
	}
	now := s.now()
	r := Request{ID: randomID(), Device: deviceName(device), Created: now.Unix(), Expires: now.Add(enrollTTL).Unix()}
	for {
		r.Code = randomCode(codeLength)
		var taken int
		s.store.db.QueryRow(`SELECT count(*) FROM requests WHERE code = ?`, r.Code).Scan(&taken)
		if taken == 0 {
			break
		}
	}
	if _, err := s.store.db.Exec(`INSERT INTO requests (id, code, alg, raw, bio_alg, bio_raw, device, created, expires)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, r.ID, r.Code, idKey.Alg(), idKey.Bytes(), bioAlg, bioRaw, r.Device, r.Created, r.Expires); err != nil {
		return Request{}, err
	}
	s.store.log("enroll.request", r.ID+" "+r.Device)
	return r, nil
}

// RequestOpen tells the terminal whether its request still waits.
func (s *Service) RequestOpen(id string) bool {
	var n int
	s.store.db.QueryRow(`SELECT count(*) FROM requests WHERE id = ? AND expires > ?`, id, s.now().Unix()).Scan(&n)
	return n == 1
}

// Requests are the open requests, for the admin (without their codes).
func (s *Service) Requests() ([]Request, error) {
	s.sweepRequests()
	rows, err := s.store.db.Query(`SELECT id, device, created, expires FROM requests ORDER BY created`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []Request{}
	for rows.Next() {
		var r Request
		rows.Scan(&r.ID, &r.Device, &r.Created, &r.Expires)
		list = append(list, r)
	}
	return list, nil
}

// EnrollIn is the admin's answer to a request: the code read on the
// terminal, and either the settings of a new terminal or the existing one
// it enrolls again.
type EnrollIn struct {
	Code     string          `json:"code"`
	Terminal *TerminalChange `json:"terminal"`
	Existing string          `json:"existing"`
}

// Enroll binds a request to a terminal once the admin typed its code.
func (s *Service) Enroll(requestID string, in EnrollIn) (Terminal, error) {
	s.sweepRequests()
	var code, alg, bioAlg, device string
	var raw, bioRaw []byte
	err := s.store.db.QueryRow(`SELECT code, alg, raw, bio_alg, bio_raw, device FROM requests WHERE id = ?`, requestID).
		Scan(&code, &alg, &raw, &bioAlg, &bioRaw, &device)
	if err != nil {
		return Terminal{}, ErrNotFound
	}
	if strings.ToUpper(strings.TrimSpace(in.Code)) != code {
		return Terminal{}, s.badCode()
	}
	idKey, err := auth.ParsePublicKey(auth.Alg(alg), raw)
	if err != nil {
		return Terminal{}, ErrInvalid
	}
	tx, err := s.store.db.Begin()
	if err != nil {
		return Terminal{}, err
	}
	defer tx.Rollback()
	id, kind := in.Existing, ""
	switch {
	case in.Existing != "":
		if tx.QueryRow(`SELECT type FROM terminals WHERE id = ?`, id).Scan(&kind) != nil {
			return Terminal{}, ErrNotFound
		}
	case in.Terminal != nil && in.Terminal.valid():
		c := in.Terminal
		id, kind = randomID(), c.Type
		var owner any
		if c.Owner != 0 {
			owner = c.Owner
		}
		if _, err := tx.Exec(`INSERT INTO terminals (id, name, type, zone, floor, room_only, owner, status)
			VALUES (?, ?, ?, ?, ?, ?, ?, 'active')`, id, strings.TrimSpace(c.Name), c.Type, c.Zone, c.Floor, c.RoomOnly, owner); err != nil {
			return Terminal{}, ErrInvalid
		}
	default:
		return Terminal{}, ErrInvalid
	}
	if bioAlg != "" && kind != "phone" {
		return Terminal{}, ErrInvalid // a bio key belongs to a personal phone
	}
	tx.Exec(`DELETE FROM keys WHERE terminal = ? AND role IN ('identity', 'bio')`, id)
	if _, err := tx.Exec(`INSERT INTO keys (kid, role, alg, raw, terminal) VALUES (?, 'identity', ?, ?, ?)`,
		idKey.KID(), alg, raw, id); err != nil {
		return Terminal{}, ErrInvalid
	}
	if bioAlg != "" {
		bioKey, err := auth.ParsePublicKey(auth.Alg(bioAlg), bioRaw)
		if err != nil {
			return Terminal{}, ErrInvalid
		}
		if _, err := tx.Exec(`INSERT INTO keys (kid, role, alg, raw, terminal) VALUES (?, 'bio', ?, ?, ?)`,
			bioKey.KID(), bioAlg, bioRaw, id); err != nil {
			return Terminal{}, ErrInvalid
		}
	}
	tx.Exec(`UPDATE terminals SET status = 'active', enrolled = ?, device = ? WHERE id = ?`, s.now().Unix(), device, id)
	tx.Exec(`DELETE FROM requests WHERE id = ?`, requestID)
	if err := tx.Commit(); err != nil {
		return Terminal{}, err
	}
	if in.Existing != "" {
		s.revoke("term:" + id) // the previous key's tokens fall
	}
	s.bumpConfig()
	s.store.log("terminal.enroll", id+" request "+requestID)
	return s.terminal(id)
}

// deviceName keeps what the app says it is (version, system) printable and
// short: shown to the admin before enrolling, never relied upon.
func deviceName(d string) string {
	d = strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return -1
	}, strings.TrimSpace(d))
	if r := []rune(d); len(r) > 64 {
		d = string(r[:64])
	}
	return d
}

// badCode counts a code that does not match its request; at the fifth
// within 10 min, every open request is cancelled.
func (s *Service) badCode() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.badCodes = slices.DeleteFunc(s.badCodes, func(t time.Time) bool { return now.Sub(t) > enrollTTL })
	s.badCodes = append(s.badCodes, now)
	if len(s.badCodes) >= maxBadCodes {
		s.store.db.Exec(`DELETE FROM requests`)
		s.badCodes = nil
		s.store.log("enroll.cancelled", "too many wrong codes")
		s.notify("Demandes d'enrôlement annulées")
	}
	return ErrDenied
}

func (s *Service) sweepRequests() {
	s.store.db.Exec(`DELETE FROM requests WHERE expires <= ?`, s.now().Unix())
}

func (s *Service) Terminals() ([]Terminal, error) {
	rows, err := s.store.db.Query(`SELECT id FROM terminals ORDER BY name`)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		rows.Scan(&id)
		ids = append(ids, id)
	}
	rows.Close()
	list := []Terminal{}
	for _, id := range ids {
		if t, err := s.terminal(id); err == nil {
			list = append(list, t)
		}
	}
	return list, nil
}

func (s *Service) DeleteTerminal(id string) error {
	res, err := s.store.db.Exec(`DELETE FROM terminals WHERE id = ?`, id)
	if n, _ := res.RowsAffected(); err != nil || n == 0 {
		return ErrNotFound
	}
	s.revoke("term:" + id)
	s.bumpConfig()
	s.store.log("terminal.delete", id)
	return nil
}

// RevokeAll is the admin's answer to a theft or an intrusion (§1.2): every
// terminal but the admin's own computer loses its keys and is blocked, and
// the open enrollment requests are cancelled; each is enrolled again from a
// new request. The validator signs it (YubiKey).
func (s *Service) RevokeAll(p Proof, by Caller) (int, error) {
	if _, err := s.prove(p, "validator", domainRevokeAll, ""); err != nil {
		return 0, err
	}
	tx, err := s.store.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT id FROM terminals WHERE id != ?`, by.Term)
	if err != nil {
		return 0, err
	}
	var ids []string
	for rows.Next() {
		var id string
		rows.Scan(&id)
		ids = append(ids, id)
	}
	rows.Close()
	for _, q := range []string{
		`DELETE FROM keys WHERE role IN ('identity', 'bio') AND terminal IN (SELECT id FROM terminals WHERE id != ?)`,
		`UPDATE terminals SET status = 'blocked' WHERE id != ?`,
	} {
		if _, err := tx.Exec(q, by.Term); err != nil {
			return 0, err
		}
	}
	if _, err := tx.Exec(`DELETE FROM requests`); err != nil { // asked before the incident
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	for _, id := range ids {
		s.revoke("term:" + id)
	}
	s.bumpConfig()
	s.store.log("terminals.revoke-all", fmt.Sprintf("%d terminals, kept %s", len(ids), by.Term))
	s.notify(fmt.Sprintf("Tous les terminaux révoqués (%d)", len(ids)))
	return len(ids), nil
}

// --- Bootstrap (§3.5) ---

// NewBootstrapCode is written to the standard output by `eria-auth
// bootstrap`, in a shell on the auth node: never logged.
func (s *Service) NewBootstrapCode() (string, error) {
	code := randomCode(12)
	_, err := s.store.db.Exec(`INSERT INTO bootstrap (code, expires) VALUES (?, ?)`,
		sha(code), s.now().Add(bootstrapTTL).Unix())
	s.store.log("bootstrap.code", "")
	s.notify("Code de bootstrap d'auth créé")
	return code, err
}

// BootstrapIn sets the level 0 passphrase, registers a validator key (the
// YubiKey) and enrolls the admin's computer, active at once: the one-time
// code, read in a shell on the auth node, is the attestation.
type BootstrapIn struct {
	Code       string `json:"code"`
	Passphrase string `json:"passphrase"`
	Validator  KeyIn  `json:"validator"`
	Name       string `json:"validatorName"`
	Computer   string `json:"computer"` // name of the admin's computer
	Identity   KeyIn  `json:"identity"`
}

func (s *Service) Bootstrap(in BootstrapIn, out bool) (string, error) {
	if out {
		return "", ErrDenied
	}
	res, err := s.store.db.Exec(`DELETE FROM bootstrap WHERE code = ? AND expires > ?`, sha(in.Code), s.now().Unix())
	if n, _ := res.RowsAffected(); err != nil || n == 0 {
		return "", ErrDenied
	}
	if err := checkPassphrase(in.Passphrase); err != nil {
		return "", err
	}
	validator, err1 := in.Validator.parse()
	identity, err2 := in.Identity.parse()
	if err1 != nil || err2 != nil || strings.TrimSpace(in.Computer) == "" {
		return "", ErrInvalid
	}
	tx, err := s.store.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var adminID int64
	err = tx.QueryRow(`SELECT id FROM profiles WHERE level = 0 ORDER BY id LIMIT 1`).Scan(&adminID)
	if err == sql.ErrNoRows {
		r, err := tx.Exec(`INSERT INTO profiles (name, level, secret) VALUES ('Admin', 0, ?)`, s.hasher.hash(in.Passphrase))
		if err != nil {
			return "", err
		}
		adminID, _ = r.LastInsertId()
	} else {
		tx.Exec(`UPDATE profiles SET secret = ? WHERE id = ?`, s.hasher.hash(in.Passphrase), adminID)
	}
	tx.Exec(`DELETE FROM keys WHERE role = 'validator' AND name = ?`, in.Name)
	if _, err := tx.Exec(`INSERT INTO keys (kid, role, alg, raw, name) VALUES (?, 'validator', ?, ?, ?)`,
		validator.KID(), validator.Alg(), validator.Bytes(), in.Name); err != nil {
		return "", ErrInvalid
	}
	id := randomID()
	if _, err := tx.Exec(`INSERT INTO terminals (id, name, type, status, enrolled) VALUES (?, ?, 'computer', 'active', ?)
		ON CONFLICT (name) DO NOTHING`, id, strings.TrimSpace(in.Computer), s.now().Unix()); err != nil {
		return "", err
	}
	tx.QueryRow(`SELECT id FROM terminals WHERE name = ?`, strings.TrimSpace(in.Computer)).Scan(&id)
	tx.Exec(`UPDATE terminals SET status = 'active' WHERE id = ?`, id)
	tx.Exec(`DELETE FROM keys WHERE terminal = ?`, id)
	if _, err := tx.Exec(`INSERT INTO keys (kid, role, alg, raw, terminal) VALUES (?, 'identity', ?, ?, ?)`,
		identity.KID(), identity.Alg(), identity.Bytes(), id); err != nil {
		return "", ErrInvalid
	}
	tx.Exec(`DELETE FROM sessions WHERE profile = ?`, adminID)
	if err := tx.Commit(); err != nil {
		return "", err
	}
	s.revokeOlder(fmt.Sprintf("sub:profil:%d", adminID))
	s.revokeOlder("term:" + id)
	s.bumpConfig()
	s.store.log("bootstrap", "computer "+id+", validator "+validator.KID())
	s.notify("Bootstrap d'auth effectué")
	return id, nil
}
