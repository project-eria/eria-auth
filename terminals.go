package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
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

// Enrollment is what the admin shows to the terminal: a QR code (secret of
// 128 bits) and a short code of 8 characters, valid 10 min (§1.2).
type Enrollment struct {
	Terminal string `json:"terminal"`
	Secret   string `json:"secret"`
	Code     string `json:"code"`
	Expires  int64  `json:"expires"`
}

// CreateTerminal adds a terminal record and its first enrollment.
func (s *Service) CreateTerminal(c TerminalChange) (Enrollment, error) {
	if !c.valid() {
		return Enrollment{}, ErrInvalid
	}
	id := randomID()
	var owner any
	if c.Owner != 0 {
		owner = c.Owner
	}
	_, err := s.store.db.Exec(`INSERT INTO terminals (id, name, type, zone, floor, room_only, owner, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, 'new')`, id, strings.TrimSpace(c.Name), c.Type, c.Zone, c.Floor, c.RoomOnly, owner)
	if err != nil {
		return Enrollment{}, ErrInvalid
	}
	s.store.log("terminal.create", id+" "+c.Name)
	return s.NewEnrollment(id)
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

// NewEnrollment gives a terminal a new code. Consuming it replaces the
// terminal's keys: one record, one key (F014).
func (s *Service) NewEnrollment(id string) (Enrollment, error) {
	if _, err := s.terminal(id); err != nil {
		return Enrollment{}, err
	}
	secret := make([]byte, 16)
	rand.Read(secret)
	e := Enrollment{Terminal: id, Secret: base64.RawURLEncoding.EncodeToString(secret), Code: randomCode(8),
		Expires: s.now().Add(enrollTTL).Unix()}
	_, err := s.store.db.Exec(`INSERT INTO enrollments (terminal, secret, code, expires) VALUES (?, ?, ?, ?)
		ON CONFLICT (terminal) DO UPDATE SET secret = excluded.secret, code = excluded.code,
		expires = excluded.expires, attempts = 0`, id, sha(e.Secret), sha(e.Code), e.Expires)
	return e, err
}

// KeyIn is a public key sent by an app: typed by alg, never by its length.
type KeyIn struct {
	Alg string `json:"alg"`
	Key []byte `json:"key"`
}

func (k KeyIn) parse() (auth.PublicKey, error) { return auth.ParsePublicKey(auth.Alg(k.Alg), k.Key) }

// Enroll consumes a code (QR secret or short code) and binds the terminal's
// keys. The terminal then waits for the admin's confirmation (F098). Only
// through the inner relay.
func (s *Service) Enroll(code string, identity KeyIn, bio *KeyIn, device string, out bool) (string, error) {
	if out {
		return "", ErrDenied
	}
	s.sweep()
	var id string
	err := s.store.db.QueryRow(`DELETE FROM enrollments WHERE (secret = ? OR code = ?) AND expires > ?
		RETURNING terminal`, sha(code), sha(strings.ToUpper(code)), s.now().Unix()).Scan(&id)
	if err != nil {
		return "", s.badCode()
	}
	t, _ := s.terminal(id)
	idKey, err := identity.parse()
	if err != nil {
		return "", ErrInvalid
	}
	keys := []struct {
		pub  auth.PublicKey
		role string
	}{{idKey, "identity"}}
	if bio != nil {
		bioKey, err := bio.parse()
		if err != nil || t.Type != "phone" || bioKey.Alg() != auth.P256 {
			return "", ErrInvalid // a bio key is hardware-held, on a phone
		}
		keys = append(keys, struct {
			pub  auth.PublicKey
			role string
		}{bioKey, "bio"})
	}
	tx, err := s.store.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var previous int
	tx.QueryRow(`SELECT count(*) FROM keys WHERE terminal = ?`, id).Scan(&previous)
	tx.Exec(`DELETE FROM keys WHERE terminal = ?`, id)
	for _, k := range keys {
		if _, err := tx.Exec(`INSERT INTO keys (kid, role, alg, raw, terminal) VALUES (?, ?, ?, ?, ?)`,
			k.pub.KID(), k.role, k.pub.Alg(), k.pub.Bytes(), id); err != nil {
			return "", ErrInvalid
		}
	}
	tx.Exec(`UPDATE terminals SET status = 'pending', enrolled = ?, device = ? WHERE id = ?`, s.now().Unix(), deviceName(device), id)
	if err := tx.Commit(); err != nil {
		return "", err
	}
	if previous > 0 {
		s.revoke("term:" + id)
		s.notify("Terminal réenrôlé : " + t.Name)
	}
	s.store.log("terminal.enroll", id)
	return id, nil
}

// deviceName keeps what the app says it is (version, system) printable and
// short: shown to the admin before confirming, never relied upon.
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

// badCode counts a wrong enrollment code; at the fifth within 10 min, every
// open code is cancelled.
func (s *Service) badCode() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.badCodes = slices.DeleteFunc(s.badCodes, func(t time.Time) bool { return now.Sub(t) > enrollTTL })
	s.badCodes = append(s.badCodes, now)
	if len(s.badCodes) >= maxBadCodes {
		s.store.db.Exec(`DELETE FROM enrollments`)
		s.badCodes = nil
		s.store.log("enroll.cancelled", "too many wrong codes")
		s.notify("Codes d'enrôlement annulés")
	}
	return ErrDenied
}

// sweep deletes the terminals left pending or new after their code expired.
func (s *Service) sweep() {
	limit := s.now().Add(-enrollTTL).Unix()
	s.store.db.Exec(`DELETE FROM terminals WHERE status IN ('new', 'pending')
		AND NOT EXISTS (SELECT 1 FROM enrollments e WHERE e.terminal = terminals.id)
		AND (status = 'new' OR enrolled < ?)`, limit)
}

// ConfirmTerminal is the admin's confirmation of an enrolled terminal.
func (s *Service) ConfirmTerminal(id string) error {
	s.sweep()
	res, err := s.store.db.Exec(`UPDATE terminals SET status = 'active' WHERE id = ? AND status = 'pending'`, id)
	if n, _ := res.RowsAffected(); err != nil || n == 0 {
		return ErrNotFound
	}
	s.bumpConfig()
	s.store.log("terminal.confirm", id)
	return nil
}

func (s *Service) Terminals() ([]Terminal, error) {
	s.sweep()
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
// terminal but the admin's own computer loses its keys and is blocked; each
// is enrolled again with a new code. The validator signs it (YubiKey).
func (s *Service) RevokeAll(p Proof, by Caller) (int, error) {
	if _, err := s.prove(p, "validator", domainRevokeAll, ""); err != nil {
		return 0, err
	}
	rows, err := s.store.db.Query(`SELECT id FROM terminals WHERE id != ?`, by.Term)
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
	for _, id := range ids {
		s.store.db.Exec(`DELETE FROM keys WHERE terminal = ? AND role IN ('identity', 'bio')`, id)
		s.store.db.Exec(`UPDATE terminals SET status = 'blocked' WHERE id = ?`, id)
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
