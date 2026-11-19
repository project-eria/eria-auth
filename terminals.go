package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/project-eria/go-wot/auth"
	zlog "github.com/rs/zerolog/log"
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
	now := s.now()
	if open >= maxRequests {
		s.store.db.Exec(`DELETE FROM requests WHERE id IN (SELECT id FROM requests ORDER BY created LIMIT ?)`, open-maxRequests+1)
		if now.Sub(s.floodAt) > enrollTTL { // a flood from the LAN alerts once
			s.floodAt = now
			s.notify("Trop de demandes d'enrôlement : les plus anciennes sont tombées")
		}
	}
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

// Enroll binds a request to a terminal once the admin typed its code. Never
// the admin's own computer: its key would be replaced under the session.
func (s *Service) Enroll(requestID string, in EnrollIn, by Caller) (Terminal, error) {
	if in.Existing != "" && in.Existing == by.Term {
		return Terminal{}, Invalid("this computer")
	}
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
	if kind != "phone" {
		bioAlg = "" // a bio key belongs to a personal phone: enrolled as something else, it is dropped
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
	// A new bio key is not a validator until the admin says so again (§1.2).
	tx.Exec(`UPDATE terminals SET status = 'active', enrolled = ?, device = ?, validator = 0 WHERE id = ?`, s.now().Unix(), device, id)
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
// within 10 min, every open request is cancelled. Not a refusal of the
// admin's session (403 ends it in the app): a 400 that says why.
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
	return Invalid("wrong code")
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
	var n int
	if err := tx.QueryRow(`SELECT count(*) FROM terminals WHERE id != ?`, by.Term).Scan(&n); err != nil {
		return 0, err
	}
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
	// One dated entry for every terminal, the list stays small (§2.10).
	s.revoke("term:*")
	s.bumpConfig()
	s.store.log("terminals.revoke-all", fmt.Sprintf("%d terminals, kept %s", n, by.Term))
	s.notify(fmt.Sprintf("Tous les terminaux révoqués (%d)", n))
	return n, nil
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
		zlog.Warn().Msg("[auth:bootstrap] refused: asked from outside the house")
		return "", ErrDenied
	}
	// Typed by hand: case and surrounding spaces don't matter (as enrollment codes).
	code := strings.ToUpper(strings.TrimSpace(in.Code))
	res, err := s.store.db.Exec(`DELETE FROM bootstrap WHERE code = ? AND expires > ?`, sha(code), s.now().Unix())
	if n, _ := res.RowsAffected(); err != nil || n == 0 {
		zlog.Warn().Msg("[auth:bootstrap] refused: unknown or expired code")
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

// --- New bio key after a biometric change (§1.2) ---

// BioPending is a phone's new bio key as the admin checks it: the phone
// shows the same print.
type BioPending struct {
	Since int64  `json:"since"`
	Print string `json:"print"`
	Kid   string `json:"kid"`
	Key   string `json:"key"` // raw, base64url: for the coordinator's admin-key add
}

// keyPrint is what a person compares between two screens: 8 hex characters
// of the key's sha256.
func keyPrint(raw []byte) string {
	h := sha256.Sum256(raw)
	return strings.ToUpper(hex.EncodeToString(h[:4]))
}

// BioState is a phone's bio key as auth knows it: active, pending or none
// (refused, or never had one).
type BioState struct {
	State string `json:"state"`
	Since int64  `json:"since,omitempty"`
	Print string `json:"print,omitempty"`
	// Validator: the admin's phone, whose new key the YubiKey confirms.
	Validator bool `json:"validator,omitempty"`
}

func (s *Service) bioState(id string) BioState {
	var st BioState
	var raw []byte
	s.store.db.QueryRow(`SELECT validator FROM terminals WHERE id = ?`, id).Scan(&st.Validator)
	if s.store.db.QueryRow(`SELECT status, raw, since FROM keys WHERE terminal = ? AND role = 'bio'`, id).
		Scan(&st.State, &raw, &st.Since) != nil {
		st.State = "none"
		return st
	}
	st.Print = keyPrint(raw)
	return st
}

// NewBio replaces a phone's bio key after its biometry changed: the phone's
// identity key signs the new one, which waits for the admin. The old one
// goes at once. Inner relay only, like an enrollment.
func (s *Service) NewBio(p Proof, in KeyIn, out bool) (BioState, error) {
	key, err := in.parse()
	if err != nil || in.Alg != "p256" || out {
		return BioState{}, ErrDenied
	}
	t, err := s.activeTerminal(p, domainNewBio, key.KID())
	if err != nil || t.Type != "phone" {
		return BioState{}, ErrDenied
	}
	tx, err := s.store.db.Begin()
	if err != nil {
		return BioState{}, err
	}
	defer tx.Rollback()
	tx.Exec(`DELETE FROM keys WHERE terminal = ? AND role = 'bio'`, t.ID)
	if _, err := tx.Exec(`INSERT INTO keys (kid, role, alg, raw, terminal, status, since) VALUES (?, 'bio', ?, ?, ?, 'pending', ?)`,
		key.KID(), in.Alg, in.Key, t.ID, s.now().Unix()); err != nil {
		return BioState{}, ErrInvalid
	}
	if err := tx.Commit(); err != nil {
		return BioState{}, err
	}
	s.store.log("terminal.bio", t.ID+" pending "+key.KID())
	s.notify("Nouvelle clé biométrique en attente : " + t.Name)
	return s.bioState(t.ID), nil
}

// BioStateOf answers a phone, on its identity proof.
func (s *Service) BioStateOf(p Proof) (BioState, error) {
	t, err := s.activeTerminal(p, domainBioState, "")
	if err != nil {
		return BioState{}, err
	}
	return s.bioState(t.ID), nil
}

// ConfirmBio is the admin's yes to a pending bio key. The admin's own phone
// (a validator) needs the YubiKey too: its key opens the administration.
func (s *Service) ConfirmBio(id string, p *Proof) error {
	t, err := s.terminal(id)
	if err != nil || t.BioPending == nil {
		return ErrNotFound
	}
	if t.Validator {
		if p == nil {
			return Invalid("the YubiKey must confirm the admin's phone")
		}
		if _, err := s.prove(*p, "validator", domainConfirmBio, id); err != nil {
			return err
		}
	}
	s.store.db.Exec(`UPDATE keys SET status = 'active' WHERE terminal = ? AND role = 'bio' AND status = 'pending'`, id)
	s.store.log("terminal.bio", id+" confirmed "+t.BioPending.Kid)
	return nil
}

// RefuseBio drops a pending bio key: the phone stays an ordinary terminal.
func (s *Service) RefuseBio(id string) error {
	res, err := s.store.db.Exec(`DELETE FROM keys WHERE terminal = ? AND role = 'bio' AND status = 'pending'`, id)
	if n, _ := res.RowsAffected(); err != nil || n == 0 {
		return ErrNotFound
	}
	s.store.log("terminal.bio", id+" refused")
	return nil
}
