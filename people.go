package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/project-eria/go-wot/auth"
)

// --- Profiles ---

// Profile is a person (§2.1): level 0 signs in with a passphrase, levels 1 to
// 8 with a 4-digit PIN.
type Profile struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Level int    `json:"level"`
}

func (s *Service) checkSecret(level int, secret string) error {
	if level == 0 {
		return checkPassphrase(secret)
	}
	return checkPIN(secret)
}

func (s *Service) CreateProfile(name string, level int, secret string) (Profile, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 64 || level < 0 || level > 8 {
		return Profile{}, ErrInvalid
	}
	if err := s.checkSecret(level, secret); err != nil {
		return Profile{}, err
	}
	res, err := s.store.db.Exec(`INSERT INTO profiles (name, level, secret) VALUES (?, ?, ?)`,
		name, level, s.hasher.hash(secret))
	if err != nil {
		return Profile{}, ErrInvalid
	}
	id, _ := res.LastInsertId()
	s.store.log("profile.create", fmt.Sprintf("%d %s level %d", id, name, level))
	return Profile{id, name, level}, nil
}

func (s *Service) Profiles() ([]Profile, error) {
	rows, err := s.store.db.Query(`SELECT id, name, level FROM profiles ORDER BY level, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []Profile{}
	for rows.Next() {
		var p Profile
		rows.Scan(&p.ID, &p.Name, &p.Level)
		list = append(list, p)
	}
	return list, rows.Err()
}

func (s *Service) profile(id int64) (Profile, string, error) {
	var p Profile
	var secret string
	err := s.store.db.QueryRow(`SELECT id, name, level, secret FROM profiles WHERE id = ?`, id).
		Scan(&p.ID, &p.Name, &p.Level, &secret)
	if err != nil {
		return p, "", ErrNotFound
	}
	return p, secret, nil
}

// UpdateProfile changes the name, level or secret; a new secret is checked
// against the level the profile ends with. Its sessions end.
func (s *Service) UpdateProfile(id int64, name *string, level *int, secret *string) error {
	p, _, err := s.profile(id)
	if err != nil {
		return err
	}
	if name != nil {
		p.Name = strings.TrimSpace(*name)
	}
	if level != nil {
		if (p.Level == 0) != (*level == 0) && secret == nil {
			return Invalid("a new secret is required when entering or leaving level 0")
		}
		p.Level = *level
	}
	if p.Name == "" || len(p.Name) > 64 || p.Level < 0 || p.Level > 8 {
		return ErrInvalid
	}
	if _, err := s.store.db.Exec(`UPDATE profiles SET name = ?, level = ? WHERE id = ?`, p.Name, p.Level, id); err != nil {
		return ErrInvalid
	}
	if secret != nil {
		if err := s.checkSecret(p.Level, *secret); err != nil {
			return err
		}
		s.store.db.Exec(`UPDATE profiles SET secret = ? WHERE id = ?`, s.hasher.hash(*secret), id)
	}
	s.store.db.Exec(`DELETE FROM sessions WHERE profile = ?`, id)
	s.revokeOlder(fmt.Sprintf("sub:profil:%d", id))
	s.store.log("profile.update", fmt.Sprint(id))
	return nil
}

func (s *Service) DeleteProfile(id int64) error {
	res, err := s.store.db.Exec(`DELETE FROM profiles WHERE id = ?`, id)
	if n, _ := res.RowsAffected(); err != nil || n == 0 {
		return ErrNotFound
	}
	s.revoke(fmt.Sprintf("sub:profil:%d", id))
	s.store.log("profile.delete", fmt.Sprint(id))
	return nil
}

// --- Secret attempts, one counter per terminal (§3.3) ---

// tryTerminal refuses while the terminal waits after failures, and forgets
// the failures after 24 h without one.
func (s *Service) tryTerminal(t Terminal) error {
	var failures int
	var until, last int64
	s.store.db.QueryRow(`SELECT pin_failures, pin_until, pin_last FROM terminals WHERE id = ?`, t.ID).
		Scan(&failures, &until, &last)
	now := s.now()
	if failures > 0 && now.Sub(time.Unix(last, 0)) >= 24*time.Hour {
		s.store.db.Exec(`UPDATE terminals SET pin_failures = 0, pin_until = 0 WHERE id = ?`, t.ID)
		return nil
	}
	if wait := time.Unix(until, 0).Sub(now); wait > 0 {
		return &RetryError{wait.Round(time.Second)}
	}
	return nil
}

// failTerminal counts a wrong secret: the wait doubles from 1 min to 1 h.
// The profile is never locked.
func (s *Service) failTerminal(t Terminal) error {
	var failures int
	s.store.db.QueryRow(`SELECT pin_failures FROM terminals WHERE id = ?`, t.ID).Scan(&failures)
	failures++
	wait := min(time.Minute<<min(failures-1, 6), time.Hour)
	now := s.now()
	s.store.db.Exec(`UPDATE terminals SET pin_failures = ?, pin_until = ?, pin_last = ? WHERE id = ?`,
		failures, now.Add(wait).Unix(), now.Unix(), t.ID)
	s.store.log("secret.fail", fmt.Sprintf("%s failure %d", t.ID, failures))
	if failures == 5 {
		s.notify("5 échecs de PIN : " + t.Name)
	}
	return &RetryError{wait}
}

func (s *Service) passTerminal(t Terminal) {
	s.store.db.Exec(`UPDATE terminals SET pin_failures = 0, pin_until = 0 WHERE id = ?`, t.ID)
}

// ResetCounter is the admin's manual reset of a terminal's counter.
func (s *Service) ResetCounter(id string) error {
	t, err := s.terminal(id)
	if err != nil {
		return err
	}
	s.passTerminal(t)
	s.store.log("secret.reset", id)
	return nil
}

// --- Sessions (§3.1, §3.2) ---

type Session struct {
	ID    string `json:"session"`
	Token string `json:"token"`
}

// OpenSession signs a person in on a fixed screen or a computer: identity
// proof of the terminal, then profile and PIN.
func (s *Service) OpenSession(p Proof, profileID int64, pin string, out bool) (Session, error) {
	t, err := s.activeTerminal(p, domainSession, fmt.Sprint(profileID))
	if err != nil {
		return Session{}, err
	}
	if t.Type == "phone" {
		return Session{}, ErrDenied // a phone signs in with its bio key
	}
	if err := s.tryTerminal(t); err != nil {
		return Session{}, err
	}
	prof, secret, err := s.profile(profileID)
	if err != nil || prof.Level == 0 || !s.hasher.check(pin, secret) {
		return Session{}, s.failTerminal(t)
	}
	s.passTerminal(t)
	return s.startSession(t, prof, false, out)
}

// OpenBioSession signs the owner of a phone in with its bio key (§2.5).
func (s *Service) OpenBioSession(p Proof, out bool) (Session, error) {
	k, err := s.prove(p, "bio", domainSession, "")
	if err != nil {
		return Session{}, err
	}
	t, err := s.terminal(k.terminal)
	if err != nil || t.Status != "active" || t.Owner == 0 {
		return Session{}, ErrDenied
	}
	prof, _, err := s.profile(t.Owner)
	if err != nil || prof.Level == 0 {
		return Session{}, ErrDenied
	}
	return s.startSession(t, prof, false, out)
}

func (s *Service) startSession(t Terminal, p Profile, admin bool, out bool) (Session, error) {
	id := randomID()
	now := s.now().Unix()
	if _, err := s.store.db.Exec(`INSERT INTO sessions (id, terminal, profile, admin, opened, gesture)
		VALUES (?, ?, ?, ?, ?, ?)`, id, t.ID, p.ID, admin, now, now); err != nil {
		return Session{}, err
	}
	s.store.log("session.open", fmt.Sprintf("%s profile %d admin %t", t.ID, p.ID, admin))
	tok, err := s.issue(t, &p, out, tokenTTL)
	return Session{id, tok}, err
}

// Renew issues a fresh token for an open session, on an identity proof
// (§3.1 step 5). A gesture pushes back the inactivity limit.
func (s *Service) Renew(sessionID string, p Proof, gesture bool, out bool) (Session, error) {
	t, err := s.activeTerminal(p, domainRenew, sessionID)
	if err != nil {
		return Session{}, err
	}
	var profileID, opened, last int64
	var admin bool
	err = s.store.db.QueryRow(`SELECT profile, admin, opened, gesture FROM sessions WHERE id = ? AND terminal = ?`,
		sessionID, t.ID).Scan(&profileID, &admin, &opened, &last)
	if err != nil {
		return Session{}, ErrDenied
	}
	idle := inactivity[t.Type]
	if admin {
		idle = adminInactivity
	}
	now := s.now()
	if now.Sub(time.Unix(last, 0)) > idle || now.Sub(time.Unix(opened, 0)) > sessionMax || (admin && out) {
		s.store.db.Exec(`DELETE FROM sessions WHERE id = ?`, sessionID)
		return Session{}, ErrDenied
	}
	if gesture {
		s.store.db.Exec(`UPDATE sessions SET gesture = ? WHERE id = ?`, now.Unix(), sessionID)
	}
	prof, _, err := s.profile(profileID)
	if err != nil {
		return Session{}, ErrDenied
	}
	tok, err := s.issue(t, &prof, out, tokenTTL)
	return Session{sessionID, tok}, err
}

func (s *Service) EndSession(sessionID string) {
	s.store.db.Exec(`DELETE FROM sessions WHERE id = ?`, sessionID)
}

// --- Admin session (§3.5): passphrase, then a validator's signature ---

type AdminRequest struct {
	ID       string `json:"request"`
	Terminal string `json:"terminal"` // name, shown by the validator
}

// AdminOpen checks the level 0 passphrase typed on a computer and opens a
// request that a validator key must sign. Never through the outer relay.
func (s *Service) AdminOpen(p Proof, passphrase string, out bool) (AdminRequest, error) {
	t, err := s.activeTerminal(p, domainAdminOpen, "")
	if err != nil || out || t.Type != "computer" {
		return AdminRequest{}, ErrDenied
	}
	if err := s.tryTerminal(t); err != nil {
		return AdminRequest{}, err
	}
	rows, err := s.store.db.Query(`SELECT id, secret FROM profiles WHERE level = 0`)
	if err != nil {
		return AdminRequest{}, err
	}
	var profileID int64
	for rows.Next() {
		var id int64
		var secret string
		rows.Scan(&id, &secret)
		if profileID == 0 && s.hasher.check(passphrase, secret) {
			profileID = id
		}
	}
	rows.Close()
	if profileID == 0 {
		return AdminRequest{}, s.failTerminal(t)
	}
	s.passTerminal(t)
	id := randomID()
	s.store.db.Exec(`INSERT INTO admin_requests (id, terminal, profile, expires) VALUES (?, ?, ?, ?)`,
		id, t.ID, profileID, s.now().Add(adminRequestTTL).Unix())
	s.store.log("admin.request", t.ID)
	return AdminRequest{id, t.Name}, nil
}

// AdminValidate is the validator's signature on a request: the YubiKey on
// the computer, later the admin's phone.
func (s *Service) AdminValidate(requestID string, p Proof) error {
	k, err := s.prove(p, "validator", domainValidate, requestID)
	if err != nil {
		return err
	}
	res, err := s.store.db.Exec(`UPDATE admin_requests SET validated = ? WHERE id = ? AND expires > ? AND validated = ''`,
		k.pub.KID(), requestID, s.now().Unix())
	if n, _ := res.RowsAffected(); err != nil || n == 0 {
		return ErrDenied
	}
	s.store.log("admin.validate", requestID+" by "+k.pub.KID())
	return nil
}

// AdminSession turns a validated request into an admin session, on the
// identity proof of the terminal that asked.
func (s *Service) AdminSession(requestID string, p Proof, out bool) (Session, error) {
	t, err := s.activeTerminal(p, domainAdminOpen, requestID)
	if err != nil || out {
		return Session{}, ErrDenied
	}
	var profileID int64
	err = s.store.db.QueryRow(`DELETE FROM admin_requests WHERE id = ? AND terminal = ? AND expires > ? AND validated != ''
		RETURNING profile`, requestID, t.ID, s.now().Unix()).Scan(&profileID)
	if err != nil {
		return Session{}, ErrDenied
	}
	prof, _, err := s.profile(profileID)
	if err != nil || prof.Level != 0 {
		return Session{}, ErrDenied
	}
	s.notify("Session admin ouverte : " + t.Name)
	return s.startSession(t, prof, true, false)
}

// --- Blocking a terminal (§2.10) ---

// BlockTerminal is done by the admin, or by a person of level ≤ 1 from
// another terminal. Only the admin unblocks.
func (s *Service) BlockTerminal(id string, by Caller) error {
	if by.Profile != auth.ProfileAdmin && (by.Profile != auth.ProfilePerson || *by.Lvl > 1 || by.Term == id) {
		return ErrDenied
	}
	res, err := s.store.db.Exec(`UPDATE terminals SET status = 'blocked' WHERE id = ? AND status = 'active'`, id)
	if n, _ := res.RowsAffected(); err != nil || n == 0 {
		return ErrNotFound
	}
	s.store.db.Exec(`DELETE FROM sessions WHERE terminal = ?`, id)
	s.revoke("term:" + id)
	s.store.log("terminal.block", id+" by "+by.Sub)
	s.notify("Terminal bloqué : " + id)
	return nil
}

func (s *Service) UnblockTerminal(id string) error {
	res, err := s.store.db.Exec(`UPDATE terminals SET status = 'active' WHERE id = ? AND status = 'blocked'`, id)
	if n, _ := res.RowsAffected(); err != nil || n == 0 {
		return ErrNotFound
	}
	s.store.log("terminal.unblock", id)
	return nil
}
