package main

import (
	"fmt"
	"regexp"
	"time"

	"github.com/project-eria/go-wot/auth"
)

// Confirmation (AUTH-DESIGN §2.8): the phone signs act with its bio key
// (Face ID shows the command), auth answers a confirm token for its owner
// and this phone, 60 s, single use at the Thing. act = sha256(thing ‖
// kind/name ‖ input) is computed by the app; the Thing computes it again.

const (
	domainConfirm = "eria-confirm-v1"
	confirmTTL    = 60 * time.Second
)

var actFormat = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// Confirm checks the bio proof over act and issues the confirm token.
func (s *Service) Confirm(p Proof, act string) (string, error) {
	if !actFormat.MatchString(act) {
		return "", ErrInvalid
	}
	k, err := s.prove(p, "bio", domainConfirm, act)
	if err != nil {
		return "", err
	}
	t, err := s.terminal(k.terminal)
	if err != nil || t.Status != "active" || t.Type != "phone" || t.Owner == 0 {
		return "", ErrDenied
	}
	owner, _, err := s.profile(t.Owner)
	if err != nil || owner.Level < 1 || owner.Level > 8 {
		return "", ErrDenied
	}
	now := s.now()
	c := auth.Claims{Iss: "auth", Aud: s.aud, Kind: auth.KindConfirm,
		Sub: fmt.Sprintf("profil:%d", owner.ID), Term: t.ID, Act: act,
		Iat: now.Unix(), Exp: now.Add(confirmTTL).Unix(), Jti: randomID()}
	tok, err := auth.Sign(s.key, s.kid, c)
	if err == nil {
		s.store.record(Entry{Type: "token.confirm", Subject: c.Sub, Object: "term:" + t.ID, Jti: c.Jti, Detail: "act " + act})
	}
	return tok, err
}
