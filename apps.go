package main

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/project-eria/go-wot/auth"
)

// App keys and service tokens (AUTH-DESIGN §1.3, step 3a). The master
// registers each app's key with a message signed by the deployment key;
// auth gives the app an id, the sub of its tokens (app:<id>), kept when the
// app moves to a new key. The app proves its key on the Things channel and
// gets a service token: an invited guest, plus its grants (step 4).

// AppOut is an app as the admin screens show it.
type AppOut struct {
	ID         string `json:"id"`
	App        string `json:"app"`
	Node       string `json:"node"`
	Kid        string `json:"kid"` // "" once retired
	Registered int64  `json:"registered"`
	LastToken  int64  `json:"lastToken"`
}

// RegisterAppKey applies an AppKey signed by a deployment key (JSON of
// auth.Signed). A new key replaces the app's previous one: the tokens of the
// old key fall. Pubkey "" retires the app's key.
func (s *Service) RegisterAppKey(signed auth.Signed) error {
	var k auth.AppKey
	if err := signed.Open(auth.AppKeyPrefix, s.deploy, &k); err != nil || k.App == "" {
		return ErrDenied
	}
	var kid string
	var raw []byte
	if k.Pubkey != "" {
		b, err := base64.RawURLEncoding.Strict().DecodeString(k.Pubkey)
		if err != nil {
			return ErrInvalid
		}
		pub, err := auth.ParsePublicKey(auth.Ed25519, b)
		if err != nil {
			return ErrInvalid
		}
		kid, raw = pub.KID(), b
	}
	var id string
	var version int64
	err := s.store.db.QueryRow(`SELECT id, version FROM apps WHERE name = ?`, k.App).Scan(&id, &version)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if kid == "" {
			return ErrNotFound
		}
		id = randomID()
		_, err = s.store.db.Exec(`INSERT INTO apps (id, name, node, kid, raw, version, registered) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			id, k.App, k.Node, kid, raw, k.Version, s.now().Unix())
	case err != nil:
		return err
	case k.Version <= version:
		return ErrDenied // replayed or older than the key held
	default:
		_, err = s.store.db.Exec(`UPDATE apps SET node = ?, kid = ?, raw = ?, version = ?, registered = ? WHERE id = ?`,
			k.Node, kid, raw, k.Version, s.now().Unix(), id)
		if err == nil && kid == "" {
			s.revoke("sub:" + auth.AppSubject + id)
		} else if err == nil {
			s.revokeOlder("sub:" + auth.AppSubject + id) // the new key's first token stays
		}
	}
	if err != nil {
		return err // a kid already held by another app
	}
	event := "app.key"
	if kid == "" {
		event = "app.retired"
	}
	s.store.log(event, fmt.Sprintf("%s on %s, id %s, kid %s", k.App, k.Node, id, kid))
	return nil
}

// appKey returns the app holding kid.
func (s *Service) appKey(kid string) (id string, pub auth.PublicKey, err error) {
	var raw []byte
	if kid == "" || s.store.db.QueryRow(`SELECT id, raw FROM apps WHERE kid = ?`, kid).Scan(&id, &raw) != nil {
		return "", auth.PublicKey{}, ErrDenied
	}
	pub, err = auth.ParsePublicKey(auth.Ed25519, raw)
	return id, pub, err
}

// ServiceChallenge issues a challenge for a registered app key.
func (s *Service) ServiceChallenge(kid string) (string, error) {
	if _, _, err := s.appKey(kid); err != nil {
		return "", err
	}
	return s.challenges.Issue(kid)
}

// ServiceToken checks the app's signature over auth.ServiceProof and issues
// its service token.
func (s *Service) ServiceToken(kid, challenge string, sig []byte) (string, error) {
	id, pub, err := s.appKey(kid)
	if err != nil || !s.challenges.Redeem(challenge, pub, auth.ServiceProof(challenge, s.kid), sig) {
		return "", ErrDenied
	}
	now := s.now()
	s.store.db.Exec(`UPDATE apps SET last_token = ? WHERE id = ?`, now.Unix(), id)
	return s.serviceToken(auth.AppSubject+id, nil, now)
}

func (s *Service) serviceToken(sub string, grants []string, now time.Time) (string, error) {
	lvl := 9
	return auth.Sign(s.key, s.kid, auth.Claims{Iss: "auth", Aud: s.aud, Kind: auth.KindService, Sub: sub, Lvl: &lvl,
		Grants: grants, Iat: now.Unix(), Exp: now.Add(serviceTokenTTL).Unix(), Jti: randomID()})
}

// Apps lists the registered apps, for the admin.
func (s *Service) Apps() ([]AppOut, error) {
	rows, err := s.store.db.Query(`SELECT id, name, node, kid, registered, last_token FROM apps ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []AppOut{}
	for rows.Next() {
		var a AppOut
		if err := rows.Scan(&a.ID, &a.App, &a.Node, &a.Kid, &a.Registered, &a.LastToken); err != nil {
			return nil, err
		}
		list = append(list, a)
	}
	return list, rows.Err()
}

// RetireApp is the admin's way to cut an app off: its key goes, its tokens
// fall. Only a new key registered by the master brings it back.
func (s *Service) RetireApp(id string) error {
	res, err := s.store.db.Exec(`UPDATE apps SET kid = '', raw = NULL WHERE id = ? AND kid != ''`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	s.revoke("sub:" + auth.AppSubject + id)
	s.store.log("app.retired", "by the admin, id "+id)
	return nil
}
