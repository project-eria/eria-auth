package main

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/project-eria/go-wot/auth"
)

// App keys and service tokens (AUTH-DESIGN §1.3, step 3a). The master
// registers each app's key with a message signed by the deployment key;
// auth gives the app an id, the sub of its tokens (app:<id>), kept when the
// app moves to a new key. The app proves its key on the Things channel and
// gets a service token: an invited guest, plus the grants the admin accepted
// at deployment, carried by the master's message (step 4).

// AppOut is an app as the admin screens show it.
type AppOut struct {
	ID         string   `json:"id"`
	App        string   `json:"app"`
	Node       string   `json:"node"`
	Kid        string   `json:"kid"` // "" once retired
	Registered int64    `json:"registered"`
	LastToken  int64    `json:"lastToken"`
	Things     int      `json:"things"` // Things whose TD it signed (step 3d)
	Grants     []string `json:"grants"` // accepted at its deployment (step 4)
}

// RegisterAppKey applies an AppKey signed by a deployment key (JSON of
// auth.Signed). A new key replaces the app's previous one: the tokens of the
// old key fall. Pubkey "" retires the app's key. A grant removed makes the
// app's tokens fall too: the next one carries the new set (§2.6).
func (s *Service) RegisterAppKey(signed auth.Signed) error {
	var k auth.AppKey
	if err := signed.Open(auth.AppKeyPrefix, s.deploy, &k); err != nil || k.App == "" {
		s.store.record(Entry{Type: "document.refused", Object: "app-key", Result: "denied", Reason: "signature"})
		s.alertOnce("signature:master", "Signature invalide : maître")
		return ErrDenied
	}
	if auth.ValidGrants(k.Grants) != nil {
		return ErrInvalid
	}
	if k.Grants == nil {
		k.Grants = []string{} // stored as [], like the column's default
	}
	grants := jsonText(k.Grants)
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
	var id, held, heldGrants string
	var version int64
	err := s.store.db.QueryRow(`SELECT id, version, kid, grants FROM apps WHERE name = ?`, k.App).Scan(&id, &version, &held, &heldGrants)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if kid == "" {
			return ErrNotFound
		}
		id = randomID()
		_, err = s.store.db.Exec(`INSERT INTO apps (id, name, node, kid, raw, version, registered, grants) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			id, k.App, k.Node, kid, raw, k.Version, s.now().Unix(), grants)
	case err != nil:
		return err
	case k.Version <= version:
		return ErrDenied // replayed or older than the key held
	case kid != "" && kid == held:
		// The master says it again (it restarted, or the admin accepted
		// another set of grants): its tokens stay, unless a grant went.
		_, err = s.store.db.Exec(`UPDATE apps SET node = ?, version = ?, grants = ? WHERE id = ?`, k.Node, k.Version, grants, id)
		if err != nil || grants == heldGrants {
			return err
		}
		var old []string
		json.Unmarshal([]byte(heldGrants), &old)
		if slices.ContainsFunc(old, func(g string) bool { return !slices.Contains(k.Grants, g) }) {
			// Up to the next second: a token issued this second may carry
			// the old set.
			// ponytail: the app holds a refused token until its renewal (at
			// most 10 min, guest rights only meanwhile); renew on a 401/403
			// in auth.ServiceTokens if that delay hurts.
			s.revoke("sub:" + auth.AppSubject + id)
		}
		s.store.log("app.grants", fmt.Sprintf("%s, id %s: %s", k.App, id, grants))
		return nil
	default:
		_, err = s.store.db.Exec(`UPDATE apps SET node = ?, kid = ?, raw = ?, version = ?, registered = ?, grants = ? WHERE id = ?`,
			k.Node, kid, raw, k.Version, s.now().Unix(), grants, id)
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
	s.store.log(event, fmt.Sprintf("%s on %s, id %s, kid %s, grants %s", k.App, k.Node, id, kid, grants))
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
// its service token for thing (step 4e): its TD id, or its DNS-SD instance
// (the id without "urn:"), read from the master's inventory. thing "" is the
// master's token: no grants, it only reads the inventory.
func (s *Service) ServiceToken(kid, challenge string, sig []byte, thing string) (string, error) {
	id, pub, err := s.appKey(kid)
	if err != nil {
		s.store.record(Entry{Type: "proof.service", Subject: "kid:" + kid, Result: "denied", Reason: "key"})
		return "", ErrDenied
	}
	if !s.challenges.Redeem(challenge, pub, auth.ServiceProof(challenge, s.kid), sig) {
		s.store.record(Entry{Type: "proof.service", Subject: auth.AppSubject + id, Result: "denied", Reason: "proof"})
		return "", ErrDenied
	}
	if thing != "" {
		t, err := s.findThing(thing)
		if err != nil {
			return "", err
		}
		thing = t.ID
	}
	now := s.now()
	s.store.db.Exec(`UPDATE apps SET last_token = ? WHERE id = ?`, now.Unix(), id)
	tok, c, err := s.appToken(id, thing, now)
	if err == nil {
		s.store.record(Entry{Type: "token.service", Subject: c.Sub, Object: thing, Jti: c.Jti, Detail: strings.Join(c.Grants, " ")})
	}
	return tok, err
}

// findThing finds a Thing by its TD id, or its DNS-SD instance (the id
// without "urn:", as the master's inventory gives it).
func (s *Service) findThing(thing string) (ThingRecord, error) {
	t, err := s.thing(thing)
	if errors.Is(err, ErrNotFound) {
		t, err = s.thing("urn:" + thing)
	}
	return t, err
}

// appToken is the token of app id for thing, carrying only the app's
// grants on it: smaller, and worthless at any other Thing.
func (s *Service) appToken(id, thing string, now time.Time) (string, auth.Claims, error) {
	var raw string
	s.store.db.QueryRow(`SELECT grants FROM apps WHERE id = ?`, id).Scan(&raw)
	var all, grants []string
	json.Unmarshal([]byte(raw), &all)
	if thing != "" {
		t, _ := s.thing(thing)
		for _, g := range all {
			scope, rest, _ := strings.Cut(g, ":")
			selector := rest[:strings.LastIndexByte(rest, ':')] // grammar checked at registration
			if scope == "thing" && selector == t.ID || scope == "room" && slices.Contains(t.Zones, selector) {
				grants = append(grants, g)
			}
		}
	}
	return s.serviceToken(auth.AppSubject+id, thing, grants, now)
}

func (s *Service) serviceToken(sub, thing string, grants []string, now time.Time) (string, auth.Claims, error) {
	lvl := 9
	ttl := serviceTokenTTL
	if s.grantsConfirmable(grants) {
		ttl = confirmableTokenTTL
	}
	c := auth.Claims{Iss: "auth", Aud: s.aud, Kind: auth.KindService, Sub: sub, Lvl: &lvl,
		Grants: grants, Thing: thing, Iat: now.Unix(), Exp: now.Add(ttl).Unix(), Jti: randomID()}
	tok, err := auth.Sign(s.key, s.kid, c)
	return tok, c, err
}

// grantsConfirmable tells whether an exact grant covers a confirmable
// function of today's tables: the token must then last 5 min at most, or
// step 8 refuses it. A table changed later is seen at the next token.
func (s *Service) grantsConfirmable(grants []string) bool {
	for _, g := range grants {
		scope, rest, _ := strings.Cut(g, ":")
		i := strings.LastIndexByte(rest, ':')
		if scope != "thing" || i < 0 {
			continue
		}
		t, err := s.thing(rest[:i])
		if err != nil {
			continue
		}
		for key, r := range t.Effective {
			if _, _, op := splitKey(key); op == rest[i+1:] && r.Confirm != "" && r.Confirm != auth.Never {
				return true
			}
		}
	}
	return false
}

// Apps lists the registered apps, for the admin.
func (s *Service) Apps() ([]AppOut, error) {
	rows, err := s.store.db.Query(`SELECT id, name, node, kid, registered, last_token, grants,
		(SELECT count(*) FROM things WHERE things.app = apps.id) FROM apps ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []AppOut{}
	for rows.Next() {
		var a AppOut
		var grants string
		if err := rows.Scan(&a.ID, &a.App, &a.Node, &a.Kid, &a.Registered, &a.LastToken, &grants, &a.Things); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(grants), &a.Grants)
		if a.Grants == nil {
			a.Grants = []string{}
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

// ReleaseThings frees the Things of a retired app: the next app to sign their
// TD owns them (its replacement). Refused while the app holds a key: it
// would take them back at once.
func (s *Service) ReleaseThings(id string) (int, error) {
	var kid string
	if err := s.store.db.QueryRow(`SELECT kid FROM apps WHERE id = ?`, id).Scan(&kid); err != nil {
		return 0, ErrNotFound
	}
	if kid != "" {
		return 0, Invalid("cut the app first")
	}
	res, err := s.store.db.Exec(`UPDATE things SET app = '' WHERE app = ?`, id)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	s.store.log("app.released", fmt.Sprintf("%d Things of app %s", n, id))
	return int(n), nil
}

// RelayTokens says when each eria-ui-server last got its service token
// (unix, 0: never since auth started).
func (s *Service) RelayTokens() map[string]int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return map[string]int64{"interieur": s.relayToken["interieur"], "exterieur": s.relayToken["exterieur"]}
}
