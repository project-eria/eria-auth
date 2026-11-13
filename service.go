package main

import (
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/project-eria/go-wot/auth"
	"github.com/project-eria/go-wot/auth/authz"
)

// Durations of AUTH-DESIGN §1.2, §3.2, §3.4, §3.5.
const (
	tokenTTL         = 5 * time.Minute
	terminalTokenTTL = 72 * time.Hour
	enrollTTL        = 10 * time.Minute
	adminRequestTTL  = 5 * time.Minute
	bootstrapTTL     = 10 * time.Minute
	sessionMax       = 2 * time.Hour
	maxBadCodes      = 5 // wrong enrollment codes before every open code is cancelled
)

// inactivity per terminal type, admin sessions apart (§3.2).
var inactivity = map[string]time.Duration{"fixed": 2 * time.Minute, "phone": 5 * time.Minute, "computer": 5 * time.Minute}

const adminInactivity = 5 * time.Minute

// Errors the API maps to statuses. Their text never says which part of a
// credential was wrong.
var (
	ErrDenied   = errors.New("denied")
	ErrNotFound = errors.New("not found")
	ErrInvalid  = errors.New("invalid request")
)

// RetryError tells the terminal to wait before the next PIN (§3.3).
type RetryError struct{ Wait time.Duration }

func (e *RetryError) Error() string { return fmt.Sprintf("retry after %s", e.Wait) }

// Service is auth: it checks people and terminals and issues tokens.
type Service struct {
	store      *Store
	hasher     Hasher
	key        ed25519.PrivateKey
	kid        string
	aud        string
	challenges *auth.Challenges
	deploy     []auth.PublicKey   // deployment keys: they register the app keys
	statesApp  string             // the app whose signed states auth takes (§2.5)
	notify     func(title string) // ntfy alert, fixed title per type (§4.5)
	mu         sync.Mutex         // guards badCodes and orders
	badCodes   []time.Time
	orders     map[string]*pendingOrder // orders to the coordinator, waiting for the phone
	floodAt    time.Time                // last « too many requests » alert, one per 10 min
	newAt      time.Time                // last « new device » alert, one per 10 min
	relayToken map[string]int64         // last service token of each eria-ui-server, unix
	acks       map[string]*ackSeen      // last acknowledgement of each app (watch.go)
	alerted    map[string]time.Time     // last alert by "<kind>:<app>"
	burst      bool                     // the « several isolated » alert is on
	certExpiry time.Time                // of auth's TLS certificate, in the daily summary
}

func NewService(store *Store, pepper []byte, key ed25519.PrivateKey, aud string) *Service {
	pub, _ := auth.ParsePublicKey(auth.Ed25519, key.Public().(ed25519.PublicKey))
	return &Service{store: store, hasher: Hasher{pepper}, key: key, kid: pub.KID(), aud: aud,
		challenges: auth.NewChallenges(time.Minute, 4096), notify: func(string) {}, relayToken: map[string]int64{},
		orders: map[string]*pendingOrder{}, acks: map[string]*ackSeen{}, alerted: map[string]time.Time{}}
}

func (s *Service) now() time.Time { return s.store.now() }

// --- Keys and challenges ---

type keyRecord struct {
	pub      auth.PublicKey
	role     string
	terminal string // "" for a validator key
	status   string
}

// validatorPhone: the bio key of an active phone the admin made a validator
// (§3.5): it signs the admin's requests like the YubiKey.
func (s *Service) validatorPhone(k keyRecord) bool {
	if k.role != "bio" || k.terminal == "" {
		return false
	}
	var ok int
	s.store.db.QueryRow(`SELECT count(*) FROM terminals WHERE id = ? AND type = 'phone' AND status = 'active' AND validator = 1`,
		k.terminal).Scan(&ok)
	return ok == 1
}

func (s *Service) keyRecord(kid string) (keyRecord, error) {
	var alg, role, status string
	var raw []byte
	var term sql.NullString
	err := s.store.db.QueryRow(`SELECT alg, raw, role, terminal, status FROM keys WHERE kid = ?`, kid).
		Scan(&alg, &raw, &role, &term, &status)
	if err != nil {
		return keyRecord{}, ErrDenied
	}
	pub, err := auth.ParsePublicKey(auth.Alg(alg), raw)
	if err != nil {
		return keyRecord{}, ErrDenied
	}
	return keyRecord{pub, role, term.String, status}, nil
}

// Challenge issues a challenge for a registered key.
func (s *Service) Challenge(kid string) (string, error) {
	if _, err := s.keyRecord(kid); err != nil {
		return "", err
	}
	return s.challenges.Issue(kid)
}

// Proof is a challenge signed by a key: sig covers challenge ‖ domain ‖ data.
type Proof struct {
	Kid       string `json:"kid"`
	Challenge string `json:"challenge"`
	Sig       []byte `json:"sig"`
}

// prove checks p for the given key role and returns the key record.
func (s *Service) prove(p Proof, role, domain, data string) (keyRecord, error) {
	k, err := s.keyRecord(p.Kid)
	if err != nil || k.status != "active" || (k.role != role && !(role == "validator" && s.validatorPhone(k))) {
		return keyRecord{}, ErrDenied
	}
	if !s.challenges.Redeem(p.Challenge, k.pub, []byte(p.Challenge+domain+data), p.Sig) {
		return keyRecord{}, ErrDenied
	}
	return k, nil
}

// Signing domains of the proofs, so that one signature never serves another
// purpose.
const (
	domainTerminal   = "eria-terminal-v1"
	domainSession    = "eria-session-v1"
	domainRenew      = "eria-renew-v1"
	domainAdminOpen  = "eria-admin-open-v1"
	domainValidate   = "eria-admin-validate-v1"
	domainEnroll     = "eria-enroll-v1"
	domainRevokeAll  = "eria-revoke-all-v1"
	domainValidator  = "eria-add-validator-v1"
	domainPending    = "eria-validations-v1"
	domainNewBio     = "eria-new-bio-v1"
	domainBioState   = "eria-bio-state-v1"
	domainConfirmBio = "eria-confirm-bio-v1"
)

// --- Terminals ---

type Terminal struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Zone     string `json:"zone,omitempty"`
	Floor    int    `json:"floor"`
	RoomOnly bool   `json:"roomOnly"`
	Owner    int64  `json:"owner,omitempty"`
	Status   string `json:"status"`
	Enrolled int64  `json:"enrolled,omitempty"`
	Device   string `json:"device,omitempty"`
	// Validator: a phone whose bio key validates the admin's requests.
	Validator bool  `json:"validator,omitempty"`
	LastSeen  int64 `json:"lastSeen,omitempty"`
	// BioPending: a new bio key after a biometric change, waiting for the admin.
	BioPending *BioPending `json:"bioPending,omitempty"`
}

func (s *Service) terminal(id string) (Terminal, error) {
	var t Terminal
	var owner sql.NullInt64
	err := s.store.db.QueryRow(`SELECT id, name, type, zone, floor, room_only, owner, status, enrolled, device, validator, last_seen
		FROM terminals WHERE id = ?`, id).
		Scan(&t.ID, &t.Name, &t.Type, &t.Zone, &t.Floor, &t.RoomOnly, &owner, &t.Status, &t.Enrolled, &t.Device, &t.Validator, &t.LastSeen)
	if err != nil {
		return t, ErrNotFound
	}
	t.Owner = owner.Int64
	var b BioPending
	var raw []byte
	if s.store.db.QueryRow(`SELECT kid, raw, since FROM keys WHERE terminal = ? AND role = 'bio' AND status = 'pending'`, id).
		Scan(&b.Kid, &raw, &b.Since) == nil {
		b.Print, b.Key = keyPrint(raw), base64.RawURLEncoding.EncodeToString(raw)
		t.BioPending = &b
	}
	return t, nil
}

// activeTerminal returns the terminal of an identity proof, if active.
func (s *Service) activeTerminal(p Proof, domain, data string) (Terminal, error) {
	k, err := s.prove(p, "identity", domain, data)
	if err != nil {
		return Terminal{}, err
	}
	t, err := s.terminal(k.terminal)
	if err != nil || t.Status != "active" {
		return Terminal{}, ErrDenied
	}
	s.store.db.Exec(`UPDATE terminals SET last_seen = ? WHERE id = ?`, s.now().Unix(), t.ID)
	return t, nil
}

// TerminalToken is the signed-out token of an active terminal (§3.4), 72 h.
// profileExpires: an iPhone's provisioning profile (§1.2), for the summary.
func (s *Service) TerminalToken(p Proof, out bool, profileExpires string) (string, error) {
	t, err := s.activeTerminal(p, domainTerminal, "")
	if err != nil {
		return "", err
	}
	if at, err := time.Parse(time.RFC3339, profileExpires); err == nil {
		s.store.db.Exec(`UPDATE terminals SET profile_expires = ? WHERE id = ?`, at.Unix(), t.ID)
	}
	tok, _, err := s.issue(t, nil, out, terminalTokenTTL, "")
	return tok, err
}

// --- Tokens ---

// issue signs a user token for terminal t and profile p (nil: signed out).
// The level is max(profile level, terminal floor); 9 gives a terminal token.
// The token of session sid has the jti sid.<rank> (§4.5): a refusal at a
// Thing leads back to the session.
func (s *Service) issue(t Terminal, p *Profile, out bool, ttl time.Duration, sid string) (string, auth.Claims, error) {
	now := s.now()
	lvl := 9
	c := auth.Claims{Iss: "auth", Aud: s.aud, Kind: auth.KindUser, Term: t.ID, Out: &out,
		RoomOnly: t.RoomOnly, Iat: now.Unix(), Exp: now.Add(ttl).Unix(), Jti: randomID()}
	if sid != "" {
		var rank int
		s.store.db.QueryRow(`UPDATE sessions SET tokens = tokens + 1 WHERE id = ? RETURNING tokens`, sid).Scan(&rank)
		c.Jti = fmt.Sprintf("%s.%d", sid, rank)
	}
	if t.Type == "fixed" {
		c.Zone = t.Zone
	}
	if p != nil {
		lvl = p.Level
		if p.Level > 0 {
			lvl = max(p.Level, t.Floor)
		}
		if lvl < 9 {
			c.Sub = fmt.Sprintf("profil:%d", p.ID)
			c.Exp = now.Add(tokenTTL).Unix()
		}
		if lvl > 0 && lvl < 9 {
			c.Grants = s.personGrants(p.ID, t)
		}
	}
	c.Lvl = &lvl
	tok, err := auth.Sign(s.key, s.kid, c)
	return tok, c, err
}

// lookup verifies the tokens auth itself issued (admin API, blocking).
func (s *Service) lookup(kid string) (auth.PublicKey, bool) {
	pub, _ := auth.ParsePublicKey(auth.Ed25519, s.key.Public().(ed25519.PublicKey))
	return pub, kid == s.kid
}

// Caller is the authenticated holder of a token, after revocation checks.
type Caller struct {
	auth.Claims
	Profile auth.Profile
}

// authenticate checks a token presented to auth (steps 0 to 4).
func (s *Service) authenticate(token string, v authz.Verifier) (Caller, error) {
	d := authz.Authenticate(authz.Request{Mode: authz.Normal, Verifier: v, Token: token,
		Keys: s.lookup, Aud: s.aud, Now: s.now()})
	if !d.Allow {
		return Caller{}, ErrDenied
	}
	if s.revoked(d.Claims) {
		return Caller{}, ErrDenied
	}
	return Caller{d.Claims, d.Profile}, nil
}

// asAdmin requires an admin token whose session is still open.
func (s *Service) asAdmin(token string) (Caller, error) {
	c, err := s.authenticate(token, authz.AuthService)
	if err != nil || c.Profile != auth.ProfileAdmin {
		return Caller{}, ErrDenied
	}
	return c, nil
}

// --- Revocations ---

// revoke makes every token of subject issued up to now fall: used when the
// subject can get no new token (blocked, deleted, re-enrolled).
func (s *Service) revoke(subject string) { s.revokeBefore(subject, s.now().Unix()+1) }

// revokeOlder makes the tokens issued before this second fall, so that a
// session opened right after (new secret, bootstrap) keeps its token.
func (s *Service) revokeOlder(subject string) { s.revokeBefore(subject, s.now().Unix()) }

func (s *Service) revokeBefore(subject string, before int64) {
	s.store.record(Entry{Type: "revocation", Object: subject, Detail: fmt.Sprintf("before %d", before)})
	s.store.db.Exec(`INSERT INTO revocations (subject, before) VALUES (?, ?)
		ON CONFLICT (subject) DO UPDATE SET before = excluded.before`, subject, before)
	s.store.db.Exec(`INSERT INTO state (key, value) VALUES ('revocations', ?)
		ON CONFLICT (key) DO UPDATE SET value = max(value + 1, excluded.value)`, s.now().UnixMilli())
}

// CheckClock refuses to start with a clock behind the last version issued
// (§4.2): versions are times, they must never go back.
func (s *Service) CheckClock() error {
	var version int64
	s.store.db.QueryRow(`SELECT value FROM state WHERE key = 'revocations'`).Scan(&version)
	if version > s.now().UnixMilli() {
		return fmt.Errorf("last version %d is in the future", version)
	}
	return nil
}

// revocationKeep is the longest token plus a margin (§2.10).
const revocationKeep = terminalTokenTTL + 24*time.Hour

// RevocationDoc is the signed list the relays and the Things apply (§2.10):
// a versioned snapshot, replaced whole by any higher version.
func (s *Service) RevocationDoc() (string, error) {
	var version int64
	s.store.db.QueryRow(`SELECT value FROM state WHERE key = 'revocations'`).Scan(&version)
	d := auth.Doc{Iss: "auth", Aud: s.aud, Doc: auth.DocRevocation, Thing: "*",
		Version: max(version, 1), Issued: s.now().Unix()}
	rows, err := s.store.db.Query(`SELECT subject, before FROM revocations WHERE before > ? ORDER BY subject`,
		s.now().Add(-revocationKeep).Unix())
	if err != nil {
		return "", err
	}
	defer rows.Close()
	for rows.Next() {
		var r auth.Revocation
		rows.Scan(&r.Subject, &r.Before)
		d.Revoked = append(d.Revoked, r)
	}
	tok, err := auth.SignDoc(s.key, s.kid, d)
	if err == nil && len(tok) > auth.MaxDocSize {
		s.notify("Liste de révocation trop grande")
		return "", errors.New("revocation list over 4000 bytes")
	}
	return tok, err
}

// revoked is auth's own check. "term:*" spares a terminal still active with
// its key: the admin's computer, kept by « revoke every terminal » (its
// tokens fall at the Things only, renewed there on their own). A terminal
// enrolled again or unblocked since has its own entry or no key.
func (s *Service) revoked(c auth.Claims) bool {
	var n int
	s.store.db.QueryRow(`SELECT count(*) FROM revocations WHERE ? < before AND (subject = ? OR subject = ?
		OR subject = 'term:*' AND ? != '' AND NOT EXISTS (SELECT 1 FROM terminals t JOIN keys k ON k.terminal = t.id
			WHERE t.id = ? AND t.status = 'active' AND k.role = 'identity'))`,
		c.Iat, "term:"+c.Term, "sub:"+c.Sub, c.Term, c.Term).Scan(&n)
	return n > 0
}
