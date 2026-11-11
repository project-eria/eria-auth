package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/project-eria/go-wot/auth"
	"github.com/project-eria/go-wot/auth/authz"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// signerKey is a terminal or validator key held by a test app.
type signerKey struct {
	in   KeyIn
	kid  string
	sign func(msg []byte) []byte
}

func edKey(t *testing.T) signerKey {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	k, err := auth.ParsePublicKey(auth.Ed25519, pub)
	require.NoError(t, err)
	return signerKey{KeyIn{"ed25519", pub}, k.KID(), func(m []byte) []byte { return ed25519.Sign(priv, m) }}
}

// p256Key signs like the Secure Enclave or a YubiKey, converted to r ‖ s.
func p256Key(t *testing.T) signerKey {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	raw, _ := priv.PublicKey.Bytes()
	k, err := auth.ParsePublicKey(auth.P256, raw)
	require.NoError(t, err)
	return signerKey{KeyIn{"p256", raw}, k.KID(), func(m []byte) []byte {
		h := sha256.Sum256(m)
		r, s, _ := ecdsa.Sign(rand.Reader, priv, h[:])
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		return sig
	}}
}

type house struct {
	t     *testing.T
	svc   *Service
	srv   *httptest.Server
	now   time.Time
	out   bool
	alert []string
}

func newHouse(t *testing.T) *house {
	store, err := OpenStore(filepath.Join(t.TempDir(), "auth.db"))
	require.NoError(t, err)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	h := &house{t: t, now: time.Unix(1_800_000_000, 0)}
	store.now = func() time.Time { return h.now }
	h.svc = NewService(store, bytes.Repeat([]byte{7}, 32), key, "eria-maison")
	h.svc.notify = func(title string) { h.alert = append(h.alert, title) }
	handler := h.svc.Handler()
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r.WithContext(withOut(r.Context(), h.out)))
	}))
	t.Cleanup(h.srv.Close)
	return h
}

// call posts in (GET when nil) with an optional bearer token, decodes the
// reply into out and returns the status.
func (h *house) call(method, path, token string, in, out any) int {
	var body bytes.Buffer
	if in != nil {
		json.NewEncoder(&body).Encode(in)
	}
	req, _ := http.NewRequest(method, h.srv.URL+path, &body)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(h.t, err)
	defer resp.Body.Close()
	if out != nil {
		json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode
}

// proof asks a challenge for k and signs challenge ‖ domain ‖ data.
func (h *house) proof(k signerKey, domain, data string) Proof {
	var ch struct{ Challenge string }
	require.Equal(h.t, 200, h.call("POST", "/v1/challenge", "", map[string]string{"kid": k.kid}, &ch))
	return Proof{Kid: k.kid, Challenge: ch.Challenge, Sig: k.sign([]byte(ch.Challenge + domain + data))}
}

func (h *house) claims(token string) auth.Claims {
	c, err := auth.Parse(token, h.svc.lookup)
	require.NoError(h.t, err)
	return c
}

// bootstrapAdmin runs the bootstrap and opens an admin session validated by
// the YubiKey, as eria-ui-admin will.
func (h *house) bootstrapAdmin() (pc, yubikey signerKey, adminToken string) {
	pc, yubikey = edKey(h.t), p256Key(h.t)
	code, err := h.svc.NewBootstrapCode()
	require.NoError(h.t, err)
	in := BootstrapIn{Code: code, Passphrase: "correct horse battery", Validator: yubikey.in,
		Name: "yubikey", Computer: "PC du bureau", Identity: pc.in}
	require.Equal(h.t, 200, h.call("POST", "/v1/bootstrap", "", in, nil))
	assert.Equal(h.t, 403, h.call("POST", "/v1/bootstrap", "", in, nil), "one-time code")

	var req AdminRequest
	require.Equal(h.t, 200, h.call("POST", "/v1/admin/open", "", map[string]any{
		"proof": h.proof(pc, domainAdminOpen, ""), "passphrase": "correct horse battery"}, &req))
	assert.Equal(h.t, "PC du bureau", req.Terminal)
	assert.Equal(h.t, 403, h.call("POST", "/v1/admin/session", "", map[string]any{
		"request": req.ID, "proof": h.proof(pc, domainAdminOpen, req.ID)}, nil), "not validated yet")
	require.Equal(h.t, 200, h.call("POST", "/v1/admin/validate", "", map[string]any{
		"request": req.ID, "proof": h.proof(yubikey, domainValidate, req.ID)}, nil))
	var s Session
	require.Equal(h.t, 200, h.call("POST", "/v1/admin/session", "", map[string]any{
		"request": req.ID, "proof": h.proof(pc, domainAdminOpen, req.ID)}, &s))
	assert.Equal(h.t, 0, *h.claims(s.Token).Lvl)
	return pc, yubikey, s.Token
}

func TestAdminSession(t *testing.T) {
	h := newHouse(t)
	pc, _, admin := h.bootstrapAdmin()
	assert.Contains(t, h.alert, "Session admin ouverte : PC du bureau")

	var list []Profile
	require.Equal(t, 200, h.call("GET", "/v1/profiles", admin, nil, &list))
	assert.Len(t, list, 1)
	assert.Equal(t, 403, h.call("GET", "/v1/profiles", "", nil, nil))

	// A wrong passphrase counts on the terminal's counter.
	assert.Equal(t, 429, h.call("POST", "/v1/admin/open", "", map[string]any{
		"proof": h.proof(pc, domainAdminOpen, ""), "passphrase": "wrong horse battery"}, nil))
	assert.Equal(t, 429, h.call("POST", "/v1/admin/open", "", map[string]any{
		"proof": h.proof(pc, domainAdminOpen, ""), "passphrase": "correct horse battery"}, nil), "waits 1 min")

	// Never from outside, and the admin API refuses the outer relay.
	h.out = true
	assert.Equal(t, 403, h.call("GET", "/v1/profiles", admin, nil, nil))
}

func TestEnrollAndSessions(t *testing.T) {
	h := newHouse(t)
	_, _, admin := h.bootstrapAdmin()

	var lea Profile
	var bad map[string]string
	assert.Equal(t, 400, h.call("POST", "/v1/profiles", admin, map[string]any{"name": "Léa", "level": 2, "secret": "1234"}, &bad))
	assert.Equal(t, "this PIN is too easy to guess", bad["error"])
	require.Equal(t, 200, h.call("POST", "/v1/profiles", admin, map[string]any{"name": "Léa", "level": 2, "secret": "4827"}, &lea))

	screen := edKey(t)
	h.out = true
	assert.Equal(t, 403, h.call("POST", "/v1/requests", "", map[string]any{"identity": screen.in}, nil),
		"never through the outer relay")
	h.out = false
	r := h.ask(screen, nil)
	assert.Len(t, r.Code, codeLength)
	assert.Equal(t, 200, h.call("GET", "/v1/requests/"+r.ID, "", nil, nil), "the terminal sees its request open")
	var open []Request
	require.Equal(t, 200, h.call("GET", "/v1/requests", admin, nil, &open))
	require.Len(t, open, 1)
	assert.Empty(t, open[0].Code, "the admin never reads the code: they type it")

	var tok struct{ Token string }
	assert.Equal(t, 403, h.call("POST", "/v1/challenge", "", map[string]string{"kid": screen.kid}, nil),
		"its key is unknown until the admin types the code")
	salon := TerminalChange{Name: "Écran du salon", Type: "fixed", Zone: "salon", Floor: 1}
	var term Terminal
	require.Equal(t, 200, h.call("POST", "/v1/requests/"+r.ID+"/enroll", admin, EnrollIn{Code: strings.ToLower(r.Code), Terminal: &salon}, &term))
	assert.Equal(t, "active", term.Status)
	assert.Equal(t, 404, h.call("GET", "/v1/requests/"+r.ID, "", nil, nil), "the request is used")
	require.Equal(t, 200, h.call("POST", "/v1/terminal-token", "", map[string]any{
		"proof": h.proof(screen, domainTerminal, ""), "profileExpires": "2027-11-05T10:00:00Z"}, &tok))
	var expires int64
	h.svc.store.db.QueryRow(`SELECT profile_expires FROM terminals WHERE id = ?`, term.ID).Scan(&expires)
	assert.Equal(t, time.Date(2027, 11, 5, 10, 0, 0, 0, time.UTC).Unix(), expires, "an iPhone's profile, for the summary")
	c := h.claims(tok.Token)
	assert.Equal(t, 9, *c.Lvl)
	assert.Equal(t, "salon", c.Zone)
	assert.Empty(t, c.Sub)

	// PIN: a wrong one makes the terminal wait, the profile is never locked.
	sessionOf := func(pin string) (int, Session) {
		var s Session
		code := h.call("POST", "/v1/sessions", "", map[string]any{
			"proof": h.proof(screen, domainSession, jsonID(lea.ID)), "profile": lea.ID, "pin": pin}, &s)
		return code, s
	}
	code, _ := sessionOf("0000")
	assert.Equal(t, 429, code)
	code, _ = sessionOf("4827")
	assert.Equal(t, 429, code, "the terminal waits 1 min")
	h.now = h.now.Add(time.Minute)
	code, s := sessionOf("4827")
	require.Equal(t, 200, code)
	c = h.claims(s.Token)
	assert.Equal(t, 2, *c.Lvl)
	assert.Equal(t, "profil:"+jsonID(lea.ID), c.Sub)

	renew := func(gesture bool) int {
		return h.call("POST", "/v1/sessions/renew", "", map[string]any{"session": s.ID,
			"proof": h.proof(screen, domainRenew, s.ID), "gesture": gesture}, nil)
	}
	h.now = h.now.Add(90 * time.Second)
	assert.Equal(t, 200, renew(true))
	h.now = h.now.Add(150 * time.Second)
	assert.Equal(t, 403, renew(false), "2 min without a gesture on a fixed screen")

	// Blocking: a child cannot, the admin can; the terminal then gets nothing.
	_, s = sessionOf("4827")
	assert.Equal(t, 403, h.call("POST", "/v1/terminals/"+term.ID+"/block", s.Token, nil, nil))
	require.Equal(t, 200, h.call("POST", "/v1/terminals/"+term.ID+"/block", admin, nil, nil))
	assert.Equal(t, 403, h.call("POST", "/v1/terminal-token", "", map[string]any{
		"proof": h.proof(screen, domainTerminal, "")}, nil))
	_, err := h.svc.authenticate(s.Token, authz.Relay)
	assert.Error(t, err, "its tokens are revoked")

	// The relays learn it from the signed list.
	var list struct{ Doc string }
	require.Equal(t, 200, h.call("GET", "/v1/revocations", "", nil, &list))
	d, err := auth.ParseDoc(list.Doc, h.svc.lookup, "eria-maison", auth.DocRevocation, "urn:eria:garage")
	require.NoError(t, err)
	assert.True(t, d.Revokes(h.claims(s.Token)))
}

func jsonID(id int64) string { b, _ := json.Marshal(id); return string(b) }

// ask makes key's terminal ask to enroll; enroll is the admin typing the
// code it shows, for a new terminal.
func (h *house) ask(key signerKey, extra map[string]any) Request {
	var r Request
	in := map[string]any{"identity": key.in}
	for k, v := range extra {
		in[k] = v
	}
	require.Equal(h.t, 200, h.call("POST", "/v1/requests", "", in, &r))
	return r
}

func (h *house) enroll(admin string, key signerKey, c TerminalChange) Terminal {
	r := h.ask(key, nil)
	var t Terminal
	require.Equal(h.t, 200, h.call("POST", "/v1/requests/"+r.ID+"/enroll", admin, EnrollIn{Code: r.Code, Terminal: &c}, &t))
	return t
}

func TestBadEnrollmentCodes(t *testing.T) {
	h := newHouse(t)
	_, _, admin := h.bootstrapAdmin()
	r := h.ask(edKey(t), nil)
	other := h.ask(edKey(t), nil)
	c := TerminalChange{Name: "Tablette", Type: "fixed", Zone: "cuisine", Floor: 1}
	assert.Equal(t, 400, h.call("POST", "/v1/requests/"+r.ID+"/enroll", admin, EnrollIn{Code: other.Code, Terminal: &c}, nil),
		"another request's code never binds this one")
	for range maxBadCodes - 1 {
		assert.Equal(t, 400, h.call("POST", "/v1/requests/"+r.ID+"/enroll", admin, EnrollIn{Code: "ZZZZZ", Terminal: &c}, nil))
	}
	assert.Equal(t, 404, h.call("POST", "/v1/requests/"+r.ID+"/enroll", admin, EnrollIn{Code: r.Code, Terminal: &c}, nil),
		"every open request cancelled after 5 wrong codes")
	assert.Contains(t, h.alert, "Demandes d'enrôlement annulées")

	// Past 5 open requests, the oldest falls.
	var first Request
	for i := range maxRequests + 1 {
		if r := h.ask(edKey(t), nil); i == 0 {
			first = r
		}
	}
	assert.Equal(t, 404, h.call("GET", "/v1/requests/"+first.ID, "", nil, nil))
	var open []Request
	require.Equal(t, 200, h.call("GET", "/v1/requests", admin, nil, &open))
	assert.Len(t, open, maxRequests)
}

func TestCheckPIN(t *testing.T) {
	for _, pin := range []string{"1234", "4321", "0000", "1212", "1122", "1987", "2030", "2512", "0101", "2902", "123", "12345", "12a4"} {
		assert.Error(t, checkPIN(pin), pin)
	}
	for _, pin := range []string{"4827", "3591", "7046"} {
		assert.NoError(t, checkPIN(pin), pin)
	}
}

// TestRevokeAll: the device told at enrollment is shown; revoking every
// terminal needs the validator and spares the admin's own computer.
func TestRevokeAll(t *testing.T) {
	h := newHouse(t)
	pc, yubikey, admin := h.bootstrapAdmin()

	screen := edKey(t)
	r := h.ask(screen, map[string]any{"device": "eria-ui-app 0.4 · android\x00\n"})
	cuisine := TerminalChange{Name: "Cuisine", Type: "fixed", Zone: "cuisine", Floor: 1}
	var e Terminal
	require.Equal(t, 200, h.call("POST", "/v1/requests/"+r.ID+"/enroll", admin, EnrollIn{Code: r.Code, Terminal: &cuisine}, &e))
	h.enroll(admin, edKey(t), TerminalChange{Name: "Entrée", Type: "fixed", Zone: "entree", Floor: 1})
	pending := h.ask(edKey(t), nil)
	var list []Terminal
	require.Equal(t, 200, h.call("GET", "/v1/terminals", admin, nil, &list))
	for _, x := range list {
		if x.ID == e.ID {
			assert.Equal(t, "eria-ui-app 0.4 · android", x.Device, "kept printable")
		}
	}

	assert.Equal(t, 403, h.call("POST", "/v1/terminals/revoke-all", admin, map[string]any{
		"proof": h.proof(pc, domainRevokeAll, "")}, nil), "the validator signs it, not the computer")
	var out map[string]int
	require.Equal(t, 200, h.call("POST", "/v1/terminals/revoke-all", admin, map[string]any{
		"proof": h.proof(yubikey, domainRevokeAll, "")}, &out))
	assert.Equal(t, 2, out["revoked"])
	assert.Equal(t, 404, h.call("GET", "/v1/requests/"+pending.ID, "", nil, nil), "a request made before the incident is cancelled")
	assert.Equal(t, 403, h.call("POST", "/v1/challenge", "", map[string]string{"kid": screen.kid}, nil), "its key is gone")
	assert.Equal(t, 200, h.call("POST", "/v1/terminal-token", "", map[string]any{
		"proof": h.proof(pc, domainTerminal, "")}, nil), "the admin's computer stays")

	// One dated entry for every terminal (piste 3): the Things drop every
	// terminal's older tokens; auth keeps the admin's session open.
	doc, err := h.svc.RevocationDoc()
	require.NoError(t, err)
	d, err := auth.ParseDoc(doc, h.svc.lookup, h.svc.aud, auth.DocRevocation, "x")
	require.NoError(t, err)
	assert.Contains(t, d.Revoked, auth.Revocation{Subject: "term:*", Before: h.now.Unix() + 1})
	for _, r := range d.Revoked {
		assert.NotEqual(t, "term:"+e.ID, r.Subject, "no entry per terminal")
	}
	assert.Equal(t, 200, h.call("GET", "/v1/terminals", admin, nil, nil), "the admin's session stays at auth")
	assert.True(t, h.svc.revoked(auth.Claims{Term: e.ID, Iat: h.now.Unix()}), "a revoked screen's token falls at auth")
}

// TestReenroll: a request bound to an existing terminal replaces its key and
// makes its tokens fall; a bio key is kept on a phone only, a key binds one terminal,
// and the admin's own computer is never enrolled again from a request.
func TestReenroll(t *testing.T) {
	h := newHouse(t)
	_, _, admin := h.bootstrapAdmin()
	old := edKey(t)
	salon := h.enroll(admin, old, TerminalChange{Name: "Salon", Type: "fixed", Zone: "salon", Floor: 1})
	var tok struct{ Token string }
	require.Equal(t, 200, h.call("POST", "/v1/terminal-token", "", map[string]any{"proof": h.proof(old, domainTerminal, "")}, &tok))

	again := edKey(t)
	r := h.ask(again, nil)
	h.now = h.now.Add(time.Second) // the old token is from an earlier second
	require.Equal(t, 200, h.call("POST", "/v1/requests/"+r.ID+"/enroll", admin, EnrollIn{Code: r.Code, Existing: salon.ID}, nil))
	assert.Equal(t, 403, h.call("POST", "/v1/challenge", "", map[string]string{"kid": old.kid}, nil), "the old key is gone")
	_, err := h.svc.authenticate(tok.Token, authz.Relay)
	assert.Error(t, err, "the old key's token falls")
	assert.Equal(t, 200, h.call("POST", "/v1/terminal-token", "", map[string]any{"proof": h.proof(again, domainTerminal, "")}, nil))

	fixed := TerminalChange{Name: "Cuisine", Type: "fixed", Zone: "cuisine", Floor: 1}
	bio := p256Key(t)
	r = h.ask(edKey(t), map[string]any{"bio": bio.in})
	require.Equal(t, 200, h.call("POST", "/v1/requests/"+r.ID+"/enroll", admin, EnrollIn{Code: r.Code, Terminal: &fixed}, nil))
	assert.Equal(t, 403, h.call("POST", "/v1/challenge", "", map[string]string{"kid": bio.kid}, nil), "a bio key is dropped off a phone")
	r = h.ask(again, nil)
	assert.Equal(t, 400, h.call("POST", "/v1/requests/"+r.ID+"/enroll", admin, EnrollIn{Code: r.Code, Terminal: &fixed}, nil), "a key binds one terminal")
	r = h.ask(edKey(t), nil)
	var bad map[string]string
	assert.Equal(t, 400, h.call("POST", "/v1/requests/"+r.ID+"/enroll", admin, EnrollIn{Code: r.Code, Existing: h.claims(admin).Term}, &bad))
	assert.Equal(t, "this computer", bad["error"])
}

// TestPhoneValidator: the YubiKey makes the admin's phone a validator; the
// phone then lists the admin requests and opens one with its bio key (Face
// ID), never from outside; enrolled again, it is no validator any more.
func TestPhoneValidator(t *testing.T) {
	h := newHouse(t)
	pc, yubikey, admin := h.bootstrapAdmin()
	phoneID, bio := edKey(t), p256Key(t)
	r := h.ask(phoneID, map[string]any{"bio": bio.in})
	var phone Terminal
	require.Equal(t, 200, h.call("POST", "/v1/requests/"+r.ID+"/enroll", admin, EnrollIn{Code: r.Code,
		Terminal: &TerminalChange{Name: "Téléphone", Type: "phone", Floor: 1}}, &phone))

	list := func() (int, []Validation) {
		var l []Validation
		return h.call("POST", "/v1/validations", "", map[string]any{"proof": h.proof(phoneID, domainPending, "")}, &l), l
	}
	code, _ := list()
	assert.Equal(t, 403, code, "not a validator yet")
	assert.Equal(t, 403, h.call("POST", "/v1/terminals/"+phone.ID+"/validator", admin, map[string]any{
		"proof": h.proof(bio, domainValidator, phone.ID)}, nil), "a phone never makes itself a validator")
	require.Equal(t, 200, h.call("POST", "/v1/terminals/"+phone.ID+"/validator", admin, map[string]any{
		"proof": h.proof(yubikey, domainValidator, phone.ID)}, nil))
	assert.Contains(t, h.alert, "Nouveau téléphone validateur : Téléphone")

	var req AdminRequest
	require.Equal(t, 200, h.call("POST", "/v1/admin/open", "", map[string]any{
		"proof": h.proof(pc, domainAdminOpen, ""), "passphrase": "correct horse battery"}, &req))
	code, pending := list()
	require.Equal(t, 200, code)
	require.Len(t, pending, 1)
	assert.Equal(t, Validation{Request: req.ID, Kind: "admin-session", Origin: "PC du bureau", Expires: pending[0].Expires}, pending[0])

	h.out = true
	assert.Equal(t, 403, h.call("POST", "/v1/admin/validate", "", map[string]any{
		"request": req.ID, "proof": h.proof(bio, domainValidate, req.ID)}, nil), "never from outside the house")
	h.out = false
	require.Equal(t, 200, h.call("POST", "/v1/admin/validate", "", map[string]any{
		"request": req.ID, "proof": h.proof(bio, domainValidate, req.ID)}, nil))
	require.Equal(t, 200, h.call("POST", "/v1/admin/session", "", map[string]any{
		"request": req.ID, "proof": h.proof(pc, domainAdminOpen, req.ID)}, nil))

	// An order to the master, carried to the phone and back.
	ch := strings.Repeat("A", 43)
	assert.Equal(t, 400, h.call("POST", "/v1/orders", admin, OrderIn{Challenge: ch, Verb: "eria-admin-validate-v1", Facts: "{}"}, nil),
		"never a message that reads as one of auth's proofs")
	var o Validation
	require.Equal(t, 200, h.call("POST", "/v1/orders", admin, OrderIn{Challenge: ch, Verb: "deployApp", Facts: `{"app":"x"}`}, &o))
	_, pending = list()
	require.Len(t, pending, 1)
	assert.Equal(t, "order", pending[0].Kind)
	assert.Equal(t, "PC du bureau", pending[0].Origin)
	var sig map[string]any
	require.Equal(t, 200, h.call("GET", "/v1/orders/"+o.Request, admin, nil, &sig))
	assert.Empty(t, sig, "not signed yet")
	msg := []byte(ch + "deployApp" + `{"app":"x"}`)
	assert.Equal(t, 403, h.call("POST", "/v1/orders/"+o.Request+"/sign", "", map[string]any{"kid": yubikey.kid, "sig": yubikey.sign(msg)}, nil),
		"the YubiKey signs on the computer, not here")
	assert.Equal(t, 403, h.call("POST", "/v1/orders/"+o.Request+"/sign", "", map[string]any{"kid": bio.kid, "sig": bio.sign([]byte("other"))}, nil))
	h.out = true
	assert.Equal(t, 403, h.call("POST", "/v1/orders/"+o.Request+"/sign", "", map[string]any{"kid": bio.kid, "sig": bio.sign(msg)}, nil),
		"never from outside the house")
	h.out = false
	require.Equal(t, 200, h.call("POST", "/v1/orders/"+o.Request+"/sign", "", map[string]any{"kid": bio.kid, "sig": bio.sign(msg)}, nil))
	_, pending = list()
	assert.Empty(t, pending)
	require.Equal(t, 200, h.call("GET", "/v1/orders/"+o.Request, admin, nil, &sig))
	assert.Equal(t, bio.kid, sig["kid"])
	assert.Equal(t, 404, h.call("GET", "/v1/orders/"+o.Request, admin, nil, nil), "given once")

	// Enrolled again (a new bio key), the phone validates nothing until the admin says so again.
	r = h.ask(edKey(t), map[string]any{"bio": p256Key(t).in})
	require.Equal(t, 200, h.call("POST", "/v1/requests/"+r.ID+"/enroll", admin, EnrollIn{Code: r.Code, Existing: phone.ID}, &phone))
	assert.False(t, phone.Validator)
}

// TestNewBio: after a biometric change the phone sends a new bio key, which
// signs nothing until the admin confirms it; the admin's phone needs the
// YubiKey for that (AUTH-DESIGN §1.2).
func TestNewBio(t *testing.T) {
	h := newHouse(t)
	_, yubikey, admin := h.bootstrapAdmin()
	var lea Profile
	require.Equal(t, 200, h.call("POST", "/v1/profiles", admin, map[string]any{"name": "Léa", "level": 3, "secret": "4821"}, &lea))
	phoneID, bio := edKey(t), p256Key(t)
	r := h.ask(phoneID, map[string]any{"bio": bio.in})
	var phone Terminal
	require.Equal(t, 200, h.call("POST", "/v1/requests/"+r.ID+"/enroll", admin, EnrollIn{Code: r.Code,
		Terminal: &TerminalChange{Name: "Téléphone", Type: "phone", Floor: 1, Owner: lea.ID}}, &phone))
	require.Equal(t, 200, h.call("POST", "/v1/terminals/"+phone.ID+"/validator", admin, map[string]any{
		"proof": h.proof(yubikey, domainValidator, phone.ID)}, nil))
	state := func() BioState {
		var st BioState
		require.Equal(t, 200, h.call("POST", "/v1/bio/state", "", map[string]any{"proof": h.proof(phoneID, domainBioState, "")}, &st))
		return st
	}
	assert.Equal(t, "active", state().State)

	fresh := p256Key(t)
	h.out = true
	assert.Equal(t, 403, h.call("POST", "/v1/bio", "", map[string]any{"proof": h.proof(phoneID, domainNewBio, fresh.kid), "key": fresh.in}, nil),
		"inner relay only")
	h.out = false
	assert.Equal(t, 403, h.call("POST", "/v1/bio", "", map[string]any{"proof": h.proof(phoneID, domainNewBio, "other"), "key": fresh.in}, nil),
		"the identity key signs that very key")
	var st BioState
	require.Equal(t, 200, h.call("POST", "/v1/bio", "", map[string]any{"proof": h.proof(phoneID, domainNewBio, fresh.kid), "key": fresh.in}, &st))
	assert.Equal(t, "pending", st.State)
	assert.Len(t, st.Print, 8)
	assert.Contains(t, h.alert, "Nouvelle clé biométrique en attente : Téléphone")

	// The old key is gone, the pending one signs nothing in.
	assert.Equal(t, 403, h.call("POST", "/v1/challenge", "", map[string]string{"kid": bio.kid}, nil))
	assert.Equal(t, 403, h.call("POST", "/v1/sessions", "", map[string]any{"proof": h.proof(fresh, domainSession, ""), "bio": true}, nil))
	var list []Terminal
	require.Equal(t, 200, h.call("GET", "/v1/terminals", admin, nil, &list))
	var seen *BioPending
	for _, x := range list {
		if x.ID == phone.ID {
			seen = x.BioPending
		}
	}
	require.NotNil(t, seen)
	assert.Equal(t, st.Print, seen.Print, "the admin sees the phone's print")

	assert.Equal(t, 400, h.call("POST", "/v1/terminals/"+phone.ID+"/bio", admin, map[string]any{}, nil), "the admin's phone needs the YubiKey")
	assert.Equal(t, 403, h.call("POST", "/v1/terminals/"+phone.ID+"/bio", admin, map[string]any{
		"proof": h.proof(fresh, domainConfirmBio, phone.ID)}, nil), "never by its own key")
	require.Equal(t, 200, h.call("POST", "/v1/terminals/"+phone.ID+"/bio", admin, map[string]any{
		"proof": h.proof(yubikey, domainConfirmBio, phone.ID)}, nil))
	assert.Equal(t, "active", state().State)
	assert.Equal(t, 200, h.call("POST", "/v1/sessions", "", map[string]any{"proof": h.proof(fresh, domainSession, ""), "bio": true}, nil))

	// Refused: the phone has no bio key any more.
	other := p256Key(t)
	require.Equal(t, 200, h.call("POST", "/v1/bio", "", map[string]any{"proof": h.proof(phoneID, domainNewBio, other.kid), "key": other.in}, nil))
	require.Equal(t, 200, h.call("DELETE", "/v1/terminals/"+phone.ID+"/bio", admin, nil, nil))
	assert.Equal(t, "none", state().State)
}
