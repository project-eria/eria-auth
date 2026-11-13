package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/project-eria/go-wot/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAppKeys(t *testing.T) {
	h := newHouse(t)
	_, _, admin := h.bootstrapAdmin()
	deployPub, deployPriv, _ := ed25519.GenerateKey(rand.Reader)
	deploy, _ := auth.ParsePublicKey(auth.Ed25519, deployPub)
	h.svc.deploy = []auth.PublicKey{deploy}
	channel := httptest.NewServer(h.svc.ChannelHandler())
	t.Cleanup(channel.Close)
	post := func(path string, in, out any) int {
		h.t.Helper()
		saved := h.srv.URL
		h.srv.URL = channel.URL
		defer func() { h.srv.URL = saved }()
		return h.call("POST", path, "", in, out)
	}
	register := func(signer ed25519.PrivateKey, pub ed25519.PublicKey, version int64) int {
		k := auth.AppKey{App: "manager-lights", Node: "rdc", Version: version}
		if pub != nil {
			k.Pubkey = base64.RawURLEncoding.EncodeToString(pub)
		}
		signed, err := auth.SignDocument(signer, auth.AppKeyPrefix, k)
		require.NoError(t, err)
		return post("/v1/apps/keys", signed, nil)
	}
	token := func(k signerKey) (int, string) {
		var ch struct{ Challenge string }
		if status := post("/v1/service/challenge", map[string]string{"kid": k.kid}, &ch); status != 200 {
			return status, ""
		}
		var out struct{ Token string }
		status := post("/v1/service/token", map[string]any{"kid": k.kid, "challenge": ch.Challenge,
			"sig": k.sign(auth.ServiceProof(ch.Challenge, h.svc.kid))}, &out)
		return status, out.Token
	}
	edPair := func() (signerKey, ed25519.PublicKey, ed25519.PrivateKey) {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		k, _ := auth.ParsePublicKey(auth.Ed25519, pub)
		return signerKey{kid: k.KID(), sign: func(m []byte) []byte { return ed25519.Sign(priv, m) }}, pub, priv
	}
	a, aPub, aPriv := edPair()
	b, bPub, _ := edPair()

	// Only the coordinator registers a key.
	assert.Equal(t, 403, register(aPriv, aPub, 1), "signed by the app itself")
	status, _ := token(a)
	assert.Equal(t, 403, status, "unknown key")
	require.Equal(t, 200, register(deployPriv, aPub, 1))

	// The proof: a wrong signature is refused, the right one gives a guest token.
	var ch struct{ Challenge string }
	require.Equal(t, 200, post("/v1/service/challenge", map[string]string{"kid": a.kid}, &ch))
	assert.Equal(t, 403, post("/v1/service/token", map[string]any{"kid": a.kid, "challenge": ch.Challenge,
		"sig": b.sign(auth.ServiceProof(ch.Challenge, h.svc.kid))}, nil), "another key's signature")
	proofA := map[string]any{"kid": a.kid, "challenge": ch.Challenge, "sig": a.sign(auth.ServiceProof(ch.Challenge, h.svc.kid))}
	var out struct{ Token string }
	require.Equal(t, 200, post("/v1/service/token", proofA, &out), "spent at the first valid signature only")
	tokA := out.Token
	assert.Equal(t, 403, post("/v1/service/token", proofA, nil), "replayed proof")
	c := h.claims(tokA)
	assert.Equal(t, auth.KindService, c.Kind)
	assert.Equal(t, 9, *c.Lvl)
	assert.Empty(t, c.Grants, "grants come with step 4")
	assert.Equal(t, int64(5*60), c.Exp-c.Iat)
	var apps []AppOut
	require.Equal(t, 200, h.call("GET", "/v1/apps", admin, nil, &apps))
	require.Len(t, apps, 1)
	id := apps[0].ID
	assert.Equal(t, auth.AppSubject+id, c.Sub)
	assert.Equal(t, AppOut{ID: id, App: "manager-lights", Node: "rdc", Kid: a.kid, Registered: h.now.Unix(), LastToken: h.now.Unix(), Grants: []string{}}, apps[0])
	h.now = h.now.Add(time.Second)
	require.Equal(t, 200, register(deployPriv, aPub, 2), "the coordinator says it again (it restarted)")
	assert.False(t, h.svc.revoked(c), "the same key: its tokens stay")

	// The app moves: same id, the old key and its tokens fall; an old message replayed changes nothing.
	h.now = h.now.Add(time.Second)
	require.Equal(t, 200, register(deployPriv, bPub, 3))
	assert.Equal(t, 403, register(deployPriv, aPub, 2), "replayed")
	assert.True(t, h.svc.revoked(c), "the old key's token")
	status, _ = token(a)
	assert.Equal(t, 403, status)
	status, tokB := token(b)
	require.Equal(t, 200, status)
	assert.Equal(t, c.Sub, h.claims(tokB).Sub, "the identity outlives the key")
	assert.False(t, h.svc.revoked(h.claims(tokB)), "the new key's first token stays")

	// The admin cuts it off: no token, no new one until the coordinator registers a key.
	require.Equal(t, 200, h.call("POST", "/v1/apps/"+id+"/retire", admin, nil, nil))
	assert.True(t, h.svc.revoked(h.claims(tokB)))
	status, _ = token(b)
	assert.Equal(t, 403, status)
	assert.Equal(t, 404, h.call("POST", "/v1/apps/"+id+"/retire", admin, nil, nil), "already retired")
	assert.Equal(t, 403, h.call("GET", "/v1/apps", "", nil, nil), "admin only")
	assert.Contains(t, mustRevocations(t, h), "sub:"+c.Sub)
}

func mustRevocations(t *testing.T, h *house) []string {
	tok, err := h.svc.RevocationDoc()
	require.NoError(t, err)
	d, err := auth.ParseDoc(tok, h.svc.lookup, "eria-maison", auth.DocRevocation, "*")
	require.NoError(t, err)
	var subjects []string
	for _, r := range d.Revoked {
		subjects = append(subjects, r.Subject)
	}
	return subjects
}

// Step 3d: a Thing belongs to the app that signs its TD; only the states app
// publishes the states, signed, each version higher than the last.
func TestSignedTDAndStates(t *testing.T) {
	h := newHouse(t)
	_, deployPriv, _ := ed25519.GenerateKey(rand.Reader)
	deploy, _ := auth.ParsePublicKey(auth.Ed25519, deployPriv.Public().(ed25519.PublicKey))
	h.svc.deploy = []auth.PublicKey{deploy}
	h.svc.statesApp = "manager-contexts"
	require.NoError(t, h.svc.SetContexts([]Context{{ID: "away", Label: "Absent"}}))
	channel := httptest.NewServer(h.svc.ChannelHandler())
	t.Cleanup(channel.Close)
	h.srv.URL = channel.URL // the channel only
	newApp := func(name string) ed25519.PrivateKey {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		signed, _ := auth.SignDocument(deployPriv, auth.AppKeyPrefix,
			auth.AppKey{App: name, Node: "rdc", Pubkey: base64.RawURLEncoding.EncodeToString(pub), Version: 1})
		require.Equal(t, 200, h.call("POST", "/v1/apps/keys", "", signed, nil))
		return priv
	}
	lights, contexts := newApp("manager-lights"), newApp("manager-contexts")
	td := map[string]any{"id": "urn:eria:salon:1", "title": "Salon", "properties": map[string]any{"light": map[string]any{}}}
	signed := func(key ed25519.PrivateKey, prefix string, v any) auth.SignedBy {
		d, err := auth.SignBy(key, prefix, v)
		require.NoError(t, err)
		return d
	}

	assert.Equal(t, 200, h.call("POST", "/v1/things/td", "", td, nil), "a Thing nobody signed for takes a plain TD")
	assert.Equal(t, 403, h.call("POST", "/v1/things/td", "", signed(lights, auth.StatesPrefix, td), nil), "another domain")
	require.Equal(t, 200, h.call("POST", "/v1/things/td", "", signed(lights, auth.TDPrefix, td), nil))
	th, err := h.svc.thing("urn:eria:salon:1")
	require.NoError(t, err)
	assert.NotEmpty(t, th.App, "the Thing belongs to manager-lights now")
	assert.Equal(t, 403, h.call("POST", "/v1/things/td", "", td, nil), "plain TD once owned")
	assert.Equal(t, 403, h.call("POST", "/v1/things/td", "", signed(contexts, auth.TDPrefix, td), nil), "another app")
	assert.Equal(t, 200, h.call("POST", "/v1/things/td", "", signed(lights, auth.TDPrefix, td), nil))

	// Release: only once the app is cut; then the next app to sign takes them.
	apps, err := h.svc.Apps()
	require.NoError(t, err)
	assert.Equal(t, "manager-lights", apps[1].App)
	assert.Equal(t, 1, apps[1].Things)
	_, err = h.svc.ReleaseThings(apps[1].ID)
	assert.Error(t, err, "an app with a key would take them back")
	require.NoError(t, h.svc.RetireApp(apps[1].ID))
	n, err := h.svc.ReleaseThings(apps[1].ID)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.Equal(t, 200, h.call("POST", "/v1/things/td", "", signed(contexts, auth.TDPrefix, td), nil), "taken by its replacement")
	th, _ = h.svc.thing("urn:eria:salon:1")
	assert.Equal(t, apps[0].ID, th.App)

	states := func(v int64) auth.States { return auth.States{States: []string{"away"}, Version: v} }
	assert.Equal(t, 403, h.call("PUT", "/v1/states", "", []string{"away"}, nil), "plain once the states app has a key")
	assert.Equal(t, 403, h.call("PUT", "/v1/states", "", signed(lights, auth.StatesPrefix, states(1)), nil), "not the states app")
	require.Equal(t, 200, h.call("PUT", "/v1/states", "", signed(contexts, auth.StatesPrefix, states(1)), nil))
	assert.Equal(t, []string{"away"}, h.svc.activeStates())
	assert.Equal(t, 403, h.call("PUT", "/v1/states", "", signed(contexts, auth.StatesPrefix, auth.States{Version: 1}), nil), "replayed")
	assert.Equal(t, 200, h.call("PUT", "/v1/states", "", signed(contexts, auth.StatesPrefix, auth.States{Version: 2}), nil))
	assert.Empty(t, h.svc.activeStates())
}

// Step 4a: the grants the coordinator sends with the key go in the service token;
// a grant on a confirmable command shortens it to 5 min; a grant removed
// makes the app's tokens fall.
func TestAppGrants(t *testing.T) {
	h := newHouse(t)
	h.bootstrapAdmin()
	deployPub, deployPriv, _ := ed25519.GenerateKey(rand.Reader)
	deploy, _ := auth.ParsePublicKey(auth.Ed25519, deployPub)
	h.svc.deploy = []auth.PublicKey{deploy}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	key, _ := auth.ParsePublicKey(auth.Ed25519, pub)
	version := int64(0)
	register := func(grants ...string) error {
		version++
		signed, err := auth.SignDocument(deployPriv, auth.AppKeyPrefix, auth.AppKey{App: "manager-pool", Node: "rdc",
			Pubkey: base64.RawURLEncoding.EncodeToString(pub), Version: version, Grants: grants})
		require.NoError(t, err)
		return h.svc.RegisterAppKey(signed)
	}
	token := func(thing string) auth.Claims {
		ch, err := h.svc.ServiceChallenge(key.KID())
		require.NoError(t, err)
		tok, err := h.svc.ServiceToken(key.KID(), ch, ed25519.Sign(priv, auth.ServiceProof(ch, h.svc.kid)), thing)
		require.NoError(t, err)
		return h.claims(tok)
	}
	require.NoError(t, h.svc.ReceiveTD(mustTD(t, garageTD), ""))
	require.NoError(t, h.svc.AdoptThing("urn:eria:garage:1"))
	require.NoError(t, h.svc.SetZones("urn:eria:garage:1", []string{"garage"}))
	const garage = "urn:eria:garage:1"

	assert.ErrorIs(t, register("piscine:*"), ErrInvalid, "outside the grammar")
	require.NoError(t, register("room:piscine:*", "room:garage:read"))
	c := token("")
	assert.Empty(t, c.Grants, "the coordinator's token: no grants")
	assert.Empty(t, c.Thing)
	// Step 4e: the token is for one Thing, with the grants on it only;
	// the DNS-SD instance (the id without "urn:") names it too.
	c = token("eria:garage:1")
	assert.Equal(t, garage, c.Thing)
	assert.Equal(t, []string{"room:garage:read"}, c.Grants)
	assert.Equal(t, int64(5*60), c.Exp-c.Iat)
	ch, _ := h.svc.ServiceChallenge(key.KID())
	_, err := h.svc.ServiceToken(key.KID(), ch, ed25519.Sign(priv, auth.ServiceProof(ch, h.svc.kid)), "urn:eria:nowhere")
	assert.ErrorIs(t, err, ErrNotFound, "a Thing auth doesn't know")

	// A grant added: the tokens stay.
	h.now = h.now.Add(time.Second)
	require.NoError(t, register("room:piscine:*", "room:garage:read", "thing:"+garage+":invoke"))
	assert.False(t, h.svc.revoked(c))
	c = token(garage)
	require.NoError(t, register("room:piscine:*", "thing:"+garage+":read"))
	assert.True(t, h.svc.revoked(c), "a grant removed")
	h.now = h.now.Add(time.Second)
	c = token(garage)
	assert.Equal(t, []string{"thing:" + garage + ":read"}, c.Grants)
	assert.False(t, h.svc.revoked(c), "the next token carries the new set")
}

func mustTD(t *testing.T, raw string) TDIn {
	var td TDIn
	require.NoError(t, json.Unmarshal([]byte(raw), &td))
	return td
}
