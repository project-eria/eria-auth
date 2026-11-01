package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
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

	// Only the master registers a key.
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
	assert.Equal(t, int64(4*3600), c.Exp-c.Iat)
	var apps []AppOut
	require.Equal(t, 200, h.call("GET", "/v1/apps", admin, nil, &apps))
	require.Len(t, apps, 1)
	id := apps[0].ID
	assert.Equal(t, auth.AppSubject+id, c.Sub)
	assert.Equal(t, AppOut{ID: id, App: "manager-lights", Node: "rdc", Kid: a.kid, Registered: h.now.Unix(), LastToken: h.now.Unix()}, apps[0])

	// The app moves: same id, the old key and its tokens fall; an old message replayed changes nothing.
	h.now = h.now.Add(time.Second)
	require.Equal(t, 200, register(deployPriv, bPub, 2))
	assert.Equal(t, 403, register(deployPriv, aPub, 1), "replayed")
	assert.True(t, h.svc.revoked(c), "the old key's token")
	status, _ = token(a)
	assert.Equal(t, 403, status)
	status, tokB := token(b)
	require.Equal(t, 200, status)
	assert.Equal(t, c.Sub, h.claims(tokB).Sub, "the identity outlives the key")
	assert.False(t, h.svc.revoked(h.claims(tokB)), "the new key's first token stays")

	// The admin cuts it off: no token, no new one until the master registers a key.
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
