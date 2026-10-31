package main

import (
	"testing"

	"github.com/project-eria/go-wot/auth"
	"github.com/project-eria/go-wot/auth/authz"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfirm(t *testing.T) {
	h := newHouse(t)
	_, _, admin := h.bootstrapAdmin()
	var paul Profile
	require.Equal(t, 200, h.call("POST", "/v1/profiles", admin, map[string]any{"name": "Paul", "level": 1, "secret": "4821"}, &paul))
	phoneID, bio := edKey(t), p256Key(t)
	r := h.ask(phoneID, map[string]any{"bio": bio.in})
	var phone Terminal
	require.Equal(t, 200, h.call("POST", "/v1/requests/"+r.ID+"/enroll", admin, EnrollIn{Code: r.Code,
		Terminal: &TerminalChange{Name: "Téléphone de Paul", Type: "phone", Floor: 1, Owner: paul.ID}}, &phone))

	act, _ := authz.Act("urn:eria:garage:1", authz.Function{Kind: "action", Name: "open"}, nil)
	var out struct{ Token string }
	assert.Equal(t, 403, h.call("POST", "/v1/confirm", "", map[string]any{"proof": h.proof(phoneID, domainConfirm, act), "act": act}, nil),
		"the identity key confirms nothing: Face ID only")
	assert.Equal(t, 403, h.call("POST", "/v1/confirm", "", map[string]any{"proof": h.proof(bio, domainConfirm, "other"), "act": act}, nil),
		"the signature covers this act")
	require.Equal(t, 200, h.call("POST", "/v1/confirm", "", map[string]any{"proof": h.proof(bio, domainConfirm, act), "act": act}, &out))
	c := h.claims(out.Token)
	p, err := c.Profile()
	require.NoError(t, err)
	assert.Equal(t, auth.ProfileConfirm, p)
	assert.Equal(t, act, c.Act)
	assert.Equal(t, phone.ID, c.Term)
	assert.Equal(t, "profil:"+jsonID(paul.ID), c.Sub)
	assert.LessOrEqual(t, c.Exp-c.Iat, int64(60))

	h.out = true
	assert.Equal(t, 200, h.call("POST", "/v1/confirm", "", map[string]any{"proof": h.proof(bio, domainConfirm, act), "act": act}, nil),
		"from outside too: it is the main case")
}
