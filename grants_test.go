package main

import (
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Step 4c: a person's grants in their tokens, none past a floor above 1;
// 90 days at most on a confirmable command; removed, the tokens fall; a
// Thing entering a granted room alerts.
func TestPersonGrants(t *testing.T) {
	h := newHouse(t)
	pc, _, admin := h.bootstrapAdmin()
	var lea Profile
	require.Equal(t, 200, h.call("POST", "/v1/profiles", admin, map[string]any{"name": "Léa", "level": 2, "secret": "3591"}, &lea))
	path := fmt.Sprintf("/v1/profiles/%d/grants", lea.ID)
	session := func() string {
		var s Session
		require.Equal(t, 200, h.call("POST", "/v1/sessions", "", map[string]any{
			"proof": h.proof(pc, domainSession, fmt.Sprint(lea.ID)), "profile": lea.ID, "pin": "3591"}, &s))
		return s.Token
	}
	add := func(grant string, expires int64) (int, Grant) {
		var g Grant
		code := h.call("POST", path, admin, map[string]any{"grant": grant, "expires": expires}, &g)
		return code, g
	}

	code, _ := add("piscine:*", 0)
	assert.Equal(t, 400, code, "outside the grammar")
	code, _ = add("room:piscine:*", h.now.Unix()-1)
	assert.Equal(t, 400, code, "expired already")
	assert.Equal(t, 403, h.call("POST", path, "", map[string]any{"grant": "room:piscine:*"}, nil), "admin only")

	code, g := add("room:piscine:*", 0)
	require.Equal(t, 200, code)
	assert.Equal(t, int64(0), g.Expires, "never, off a confirmable command")
	assert.Equal(t, []string{"room:piscine:*"}, h.claims(session()).Grants)
	assert.Nil(t, h.svc.personGrants(lea.ID, Terminal{Floor: 3}), "a floor above 1 carries no grant")

	// The garage's open is confirmable: 90 days at most.
	require.NoError(t, h.svc.ReceiveTD(mustTD(t, garageTD), ""))
	require.NoError(t, h.svc.AdoptThing("urn:eria:garage:1"))
	code, g = add("thing:urn:eria:garage:1:invoke", h.now.Add(365*24*time.Hour).Unix())
	require.Equal(t, 200, code)
	assert.True(t, g.Confirmable)
	assert.Equal(t, h.now.Add(grantMaxAge).Unix(), g.Expires)
	tok := session()
	assert.Equal(t, []string{"room:piscine:*", "thing:urn:eria:garage:1:invoke"}, h.claims(tok).Grants)
	assert.Equal(t, 404, h.call("DELETE", path+"/"+url.PathEscape("room:salon:*"), admin, nil, nil))
	h.now = h.now.Add(grantMaxAge + time.Second)
	assert.Equal(t, []string{"room:piscine:*"}, h.claims(session()).Grants, "expired")
	// The admin's token is long gone: the service directly from here on.
	list, err := h.svc.ProfileGrants(lea.ID)
	require.NoError(t, err)
	assert.Len(t, list, 2, "the admin still sees it")

	// Removed: the tokens fall, the next one comes without it.
	tok = session()
	h.now = h.now.Add(time.Second)
	require.NoError(t, h.svc.RemoveGrant(lea.ID, "room:piscine:*"))
	assert.True(t, h.svc.revoked(h.claims(tok)))
	h.now = h.now.Add(time.Second)
	assert.Empty(t, h.claims(session()).Grants)
	assert.ErrorIs(t, h.svc.RemoveGrant(lea.ID, "room:piscine:*"), ErrNotFound)

	// A Thing entering a room some grant covers: the admin is alerted.
	_, err = h.svc.AddGrant(lea.ID, "room:garage:read", 0)
	require.NoError(t, err)
	require.NoError(t, h.svc.SetZones("urn:eria:garage:1", []string{"cave"}))
	assert.NotContains(t, h.alert, "Un appareil entre dans une pièce couverte par un droit")
	require.NoError(t, h.svc.SetZones("urn:eria:garage:1", []string{"cave", "garage"}))
	assert.Contains(t, h.alert, "Un appareil entre dans une pièce couverte par un droit")

	// The simulator names the grant that allowed it (step 4d): the closed
	// state needs level 1 off the garage.
	all, err := h.svc.Grants()
	require.NoError(t, err)
	assert.Equal(t, []Grant{{Profile: lea.ID, Grant: "room:garage:read", Added: h.now.Unix()},
		{Profile: lea.ID, Grant: "thing:urn:eria:garage:1:invoke", Expires: list[1].Expires, Added: list[1].Added, Confirmable: true}}, all)
	terms, err := h.svc.Terminals()
	require.NoError(t, err)
	out, err := h.svc.Simulate(SimulateIn{Terminal: terms[0].ID, Profile: lea.ID, Thing: "urn:eria:garage:1", Key: "property/closed/read"})
	require.NoError(t, err)
	assert.Equal(t, SimulateOut{Allow: true, Level: 2, Grant: "room:garage:read", WithoutStep: 7}, out)
	// An app: its accepted grants, its service token.
	_, err = h.svc.store.db.Exec(`INSERT INTO apps (id, name, kid, raw, version, registered, grants) VALUES ('a1', 'pool', 'k1', x'00', 1, 1, '["thing:urn:eria:garage:1:read"]')`)
	require.NoError(t, err)
	out, err = h.svc.Simulate(SimulateIn{App: "a1", Thing: "urn:eria:garage:1", Key: "property/closed/read"})
	require.NoError(t, err)
	assert.Equal(t, SimulateOut{Allow: true, Level: 9, Grant: "thing:urn:eria:garage:1:read", WithoutStep: 7}, out)
	out, err = h.svc.Simulate(SimulateIn{App: "a1", Thing: "urn:eria:garage:1", Key: "action/open/invoke"})
	require.NoError(t, err)
	assert.False(t, out.Allow)
}
