package main

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig(t *testing.T) {
	h := newHouse(t)
	pc, _, admin := h.bootstrapAdmin()

	// A parent (level 1) and a child (level 2), signed in on the admin's PC.
	session := func(name string, level int, pin string) string {
		var p Profile
		require.Equal(t, 200, h.call("POST", "/v1/profiles", admin, map[string]any{"name": name, "level": level, "secret": pin}, &p))
		var s Session
		require.Equal(t, 200, h.call("POST", "/v1/sessions", "", map[string]any{
			"proof": h.proof(pc, domainSession, fmt.Sprint(p.ID)), "profile": p.ID, "pin": pin}, &s))
		return s.Token
	}
	parent, child := session("Cédric", 1, "4827"), session("Léo", 2, "3591")
	var tok struct{ Token string }
	require.Equal(t, 200, h.call("POST", "/v1/terminal-token", "", map[string]any{"proof": h.proof(pc, domainTerminal, "")}, &tok))

	var before InterfaceConfig
	require.Equal(t, 200, h.call("GET", "/v1/config", "", nil, &before))
	assert.Equal(t, 304, h.call("GET", fmt.Sprintf("/v1/config?since=%d", before.Version), "", nil, nil))

	page := Page{Title: "Salon", Elements: []Element{{ID: "e1", Type: "property", Thing: "urn:lampe", Name: "on"}}}
	assert.Equal(t, 403, h.call("POST", "/v1/pages", child, page, nil), "level 2")
	assert.Equal(t, 403, h.call("POST", "/v1/pages", tok.Token, page, nil), "a terminal token")
	h.out = true
	assert.Equal(t, 403, h.call("POST", "/v1/pages", parent, page, nil), "never from outside")
	h.out = false
	var saved Page
	require.Equal(t, 200, h.call("POST", "/v1/pages", parent, page, &saved))
	assert.Equal(t, 1, saved.Version)
	assert.Equal(t, 400, h.call("POST", "/v1/pages", admin, saved.withVersion(0), nil), "stale version")

	var after InterfaceConfig
	require.Equal(t, 200, h.call("GET", fmt.Sprintf("/v1/config?since=%d", before.Version), "", nil, &after))
	assert.Len(t, after.Pages, 1)

	// The start page is the page editors'; the other settings the admin's.
	assert.Equal(t, 403, h.call("PUT", "/v1/config/home-page", child, map[string]string{"page": saved.ID}, nil))
	require.Equal(t, 200, h.call("PUT", "/v1/config/home-page", admin, map[string]string{"page": saved.ID}, nil))
	assert.Equal(t, 400, h.call("PUT", "/v1/config/hidden", admin, []string{"["}, nil))

	// The app reports its screen with its own token.
	require.Equal(t, 200, h.call("POST", "/v1/screen", tok.Token, map[string]string{"screen": "desktop"}, nil))
	h.call("GET", "/v1/config", "", nil, &after)
	require.Len(t, after.Terminals, 1)
	assert.Equal(t, "desktop", after.Terminals[0].DetectedScreen)
	assert.Equal(t, saved.ID, after.HomePage)

	var names []Profile
	require.Equal(t, 200, h.call("GET", "/v1/profiles/names", "", nil, &names))
	assert.Len(t, names, 2, "the admin is never offered on a sign-in screen")
	assert.Zero(t, names[0].Level)
}

func (p Page) withVersion(v int) Page { p.Version = v; return p }
