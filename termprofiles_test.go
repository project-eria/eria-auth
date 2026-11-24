package main

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTerminalProfiles(t *testing.T) {
	h := newHouse(t)
	pc, _, admin := h.bootstrapAdmin()
	db := h.svc.store.db

	session := func(name string, level int, pin string) (string, int64) {
		var p Profile
		require.Equal(t, 200, h.call("POST", "/v1/profiles", admin, map[string]any{"name": name, "level": level, "secret": pin}, &p))
		var s Session
		require.Equal(t, 200, h.call("POST", "/v1/sessions", "", map[string]any{
			"proof": h.proof(pc, domainSession, fmt.Sprint(p.ID)), "profile": p.ID, "pin": pin}, &s))
		return s.Token, p.ID
	}
	parent, _ := session("Cédric", 1, "4827")
	child, childID := session("Léo", 2, "3591")

	// The default profile is there from the start; a page without profile joins it.
	var c InterfaceConfig
	require.Equal(t, 200, h.call("GET", "/v1/config", "", nil, &c))
	require.Len(t, c.TerminalProfiles, 1)
	assert.Equal(t, defaultProfile, c.TerminalProfiles[0].ID)
	var home Page
	require.Equal(t, 200, h.call("POST", "/v1/pages", parent, Page{Title: "Maison"}, &home))
	assert.Equal(t, defaultProfile, home.TerminalProfile)

	// A phone profile: made by the admin only; its pages take its theme and aspect.
	phone := TerminalProfile{Name: "Téléphone de Léo", Format: "phone", Theme: "hex", Aspect: "nuit"}
	assert.Equal(t, 403, h.call("POST", "/v1/terminal-profiles", child, phone, nil))
	assert.Equal(t, 403, h.call("POST", "/v1/terminal-profiles", parent, phone, nil), "not even a parent")
	assert.Equal(t, 400, h.call("POST", "/v1/terminal-profiles", admin, TerminalProfile{Name: "X", Format: "watch"}, nil), "no watch format")
	require.Equal(t, 200, h.call("POST", "/v1/terminal-profiles", admin, phone, &phone))
	var mine Page
	require.Equal(t, 200, h.call("POST", "/v1/pages", parent, Page{Title: "Ma chambre", TerminalProfile: phone.ID, Theme: "base"}, &mine))
	assert.Equal(t, "hex", mine.Theme, "the profile's theme")

	// The child edits the pages of the profile given to their own terminal, on it, and no other.
	assert.Equal(t, 403, h.call("POST", "/v1/pages", child, mine, nil), "not given to their terminal yet")
	db.Exec(`UPDATE terminals SET owner = ?, detected_screen = 'desktop'`, childID)
	assert.Equal(t, 400, h.call("PATCH", "/v1/terminals/"+h.pcID(pc)+"/screen", admin, map[string]string{"terminalProfile": phone.ID}, nil),
		"a phone profile on a desktop screen")
	require.Equal(t, 200, h.call("PATCH", "/v1/terminals/"+h.pcID(pc)+"/screen", admin, map[string]string{"screen": "phone", "terminalProfile": phone.ID}, nil))
	require.Equal(t, 200, h.call("POST", "/v1/pages", child, mine, &mine))
	assert.Equal(t, 403, h.call("POST", "/v1/pages", child, home, nil), "another profile")
	renamed := phone
	renamed.Name = "Mon téléphone"
	assert.Equal(t, 403, h.call("POST", "/v1/terminal-profiles", child, renamed, nil), "renaming is the admin's")

	// Its start page is one of its pages, set by who may write them.
	phone.HomePage = home.ID
	assert.Equal(t, 400, h.call("POST", "/v1/terminal-profiles", parent, phone, nil))
	phone.HomePage = mine.ID
	require.Equal(t, 200, h.call("POST", "/v1/terminal-profiles", child, phone, &phone))
	assert.Equal(t, mine.ID, phone.HomePage)

	// Deleting the profile deletes its pages and frees its terminals; the default one stays.
	assert.Equal(t, 403, h.call("DELETE", "/v1/terminal-profiles/"+phone.ID, parent, nil, nil), "the admin's")
	assert.Equal(t, 400, h.call("DELETE", "/v1/terminal-profiles/"+defaultProfile, admin, nil, nil))
	require.Equal(t, 200, h.call("DELETE", "/v1/terminal-profiles/"+phone.ID, admin, nil, nil))
	require.Equal(t, 200, h.call("GET", "/v1/config", "", nil, &c))
	assert.Len(t, c.TerminalProfiles, 1)
	assert.Len(t, c.Pages, 1)
	require.Len(t, c.Terminals, 1)
	assert.Equal(t, "", c.Terminals[0].TerminalProfile)
	assert.Equal(t, childID, c.Terminals[0].Owner)
}

// pcID is the id of the terminal enrolled with this key.
func (h *house) pcID(pc signerKey) string {
	var id string
	h.svc.store.db.QueryRow(`SELECT id FROM terminals LIMIT 1`).Scan(&id)
	return id
}
