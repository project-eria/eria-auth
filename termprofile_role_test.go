package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTerminalProfileRole(t *testing.T) {
	h := newHouse(t)
	_, _, admin := h.bootstrapAdmin()

	var phone, hall TerminalProfile
	require.Equal(t, 200, h.call("POST", "/v1/terminal-profiles", admin, TerminalProfile{Name: "Téléphone", Format: "phone"}, &phone))
	assert.Equal(t, "personal", phone.Role, "a phone's default")
	require.Equal(t, 200, h.call("POST", "/v1/terminal-profiles", admin, TerminalProfile{Name: "Entrée", Format: "tablet", Role: "shared"}, &hall))
	assert.Equal(t, "shared", hall.Role)
	assert.Equal(t, 400, h.call("POST", "/v1/terminal-profiles", admin, TerminalProfile{Name: "X", Format: "tablet", Role: "kiosk"}, nil))

	hall.Role = "room"
	require.Equal(t, 200, h.call("POST", "/v1/terminal-profiles", admin, hall, &hall))
	assert.Equal(t, "room", hall.Role, "the admin changes it")
}
