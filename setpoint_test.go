package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The set point delay of a Thing: set by the admin only, bounded, carried by
// the interfaces' config for eria-ui-server.
func TestSetpointTimeout(t *testing.T) {
	h := newHouse(t)
	_, _, admin := h.bootstrapAdmin()
	h.svc.store.db.Exec(`INSERT INTO things (id, title, adopted) VALUES ('urn:eria:volet:1', 'Volet', 1)`)
	path := "/v1/things/urn:eria:volet:1/setpoint-timeout"

	assert.Equal(t, 403, h.call("PUT", path, "", 90, nil), "admin only")
	assert.Equal(t, 400, h.call("PUT", path, admin, 3601, nil))
	assert.Equal(t, 404, h.call("PUT", "/v1/things/urn:eria:nope/setpoint-timeout", admin, 90, nil))
	require.Equal(t, 200, h.call("PUT", path, admin, 90, nil))

	var c InterfaceConfig
	require.Equal(t, 200, h.call("GET", "/v1/config", "", nil, &c))
	assert.Equal(t, map[string]int{"urn:eria:volet:1": 90}, c.SetpointTimeouts)

	// Back to the default: no longer listed.
	require.Equal(t, 200, h.call("PUT", path, admin, 0, nil))
	var after InterfaceConfig
	require.Equal(t, 200, h.call("GET", "/v1/config", "", nil, &after))
	assert.Empty(t, after.SetpointTimeouts)
}
