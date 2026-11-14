package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Level names: seeded once (defaults without a config), edited by the admin,
// served with the interface config; level 0 and odd names refused.
func TestLevelNames(t *testing.T) {
	h := newHouse(t)
	require.NoError(t, h.svc.SeedLevels(nil))
	c, err := h.svc.Config()
	require.NoError(t, err)
	assert.Equal(t, defaultLevels, c.Levels)

	require.NoError(t, h.svc.SetLevels([]Level{{2, " Ados "}, {9, "Invité"}}))
	require.NoError(t, h.svc.SeedLevels([]Level{{1, "Ignored"}}), "seeded once only")
	c, _ = h.svc.Config()
	assert.Equal(t, []Level{{2, "Ados"}, {9, "Invité"}}, c.Levels)

	for _, bad := range [][]Level{{{0, "Admin"}}, {{10, "x"}}, {{3, ""}}, {{3, "a"}, {3, "b"}},
		{{3, "un nom bien trop long pour un niveau !"}}} {
		assert.Error(t, h.svc.SetLevels(bad), "%v", bad)
	}
	c, _ = h.svc.Config()
	assert.Len(t, c.Levels, 2, "a refused list changes nothing")
}
