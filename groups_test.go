package main

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func astralTD(props ...string) TDIn {
	td := TDIn{ID: "urn:eria:service:astral:1", Title: "Astral", Properties: map[string]json.RawMessage{}}
	keys := []string{}
	for _, p := range props {
		td.Properties[p] = json.RawMessage(`{"readOnly": true}`)
		keys = append(keys, "property/"+p+"/read")
	}
	td.Properties["mode"] = json.RawMessage(`{}`)
	td.Groups = []Group{
		{ID: "today", Title: "Heures du jour", Functions: keys},
		{ID: "mixed", Title: "Mêlé", Functions: []string{"property/mode/read", "property/mode/write"}},
		{ID: "again", Title: "Encore", Functions: keys[:1]},
	}
	return td
}

func TestGroups(t *testing.T) {
	h := newHouse(t)
	id := "urn:eria:service:astral:1"
	sunrise, sunset, noon := "property/today/sunrise/read", "property/today/sunset/read", "property/today/noon/read"
	view := func() (ThingRecord, GroupView) {
		th, err := h.svc.thing(id)
		require.NoError(t, err)
		require.Len(t, th.Groups, 1, "mixed operations and a function in two groups are dropped")
		return th, th.Groups[0]
	}

	require.NoError(t, h.svc.ReceiveTD(astralTD("today/sunrise", "today/sunset"), ""))
	require.NoError(t, h.svc.AdoptThing(id))
	_, g := view()
	assert.Equal(t, "Heures du jour", g.Title)
	assert.False(t, g.Individual, "no choice yet, the members agree: a group")
	assert.Equal(t, Rule{}, *g.Rule, "without a right")

	// The group's rule goes on every member; a member alone is refused.
	all := Rule{Levels: [3]int{9, 9, 9}}
	require.NoError(t, h.svc.SetGroupRule(id, "today", &all))
	th, _ := view()
	assert.Equal(t, all, th.Effective[sunrise])
	assert.Equal(t, all, th.Effective[sunset])
	assert.Error(t, h.svc.SetRule(id, "", sunrise, &Rule{Levels: [3]int{1, 1, 1}}), "set by its group")
	assert.ErrorIs(t, h.svc.SetGroupRule(id, "nope", &all), ErrNotFound)

	// A function new in the group arrives without a right, pending.
	require.NoError(t, h.svc.ReceiveTD(astralTD("today/sunrise", "today/sunset", "today/noon"), ""))
	th, g = view()
	assert.Equal(t, []string{noon}, g.Pending)
	assert.NotContains(t, th.Effective, noon, "an app update never opens a function alone")
	require.NoError(t, h.svc.SettlePending(id, "today", noon, true))
	th, g = view()
	assert.Empty(t, g.Pending)
	assert.Equal(t, all, th.Effective[noon])
	assert.ErrorIs(t, h.svc.SettlePending(id, "today", noon, true), ErrNotFound, "no longer pending")

	// Declined: no right, no longer pending.
	require.NoError(t, h.svc.ReceiveTD(astralTD("today/sunrise", "today/sunset", "today/noon", "today/midnight"), ""))
	require.NoError(t, h.svc.SettlePending(id, "today", "property/today/midnight/read", false))
	th, g = view()
	assert.Empty(t, g.Pending)
	assert.NotContains(t, th.Effective, "property/today/midnight/read")

	// Function by function: each keeps its rule and can change.
	require.NoError(t, h.svc.SetGroupRule(id, "today", nil))
	th, g = view()
	assert.True(t, g.Individual)
	assert.Nil(t, g.Rule)
	assert.Equal(t, all, th.Effective[sunrise])
	require.NoError(t, h.svc.SetRule(id, "", sunrise, &Rule{Levels: [3]int{9, 9, 1}}))
}

func TestGroupRuleChecked(t *testing.T) {
	h := newHouse(t)
	td := TDIn{ID: "urn:eria:x:1", Title: "X", Actions: map[string]json.RawMessage{"a": nil, "b": nil},
		Groups: []Group{{ID: "cmds", Title: "Commandes", Functions: []string{"action/a/invoke", "action/b/invoke"}}}}
	require.NoError(t, h.svc.ReceiveTD(td, ""))
	require.NoError(t, h.svc.AdoptThing(td.ID))
	assert.Error(t, h.svc.SetGroupRule(td.ID, "cmds", &Rule{Levels: [3]int{9, 9, 9}}), "a command needs confirm_when")
	require.NoError(t, h.svc.SetGroupRule(td.ID, "cmds", &Rule{Levels: [3]int{1, 1, 0}, Confirm: "never"}))
}
