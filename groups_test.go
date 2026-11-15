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
	require.NoError(t, h.svc.SetGroupRule(id, "today", &all, false))
	th, _ := view()
	assert.Equal(t, all, th.Effective[sunrise])
	assert.Equal(t, all, th.Effective[sunset])
	assert.Error(t, h.svc.SetRule(id, "", sunrise, &Rule{Levels: [3]int{1, 1, 1}}), "set by its group")
	assert.ErrorIs(t, h.svc.SetGroupRule(id, "nope", &all, false), ErrNotFound)

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
	require.NoError(t, h.svc.SetGroupRule(id, "today", nil, true))
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
	assert.Error(t, h.svc.SetGroupRule(td.ID, "cmds", &Rule{Levels: [3]int{9, 9, 9}}, false), "a command needs confirm_when")
	require.NoError(t, h.svc.SetGroupRule(td.ID, "cmds", &Rule{Levels: [3]int{1, 1, 0}, Confirm: "never"}, false))
}

// The admin's choices follow the TD: a function that left and came back is
// new again; a group gone and back has no stale rule.
func TestGroupsFollowTheTD(t *testing.T) {
	h := newHouse(t)
	id := "urn:eria:service:astral:1"
	sunset := "property/today/sunset/read"
	group := func() GroupView {
		th, err := h.svc.thing(id)
		require.NoError(t, err)
		for _, g := range th.Groups {
			if g.ID == "today" {
				return g
			}
		}
		return GroupView{}
	}
	require.NoError(t, h.svc.ReceiveTD(astralTD("today/sunrise", "today/sunset"), ""))
	require.NoError(t, h.svc.AdoptThing(id))
	require.NoError(t, h.svc.SetGroupRule(id, "today", &Rule{Levels: [3]int{9, 9, 9}}, false))

	// sunset leaves the group (still in the TD), is set alone, comes back: pending.
	td := astralTD("today/sunrise", "today/sunset")
	td.Groups[0].Functions = []string{"property/today/sunrise/read"}
	td.Groups = td.Groups[:1]
	require.NoError(t, h.svc.ReceiveTD(td, ""))
	require.NoError(t, h.svc.SetRule(id, "", sunset, &Rule{Levels: [3]int{9, 9, 1}}))
	require.NoError(t, h.svc.ReceiveTD(astralTD("today/sunrise", "today/sunset"), ""))
	assert.Equal(t, []string{sunset}, group().Pending)

	// The group gone, then back: no row left, shown from its members' rules.
	td = astralTD("today/sunrise", "today/sunset")
	td.Groups = nil
	require.NoError(t, h.svc.ReceiveTD(td, ""))
	rows, err := h.svc.groupRows(id)
	require.NoError(t, err)
	assert.Empty(t, rows)
	require.NoError(t, h.svc.ReceiveTD(astralTD("today/sunrise", "today/sunset"), ""))
	g := group()
	assert.True(t, g.Individual, "its members differ: 9·9·9 and 9·9·1")
	assert.Empty(t, g.Pending)
}

// A rule or individual, said; a regrouping is journaled.
func TestGroupCallsAndJournal(t *testing.T) {
	h := newHouse(t)
	id := "urn:eria:service:astral:1"
	regroupings := func() int {
		lines, err := h.svc.store.Journal(0)
		require.NoError(t, err)
		n := 0
		for _, l := range lines {
			if l.Type == "thing.groups" {
				n++
			}
		}
		return n
	}
	require.NoError(t, h.svc.ReceiveTD(astralTD("today/sunrise", "today/sunset"), ""))
	require.NoError(t, h.svc.AdoptThing(id))
	assert.Equal(t, 0, regroupings(), "a new Thing is journaled as thing.new")
	require.NoError(t, h.svc.ReceiveTD(astralTD("today/sunrise", "today/sunset"), ""))
	assert.Equal(t, 0, regroupings(), "the same groups again: nothing")
	td := astralTD("today/sunrise", "today/sunset")
	td.Groups[0].Title = "Heures"
	require.NoError(t, h.svc.ReceiveTD(td, ""))
	assert.Equal(t, 1, regroupings(), "a group renamed")

	all := Rule{Levels: [3]int{9, 9, 9}}
	assert.Error(t, h.svc.SetGroupRule(id, "today", nil, false), "an empty body switches nothing")
	assert.Error(t, h.svc.SetGroupRule(id, "today", &all, true))
}
