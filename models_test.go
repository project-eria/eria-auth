package main

import (
	"encoding/json"
	"net/url"
	"testing"

	"github.com/project-eria/go-wot/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A model's rule changes the default of its Things; an own rule stays
// until the admin makes the Thing follow the model again.
func TestModelRules(t *testing.T) {
	h := newHouse(t)
	_, _, admin := h.bootstrapAdmin()
	lamp := func(id string) {
		err := h.svc.ReceiveTD(TDIn{ID: id, Title: id, Types: json.RawMessage(`["LightBasic"]`),
			Properties: map[string]json.RawMessage{"on": json.RawMessage(`{"readOnly": true}`), "scene": json.RawMessage(`{"readOnly": true}`)},
			Actions:    map[string]json.RawMessage{"toggle": json.RawMessage(`{}`)}}, "")
		require.NoError(t, err)
		require.Equal(t, 200, h.call("POST", "/v1/things/"+url.PathEscape(id)+"/adopt", admin, nil, nil))
	}
	lamp("urn:eria:knx:a")
	lamp("urn:eria:knx:b")
	toggle := "action/toggle/invoke"
	defaultOf := func(id string) Rule {
		th, err := h.svc.thing(id)
		require.NoError(t, err)
		return th.Defaults[toggle]
	}
	eria := Rule{Levels: [3]int{9, 8, 0}, Confirm: auth.Never}
	assert.Equal(t, eria, defaultOf("urn:eria:knx:a"))

	// b has its own rule; the model changes for both, b keeps its own.
	own := Rule{Levels: [3]int{9, 9, 0}, Confirm: auth.Never}
	require.NoError(t, h.svc.SetRule("urn:eria:knx:b", "", toggle, &own))
	set := Rule{Levels: [3]int{9, 2, 1}, Confirm: auth.Never}
	require.Equal(t, 200, h.call("PUT", "/v1/models/LightBasic/rules", admin, map[string]any{"key": toggle, "rule": set}, nil))
	assert.Equal(t, set, defaultOf("urn:eria:knx:a"))
	b, _ := h.svc.thing("urn:eria:knx:b")
	assert.Equal(t, own, b.Rules[toggle])

	// Refused: a function out of the model, an unknown model, a bad rule.
	assert.Equal(t, 400, h.call("PUT", "/v1/models/LightBasic/rules", admin, map[string]any{"key": "property/scene/read", "rule": set}, nil))
	assert.Equal(t, 400, h.call("PUT", "/v1/models/Nope/rules", admin, map[string]any{"key": toggle, "rule": set}, nil))
	assert.Equal(t, 400, h.call("PUT", "/v1/models/LightBasic/rules", admin, map[string]any{"key": toggle,
		"rule": Rule{Levels: [3]int{9, 9, 9}, Confirm: auth.Always}}, nil))
	assert.Equal(t, 403, h.call("PUT", "/v1/models/LightBasic/rules", "", map[string]any{"key": toggle, "rule": set}, nil))

	// The list: LightBasic with its two Things and the admin's rule.
	var models []ModelView
	require.Equal(t, 200, h.call("GET", "/v1/models", admin, nil, &models))
	var lb ModelView
	for _, m := range models {
		if m.ID == "LightBasic" {
			lb = m
		}
	}
	assert.Equal(t, []string{"urn:eria:knx:a", "urn:eria:knx:b"}, lb.Things)
	require.Len(t, lb.Functions, 2)
	assert.Equal(t, toggle, lb.Functions[0].Key)
	assert.Equal(t, eria, lb.Functions[0].ERIA)
	assert.Equal(t, &set, lb.Functions[0].Rule)

	// Follow the model: b's own rule goes; the scene rule (out of model) stays.
	scene := Rule{Levels: [3]int{1, 1, 0}}
	require.NoError(t, h.svc.SetRule("urn:eria:knx:b", "", "property/scene/read", &scene))
	var out map[string]int
	require.Equal(t, 200, h.call("POST", "/v1/models/LightBasic/follow", admin, nil, &out))
	assert.Equal(t, 1, out["removed"])
	b, _ = h.svc.thing("urn:eria:knx:b")
	assert.NotContains(t, b.Rules, toggle)
	assert.Equal(t, scene, b.Rules["property/scene/read"])
	assert.Equal(t, set, b.Effective[toggle])

	// Back to ERIA's rule.
	require.Equal(t, 200, h.call("PUT", "/v1/models/LightBasic/rules", admin, map[string]any{"key": toggle, "rule": nil}, nil))
	assert.Equal(t, eria, defaultOf("urn:eria:knx:a"))
}
