package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/project-eria/go-wot/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const garageTD = `{"id": "urn:eria:garage:1", "title": "Garage", "@type": ["GarageDoor", "Unknown"],
	"properties": {"open": {"readOnly": true}, "closed": {"readOnly": true}, "moving": {"readOnly": true},
		"light": {}},
	"actions": {"open": {}, "close": {}}}`

func TestThingTables(t *testing.T) {
	h := newHouse(t)
	_, _, admin := h.bootstrapAdmin()
	require.NoError(t, h.svc.SetContexts([]Context{{ID: "away", Label: "Absent"}}))
	channel := httptest.NewServer(h.svc.ChannelHandler())
	t.Cleanup(channel.Close)
	send := func(method, path, body, etag string) (int, string, string) {
		req, _ := http.NewRequest(method, channel.URL+path, strings.NewReader(body))
		if etag != "" {
			req.Header.Set("If-None-Match", etag)
		}
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b), resp.Header.Get("ETag")
	}
	id := "urn:eria:garage:1"
	path := "/v1/things/" + url.PathEscape(id)
	table := func() auth.Doc {
		status, tok, _ := send("GET", path+"/table", "", "")
		require.Equal(t, 200, status, tok)
		d, err := auth.ParseDoc(tok, h.svc.lookup, "eria-maison", auth.DocTable, id)
		require.NoError(t, err)
		return d
	}

	// A new Thing waits for the admin: no table.
	status, _, _ := send("POST", "/v1/things/td", garageTD, "")
	require.Equal(t, 200, status)
	assert.Contains(t, h.alert, "Nouvel appareil à classer")
	status, _, _ = send("GET", path+"/table", "", "")
	assert.Equal(t, 404, status)
	assert.Equal(t, 403, h.call("POST", path+"/adopt", "", nil, nil), "admin only")

	// Adopted: the admin's rules of GarageDoor; light is not one of its functions.
	garageModel(t, h.svc)
	require.Equal(t, 200, h.call("POST", path+"/adopt", admin, nil, nil))
	d := table()
	assert.Equal(t, Rule{Levels: [3]int{1, 1, 1}, Confirm: auth.OutsideRoom}, d.Table["action/open/invoke"])
	assert.Equal(t, Rule{Levels: [3]int{9, 1, 1}}, d.Table["property/closed/read"])
	assert.NotContains(t, d.Table, "property/light/read", "unclassified: None")

	// The admin classifies light, sets the room; a wrong rule is refused.
	require.Equal(t, 200, h.call("PUT", path+"/rules", admin, map[string]any{"key": "property/light/write",
		"rule": Rule{Levels: [3]int{9, 8, 0}, Confirm: auth.Never}}, nil))
	assert.Equal(t, 400, h.call("PUT", path+"/rules", admin, map[string]any{"key": "action/close/invoke",
		"rule": Rule{Levels: [3]int{3, 1, 1}, Confirm: auth.OutsideRoom}}, nil), "confirmed: level 1 at most")
	assert.Equal(t, 400, h.call("PUT", path+"/rules", admin, map[string]any{"key": "property/light/read",
		"rule": Rule{Levels: [3]int{9, 9, 9}, Confirm: auth.Always}}, nil), "no confirmation on a read")
	require.Equal(t, 200, h.call("PUT", path+"/zones", admin, []string{"garage"}, nil))
	d = table()
	assert.Equal(t, []string{"garage"}, d.Zones)
	assert.Equal(t, [3]int{9, 8, 0}, d.Table["property/light/write"].Levels)

	// The Thing pulls again: 304 while nothing changed.
	_, _, etag := send("GET", path+"/table", "", "")
	status, _, _ = send("GET", path+"/table", "", etag)
	assert.Equal(t, 304, status)

	// A state override only restricts, and applies while the state is active.
	assert.Equal(t, 400, h.call("PUT", path+"/rules", admin, map[string]any{"state": "away", "key": "property/closed/read",
		"rule": Rule{Levels: [3]int{9, 9, 9}}}, nil))
	require.Equal(t, 200, h.call("PUT", path+"/rules", admin, map[string]any{"state": "away", "key": "property/light/write",
		"rule": Rule{Levels: [3]int{0, 0, 0}}}, nil))
	assert.Contains(t, table().Table, "property/light/write")
	status, _, _ = send("PUT", "/v1/states", `["away"]`, "")
	require.Equal(t, 200, status)
	assert.NotContains(t, table().Table, "property/light/write", "closed while away")
	status, _, _ = send("PUT", "/v1/states", `["weekday"]`, "")
	assert.Equal(t, 200, status, "a daily context is no state")
	assert.Contains(t, table().Table, "property/light/write", "away is over")

	// Simulator: a screen in the garage, one at the entrance, signed out.
	garage := h.enroll(admin, edKey(t), TerminalChange{Name: "Écran garage", Type: "fixed", Zone: "garage", Floor: 1})
	entrance := h.enroll(admin, edKey(t), TerminalChange{Name: "Écran entrée", Type: "fixed", Zone: "entree", Floor: 1})
	var out SimulateOut
	require.Equal(t, 200, h.call("POST", "/v1/simulate", admin, SimulateIn{Terminal: garage.ID, Thing: id, Key: "property/closed/read"}, &out))
	assert.True(t, out.Allow, out.Reason)
	require.Equal(t, 200, h.call("POST", "/v1/simulate", admin, SimulateIn{Terminal: entrance.ID, Thing: id, Key: "property/closed/read"}, &out))
	assert.Equal(t, SimulateOut{Step: 7, Reason: out.Reason, Level: 9, Place: "remote", Need: out.Need}, out)
	assert.Less(t, out.Need, 9, "the level the rule asks in the house")
	require.Equal(t, 200, h.call("POST", "/v1/simulate", admin, SimulateIn{Terminal: garage.ID, Thing: id, Key: "property/light/read"}, &out))
	assert.Equal(t, 7, out.Step, "unclassified")

	// New capabilities in a later TD are flagged, the adopted ones kept.
	send("POST", "/v1/things/td", strings.Replace(garageTD, `"GarageDoor"`, `"LightBasic"`, 1), "")
	assert.Contains(t, h.alert, "Capacités d'un appareil changées")
	assert.Equal(t, Rule{Levels: [3]int{1, 1, 1}, Confirm: auth.OutsideRoom}, table().Table["action/open/invoke"])

	// A TD without @type: lists, never null, for the admin screen.
	send("POST", "/v1/things/td", `{"id": "urn:eria:tic:1", "title": "Teleinfo", "properties": {"iinst": {}}}`, "")
	var list []map[string]any
	require.Equal(t, 200, h.call("GET", "/v1/things", admin, nil, &list))
	for _, th := range list {
		assert.NotNil(t, th["seenTypes"], th["id"])
		assert.NotNil(t, th["types"], th["id"])
	}
}

// Step 5a: the signed time for a Thing's nonce, with the versions auth holds.
func TestHeartbeat(t *testing.T) {
	h := newHouse(t)
	_, err := h.svc.HeartbeatDoc("", nil)
	assert.ErrorIs(t, err, ErrInvalid, "a nonce is required")
	_, err = h.svc.HeartbeatDoc("n", make([]string, maxBeatThings+1))
	assert.ErrorIs(t, err, ErrInvalid)
	require.NoError(t, h.svc.ReceiveTD(mustTD(t, garageTD), ""))
	require.NoError(t, h.svc.ReceiveTD(TDIn{ID: "urn:eria:salon:1", Title: "Salon"}, ""))
	require.NoError(t, h.svc.AdoptThing("urn:eria:garage:1"))
	tok, err := h.svc.HeartbeatDoc("n1", []string{"urn:eria:garage:1", "urn:eria:salon:1", "urn:eria:nowhere"})
	require.NoError(t, err)
	d, err := auth.ParseDoc(tok, h.svc.lookup, "eria-maison", auth.DocHeartbeat, "urn:eria:garage:1")
	require.NoError(t, err)
	assert.Equal(t, "n1", d.Nonce)
	assert.Equal(t, h.now.UnixMilli(), d.Version)
	_, table, _ := h.svc.TableDoc("urn:eria:garage:1")
	assert.Equal(t, map[string]int64{"urn:eria:garage:1": table, "urn:eria:salon:1": 0, "urn:eria:nowhere": 0}, d.Versions.Tables)
	assert.Positive(t, d.Versions.Revocation)
}

// A property name holding a "/" (service-astral's today/sunrise) is one
// function: listed, ruled and in the table like any other.
func TestSlashedFunctionName(t *testing.T) {
	h := newHouse(t)
	td := TDIn{ID: "urn:eria:service:astral:1", Title: "Astral",
		Properties: map[string]json.RawMessage{"today/sunrise": json.RawMessage(`{"readOnly": true}`)}}
	require.NoError(t, h.svc.ReceiveTD(td, ""))
	require.NoError(t, h.svc.AdoptThing(td.ID))
	key := "property/today/sunrise/read"
	require.NoError(t, h.svc.SetRule(td.ID, "", key, &Rule{Levels: [3]int{9, 9, 9}}))
	th, err := h.svc.thing(td.ID)
	require.NoError(t, err)
	assert.Equal(t, []string{key}, th.Functions)
	assert.Equal(t, Rule{Levels: [3]int{9, 9, 9}}, th.Effective[key])

	td.Properties = map[string]json.RawMessage{"today/sun rise": json.RawMessage(`{}`)}
	assert.Error(t, h.svc.ReceiveTD(td, ""), "each segment of the name is checked")
}

// garageModel sets the rules of GarageDoor the tests expect (no rule is
// written in the code): commands for adults with confirmation outside the
// room, its state read in the house by adults.
func garageModel(t *testing.T, s *Service) {
	cmd := Rule{Levels: [3]int{1, 1, 1}, Confirm: auth.OutsideRoom}
	state := Rule{Levels: [3]int{9, 1, 1}}
	for key, r := range map[string]*Rule{"action/open/invoke": &cmd, "action/close/invoke": &cmd,
		"property/open/read": &state, "property/closed/read": &state, "property/moving/read": &state} {
		require.NoError(t, s.SetModelRule("GarageDoor", key, r))
	}
}
