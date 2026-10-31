package main

import (
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

	// Adopted: defaults of GarageDoor; light is not one of its functions.
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
	assert.Equal(t, SimulateOut{Step: 7, Reason: out.Reason, Level: 9}, out)
	require.Equal(t, 200, h.call("POST", "/v1/simulate", admin, SimulateIn{Terminal: garage.ID, Thing: id, Key: "property/light/read"}, &out))
	assert.Equal(t, 7, out.Step, "unclassified")

	// New capabilities in a later TD are flagged, the adopted ones kept.
	send("POST", "/v1/things/td", strings.Replace(garageTD, `"GarageDoor"`, `"LightBasic"`, 1), "")
	assert.Contains(t, h.alert, "Capacités d'un appareil changées")
	assert.Equal(t, Rule{Levels: [3]int{1, 1, 1}, Confirm: auth.OutsideRoom}, table().Table["action/open/invoke"])
}
