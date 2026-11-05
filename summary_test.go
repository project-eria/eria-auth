package main

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Step 5e-5: yesterday's summary, sent once each morning, even empty.
func TestSummary(t *testing.T) {
	h := newHouse(t)
	h.now = time.Date(2026, 11, 5, 5, 0, 0, 0, time.UTC)
	db := h.svc.store.db
	_, err := db.Exec(`INSERT INTO profiles (id, name, level) VALUES (1, 'Paul', 1)`)
	require.NoError(t, err)
	db.Exec(`INSERT INTO things (id, title, functions, adopted) VALUES ('urn:eria:garage:1', 'Garage', '["action/open/invoke","property/x/read"]', 1)`)
	db.Exec(`INSERT INTO terminals (id, name, type, status, last_seen) VALUES ('t1', 'Écran cuisine', 'fixed', 'active', ?)`, h.now.Add(-48*time.Hour).Unix())
	db.Exec(`INSERT INTO grants (profile, grant, expires, added) VALUES (1, 'thing:urn:eria:garage:1', ?, 0)`, h.now.Add(48*time.Hour).Unix())

	yesterday := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC).Unix()
	at := func(e Entry) { e.At = yesterday; h.svc.store.record(e) }
	at(Entry{Type: "guard.denied", Subject: "profil:1", Object: "urn:eria:garage:1", Result: "denied", Reason: "step 7"})
	at(Entry{Type: "relay.denied", Subject: "term:t1", Object: "urn:eria:garage:1", Result: "denied"})
	at(Entry{Type: "session.pin", Subject: "profil:1", Result: "denied"})
	at(Entry{Type: "guard.confirmable", Subject: "profil:1", Object: "urn:eria:garage:1", Detail: "action open outside grant:thing:urn:eria:garage:1"})
	at(Entry{Type: "guard.confirmable", Subject: "profil:1", Object: "urn:eria:garage:1", Detail: "action open"})

	h.svc.sendSummary()
	assert.Empty(t, h.alert, "not before 6:00 UTC")
	h.now = h.now.Add(time.Hour)
	h.svc.sendSummary()
	require.Len(t, h.alert, 1)
	text := h.alert[0]
	for _, want := range []string{
		"Résumé quotidien du 2026-11-04",
		"Refus : 3",
		"- par personne : Paul 2",
		"- par appareil : urn:eria:garage:1 2",
		"Commandes confirmées : 2 (dont 1 hors de la maison)",
		"- Paul : thing:urn:eria:garage:1 sur urn:eria:garage:1",
		"- urn:eria:garage:1 : 2", // no capability adopted: no default, no rule
		"- Écran cuisine",
		"accès thing:urn:eria:garage:1 de Paul le 2026-11-07",
		"Empreinte 30 j : ",
	} {
		assert.Contains(t, text, want)
	}
	assert.NotContains(t, text, "Empreinte 30 j : aucune ligne")
	h.svc.sendSummary()
	assert.Len(t, h.alert, 1, "sent once")

	// The next day, nothing happened: sent all the same, the first use not again.
	h.now = h.now.Add(24 * time.Hour)
	h.svc.sendSummary()
	require.Len(t, h.alert, 2)
	assert.True(t, strings.HasPrefix(h.alert[1], "Résumé quotidien du 2026-11-05"))
	assert.Contains(t, h.alert[1], "Refus : 0")
	assert.Contains(t, h.alert[1], "Premier usage d'un accès accordé : aucun")
}
