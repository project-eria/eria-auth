package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/project-eria/go-wot/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Step 5b-2: the apps acknowledge the heartbeats; auth alerts on an app
// gone silent, several together, or one behind a document.
func TestWatchThings(t *testing.T) {
	h := newHouse(t)
	keys := map[string]ed25519.PrivateKey{}
	for i, name := range []string{"pool", "lights", "knx"} {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		keys[name] = priv
		_, err := h.svc.store.db.Exec(`INSERT INTO apps (id, name, kid, raw, version, registered) VALUES (?, ?, ?, ?, 1, 1)`,
			fmt.Sprint("a", i), name, auth.AppKID(priv), []byte(pub))
		require.NoError(t, err)
	}
	ack := func(name string, a auth.Ack) error {
		signed, err := auth.SignBy(keys[name], auth.AckPrefix, a)
		require.NoError(t, err)
		body, _ := json.Marshal(signed)
		return h.svc.ReceiveAck(body)
	}
	fresh := func() auth.Ack { return auth.Ack{Beat: h.now.UnixMilli(), Mode: "normal", Revocation: 1} }

	_, other, _ := ed25519.GenerateKey(rand.Reader)
	keys["stranger"] = other
	assert.ErrorIs(t, ack("stranger", fresh()), ErrDenied, "an unknown key")
	old := fresh()
	old.Beat = h.now.Add(-10 * time.Minute).UnixMilli()
	assert.ErrorIs(t, ack("pool", old), ErrDenied, "an old heartbeat replayed")
	for _, name := range []string{"pool", "lights", "knx"} {
		require.NoError(t, ack(name, fresh()))
	}

	// lights stays behind the revocation list; knx and pool go silent.
	h.now = h.now.Add(3 * time.Minute)
	behind := fresh()
	behind.Revocation = 0
	require.NoError(t, ack("lights", behind))
	h.svc.checkThings()
	assert.Empty(t, h.alert, "two silent, under the burst count")

	h.now = h.now.Add(13 * time.Minute)
	behind.Beat = h.now.UnixMilli()
	require.NoError(t, ack("lights", behind))
	h.svc.checkThings()
	assert.Contains(t, h.alert, "Appareil isolé : pool")
	assert.Contains(t, h.alert, "Appareil isolé : knx")
	assert.Contains(t, h.alert, "Appareil en retard de documents : lights")
	n := len(h.alert)
	h.svc.checkThings()
	assert.Len(t, h.alert, n, "once a day")

	// lights goes silent too: three together.
	h.now = h.now.Add(3 * time.Minute)
	h.svc.checkThings()
	assert.Contains(t, h.alert, "Plusieurs appareils isolés : 3")
}
