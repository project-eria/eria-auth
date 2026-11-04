package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/project-eria/go-wot/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// last returns the last journal line of type typ.
func (h *house) last(typ string) Entry {
	lines, err := h.svc.store.Journal(0)
	require.NoError(h.t, err)
	for i := len(lines) - 1; i >= 0; i-- {
		if lines[i].Type == typ {
			return lines[i]
		}
	}
	h.t.Fatalf("no %s in the journal", typ)
	return Entry{}
}

// Step 5e-1: one schema, the jti from session to token, the classes.
func TestJournal(t *testing.T) {
	h := newHouse(t)
	pc, _, admin := h.bootstrapAdmin()

	// The admin's token: jti = session.rank, the session kept a year (level 0).
	c := h.claims(admin)
	sid, rank, _ := strings.Cut(c.Jti, ".")
	assert.Equal(t, "1", rank)
	open := h.last("session.open")
	assert.Equal(t, c.Jti, open.Jti)
	assert.Equal(t, "term:"+c.Term, open.Object)
	assert.Equal(t, keepLong, open.Keep)
	assert.Contains(t, open.Detail, "session "+sid)

	var s Session
	require.Equal(t, 200, h.call("POST", "/v1/sessions/renew", "", map[string]any{"session": sid,
		"proof": h.proof(pc, domainRenew, sid)}, &s))
	assert.Equal(t, sid+".2", h.claims(s.Token).Jti)
	h.now = h.now.Add(6 * time.Minute)
	assert.Equal(t, 403, h.call("POST", "/v1/sessions/renew", "", map[string]any{"session": sid,
		"proof": h.proof(pc, domainRenew, sid)}, nil))
	closed := h.last("session.close")
	assert.Equal(t, "idle", closed.Reason)
	assert.Equal(t, keepShort, closed.Keep)

	// A service proof refused is journaled, never its challenge.
	_, err := h.svc.ServiceToken("unknown-kid", "a-challenge", nil, "")
	assert.ErrorIs(t, err, ErrDenied)
	refused := h.last("proof.service")
	assert.Equal(t, "denied", refused.Result)
	assert.NotContains(t, refused.Detail, "a-challenge")

	// Purge by class and whole days: a short line goes after 30 days, a long one stays.
	h.now = h.now.Add(31 * 24 * time.Hour)
	h.svc.store.purge()
	lines, err := h.svc.store.Journal(0)
	require.NoError(t, err)
	for _, e := range lines {
		assert.Equal(t, keepLong, e.Keep, "%s should be purged", e.Type)
	}
	assert.Equal(t, open.Jti, h.last("session.open").Jti)

	// A start journaled; a database without journal comes from a backup.
	h.svc.Started()
	assert.NotContains(t, h.alert, "Restauration d'auth")
	h.svc.store.db.Exec(`DELETE FROM journal`)
	h.svc.Started()
	assert.Contains(t, h.alert, "Restauration d'auth")
}

// A document signed by another key than the app's, or from the future, is
// refused, journaled and alerted once a day.
func TestBadDocuments(t *testing.T) {
	h := newHouse(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, err := h.svc.store.db.Exec(`INSERT INTO apps (id, name, kid, raw, version, registered) VALUES ('a0', 'pool', ?, ?, 1, 1)`,
		auth.AppKID(priv), []byte(pub))
	require.NoError(t, err)
	send := func(key ed25519.PrivateKey, a auth.Ack) error {
		signed, err := auth.SignBy(key, auth.AckPrefix, a)
		require.NoError(t, err)
		signed.Kid = auth.AppKID(priv)
		body, _ := json.Marshal(signed)
		return h.svc.ReceiveAck(body)
	}
	_, forger, _ := ed25519.GenerateKey(rand.Reader)
	beat := auth.Ack{Beat: h.now.UnixMilli(), Mode: "normal", Revocation: 1}
	assert.ErrorIs(t, send(forger, beat), ErrDenied)
	assert.ErrorIs(t, send(forger, beat), ErrDenied)
	assert.Equal(t, []string{"Signature invalide : pool"}, h.alert)
	assert.Equal(t, "signature", h.last("document.refused").Reason)

	future := beat
	future.Beat = h.now.Add(time.Hour).UnixMilli()
	assert.ErrorIs(t, send(priv, future), ErrDenied)
	assert.Contains(t, h.alert, "Horodatage invraisemblable : pool")

	require.NoError(t, send(priv, beat))
	require.NoError(t, send(priv, beat))
	lines, _ := h.svc.store.Journal(0)
	acks := 0
	for _, e := range lines {
		if e.Type == "revocation.ack" {
			acks++
		}
	}
	assert.Equal(t, 1, acks, "a revocation version journaled once per app")
}
