package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/project-eria/go-wot/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Step 5e-6: the admin reads a period or a session, journaled; the master's
// signed order erases whole days, never today nor twice.
func TestReadAndEraseJournal(t *testing.T) {
	h := newHouse(t)
	h.now = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	at := func(day int, e Entry) { e.At = time.Date(2026, 11, day, 10, 0, 0, 0, time.UTC).Unix(); h.svc.store.record(e) }
	at(3, Entry{Type: "session.open", Jti: "s1.1", Detail: "session s1 zone cuisine"})
	at(3, Entry{Type: "guard.denied", Jti: "s1.2", Result: "denied"})
	at(3, Entry{Type: "guard.denied", Jti: "s10.1", Result: "denied"})
	at(3, Entry{Type: "order.validated"}) // a year
	at(4, Entry{Type: "session.close", Detail: "session s1"})
	at(4, Entry{Type: "relay.connect"})

	by := Caller{Claims: auth.Claims{Sub: "profil:1", Jti: "a.1"}}
	lines, err := h.svc.ReadJournal(by, 0, 0, "s1")
	require.NoError(t, err)
	assert.Len(t, lines, 3, "open, its token's refusal, close; not s10")
	day4 := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC).Unix()
	lines, _ = h.svc.ReadJournal(by, day4, day4+86400, "")
	assert.Len(t, lines, 2)
	_, err = h.svc.ReadJournal(by, 0, day4, "")
	assert.Error(t, err, "two days at most")
	assert.Equal(t, keepLong, h.last("journal.read").Keep)
	assert.Equal(t, fmt.Sprintf("%d %d", day4, day4+86400), h.last("journal.read").Detail, "the last reading")

	deployPub, deployPriv, _ := ed25519.GenerateKey(rand.Reader)
	deploy, _ := auth.ParsePublicKey(auth.Ed25519, deployPub)
	h.svc.deploy = []auth.PublicKey{deploy}
	erase := func(e auth.JournalErase, key ed25519.PrivateKey) error {
		doc, _ := auth.SignDocument(key, auth.JournalErasePrefix, e)
		return h.svc.EraseJournal(doc)
	}
	_, forger, _ := ed25519.GenerateKey(rand.Reader)
	assert.ErrorIs(t, erase(auth.JournalErase{Until: "2026-11-03", At: h.now.Unix()}, forger), ErrDenied)
	assert.Error(t, erase(auth.JournalErase{Until: "2026-11-05", At: h.now.Unix()}, deployPriv), "never today")
	require.NoError(t, erase(auth.JournalErase{Until: "2026-11-03", At: h.now.Unix()}, deployPriv))
	assert.Error(t, erase(auth.JournalErase{Until: "2026-11-04", At: h.now.Unix()}, deployPriv), "replayed")
	left, _ := h.svc.store.journalWhere(`at < ?`, 0, day4)
	require.Len(t, left, 1, "the year line of the 3rd stays")
	assert.Equal(t, "order.validated", left[0].Type)
	assert.Equal(t, "2026-11-03", h.last("journal.erased").Object)
	require.NoError(t, erase(auth.JournalErase{Until: "2026-11-04", All: true, At: h.now.Unix() + 1}, deployPriv))
	left, _ = h.svc.store.journalWhere(`at < ?`, 0, day4+86400)
	assert.Empty(t, left)
}
