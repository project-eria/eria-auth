package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
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

// Step 5e-2: each line copied once to the coordinator, yesterday compared.
func TestJournalCopy(t *testing.T) {
	h := newHouse(t)
	var kept []string // the coordinator's lines, as sent
	lost := false     // the coordinator keeps the lines, its answer is lost
	pub := h.svc.key.Public().(ed25519.PublicKey)
	coordinator := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/appendAuthJournal", r.URL.Path)
		var in struct{ Lines, Sig, Day string }
		json.NewDecoder(r.Body).Decode(&in)
		sum := sha256.Sum256([]byte(in.Lines))
		sig, _ := base64.StdEncoding.DecodeString(in.Sig)
		require.True(t, ed25519.Verify(pub, append([]byte(JournalPrefix), sum[:]...), sig))
		var last Entry
		if len(kept) > 0 {
			json.Unmarshal([]byte(kept[len(kept)-1]), &last)
		}
		for line := range strings.Lines(in.Lines) {
			var e Entry
			json.Unmarshal([]byte(line), &e)
			if e.At > last.At || e.At == last.At && e.ID > last.ID {
				kept, last = append(kept, line), e
			}
		}
		if lost {
			lost = false
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		digests := map[string]string{}
		for _, keep := range []int{keepShort, keepLong} {
			var file string
			for _, line := range kept {
				var e Entry
				json.Unmarshal([]byte(line), &e)
				if time.Unix(e.At, 0).UTC().Format(time.DateOnly) == in.Day && e.Keep == keep {
					file += line
				}
			}
			if file != "" {
				d := sha256.Sum256([]byte(file))
				digests[strconv.Itoa(keep)] = hex.EncodeToString(d[:])
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"at": last.At, "id": last.ID, "digests": digests})
	}))
	defer coordinator.Close()
	jc, err := NewJournalCopy(h.svc, coordinator.URL+"/storeAuthBackup", coordinator.Client())
	require.NoError(t, err)

	h.svc.Started()
	require.NoError(t, jc.Sync())
	require.Len(t, kept, 1)
	// A batch sent again after a lost answer: no line twice.
	h.svc.store.record(Entry{Type: "grant.add"})
	lost = true
	assert.Error(t, jc.Sync())
	jc.known = false
	h.svc.store.record(Entry{Type: "grant.remove"})
	require.NoError(t, jc.Sync())
	lines, _ := h.svc.store.Journal(0)
	assert.Equal(t, journalText(lines), strings.Join(kept, ""))

	// The next day, yesterday is compared: the same, then altered on the coordinator.
	h.now = h.now.Add(24 * time.Hour)
	require.NoError(t, jc.Sync())
	assert.Empty(t, h.alert)
	kept[0] = strings.Replace(kept[0], "auth.start", "auth.stop", 1)
	jc.compared = "" // as after a restart
	require.NoError(t, jc.Sync())
	assert.Contains(t, h.alert, "Journal divergent")
	assert.Equal(t, "digest", h.last("journal.diverged").Reason)
}

// Step 5e-3: the coordinator's and the relay's lines, signed, taken once, their
// own types only.
func TestJournalSources(t *testing.T) {
	h := newHouse(t)
	deployPub, deployPriv, _ := ed25519.GenerateKey(rand.Reader)
	deploy, _ := auth.ParsePublicKey(auth.Ed25519, deployPub)
	h.svc.deploy = []auth.PublicKey{deploy}
	channel := httptest.NewServer(h.svc.ChannelHandler())
	defer channel.Close()
	post := func(b auth.JournalBatch, key ed25519.PrivateKey) int {
		doc, _ := auth.SignDocument(key, auth.JournalPrefix, b)
		body, _ := json.Marshal(doc)
		resp, err := http.Post(channel.URL+"/v1/journal", "application/json", strings.NewReader(string(body)))
		require.NoError(t, err)
		resp.Body.Close()
		return resp.StatusCode
	}
	order := auth.Line{At: h.now.Unix(), Type: "order.validated", Subject: "profil:1", Object: "deployApp"}
	b := auth.JournalBatch{Seq: 10, Lines: []auth.Line{order, {At: h.now.Unix(), Type: "session.open"}}}
	assert.Equal(t, 200, post(b, deployPriv))
	assert.Equal(t, 200, post(b, deployPriv), "sent again: taken once")
	got := h.last("order.validated")
	assert.Equal(t, sourceCoordinator, got.Source)
	assert.Equal(t, keepLong, got.Keep)
	assert.Equal(t, "type", h.last("document.refused").Reason, "a type of another source")
	lines, _ := h.svc.store.Journal(0)
	n := 0
	for _, e := range lines {
		if e.Type == "order.validated" {
			n++
		}
	}
	assert.Equal(t, 1, n)

	// Another key: refused, alerted; a late line keeps its own time in detail.
	_, forger, _ := ed25519.GenerateKey(rand.Reader)
	assert.Equal(t, 403, post(auth.JournalBatch{Seq: 11, Lines: []auth.Line{order}}, forger))
	assert.Contains(t, h.alert, "Signature invalide : coordinateur")
	late := order
	late.At -= 600
	assert.Equal(t, 200, post(auth.JournalBatch{Seq: 12, Lines: []auth.Line{late}}, deployPriv))
	assert.Contains(t, h.last("order.validated").Detail, "(at ")
	assert.Equal(t, h.now.Unix(), h.last("order.validated").At, "auth's time")

	// The relay, by its TLS key: relay.* only.
	relayPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	raw, _ := relayPriv.PublicKey.Bytes()
	relay, _ := auth.ParsePublicKey(auth.P256, raw)
	doc, _ := auth.SignDocumentP256(relayPriv, auth.JournalPrefix, auth.JournalBatch{Seq: 1,
		Lines: []auth.Line{{At: h.now.Unix(), Type: "relay.denied", Object: "urn:garage"}, order}})
	require.NoError(t, h.svc.ReceiveJournal(sourceRelay+"interieur", []auth.PublicKey{relay}, doc))
	assert.Equal(t, "eria-ui-server-interieur", h.last("relay.denied").Source)
	assert.Equal(t, keepShort, h.last("relay.denied").Keep)
	assert.Equal(t, sourceCoordinator, h.last("order.validated").Source)
}

// Step 5e-4: an app's Things, by its key: guard.* only, a confirmation used
// twice alerted with the Thing's id when the app owns it.
func TestThingJournal(t *testing.T) {
	h := newHouse(t)
	_, deployPriv, _ := ed25519.GenerateKey(rand.Reader)
	deploy, _ := auth.ParsePublicKey(auth.Ed25519, deployPriv.Public().(ed25519.PublicKey))
	h.svc.deploy = []auth.PublicKey{deploy}
	channel := httptest.NewServer(h.svc.ChannelHandler())
	t.Cleanup(channel.Close)
	h.srv.URL = channel.URL
	pub, app, _ := ed25519.GenerateKey(rand.Reader)
	key, _ := auth.SignDocument(deployPriv, auth.AppKeyPrefix,
		auth.AppKey{App: "garage", Node: "rdc", Pubkey: base64.RawURLEncoding.EncodeToString(pub), Version: 1})
	require.Equal(t, 200, h.call("POST", "/v1/apps/keys", "", key, nil))
	td, _ := auth.SignBy(app, auth.TDPrefix, map[string]any{"id": "urn:eria:garage:1", "title": "Garage"})
	require.Equal(t, 200, h.call("POST", "/v1/things/td", "", td, nil))
	post := func(seq int64, key ed25519.PrivateKey, lines ...auth.Line) int {
		b, _ := auth.SignBy(key, auth.JournalPrefix, auth.JournalBatch{Seq: seq, Lines: lines})
		return h.call("POST", "/v1/things/journal", "", b, nil)
	}
	at := h.now.Unix()
	assert.Equal(t, 200, post(1, app,
		auth.Line{At: at, Type: "guard.confirmable", Subject: "profil:1", Object: "urn:eria:garage:1", Jti: "s.1"},
		auth.Line{At: at, Type: "guard.denied", Object: "urn:eria:garage:1", Result: "denied", Reason: "step 7"},
		auth.Line{At: at, Type: "order.validated"}))
	got := h.last("guard.confirmable")
	assert.True(t, strings.HasPrefix(got.Source, "app:"), got.Source)
	assert.Equal(t, keepLong, got.Keep)
	assert.Equal(t, keepShort, h.last("guard.denied").Keep)
	assert.Equal(t, "type", h.last("document.refused").Reason)

	assert.Equal(t, 200, post(2, app, auth.Line{At: at, Type: "guard.denied", Object: "urn:eria:garage:1", Result: "denied", Reason: "reused"}))
	assert.Contains(t, h.alert, "Jeton réutilisé : urn:eria:garage:1")
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	assert.Equal(t, 403, post(3, other, auth.Line{At: at, Type: "guard.start"}), "an unknown key")
}
