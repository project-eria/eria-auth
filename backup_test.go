package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBackup(t *testing.T) {
	h := newHouse(t)
	h.bootstrapAdmin()
	identity, _ := age.GenerateX25519Identity()

	var got map[string]any
	coordinator := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
	}))
	defer coordinator.Close()

	b, err := NewBackup(h.svc.store, h.svc.key, h.svc.kid, coordinator.URL, identity.Recipient().String(), coordinator.Client())
	require.NoError(t, err)
	require.NoError(t, b.Send())

	data, _ := base64.StdEncoding.DecodeString(got["data"].(string))
	sig, _ := base64.StdEncoding.DecodeString(got["sig"].(string))
	version := int64(got["version"].(float64))
	pub := h.svc.key.Public().(ed25519.PublicKey)
	assert.True(t, bytes.Equal(SignBackup(h.svc.key, version, data), sig))
	assert.True(t, ed25519.Verify(pub, append([]byte(BackupPrefix+"1800000000000"), sha256Of(data)...), sig))

	r, err := age.Decrypt(bytes.NewReader(data), identity)
	require.NoError(t, err, "only the coordinator's age key reads it")
	plain, _ := io.ReadAll(r)
	path := filepath.Join(t.TempDir(), "restored.db")
	os.WriteFile(path, plain, 0o600)
	db, _ := sql.Open("sqlite", "file:"+path)
	defer db.Close()
	var profiles, journal int
	db.QueryRow(`SELECT count(*) FROM profiles`).Scan(&profiles)
	db.QueryRow(`SELECT count(*) FROM journal`).Scan(&journal)
	assert.Equal(t, 1, profiles)
	assert.Zero(t, journal, "the journal is not part of the state")

	// A change asks for a backup.
	h.svc.store.log("test", "")
	select {
	case <-b.changed:
	default:
		t.Fatal("no backup asked")
	}
}

func sha256Of(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}
