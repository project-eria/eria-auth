package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/project-eria/go-wot/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The coordinator's registry makes the admin's phone a validator by its active
// bio key, adds a YubiKey, never turns a phone not enrolled into a key of
// its own, and an older or foreign registry changes nothing.
func TestAdminKeysRegistry(t *testing.T) {
	h := newHouse(t)
	_, _, admin := h.bootstrapAdmin()
	deployPub, deployPriv, _ := ed25519.GenerateKey(rand.Reader)
	deploy, _ := auth.ParsePublicKey(auth.Ed25519, deployPub)
	h.svc.deploy = []auth.PublicKey{deploy}

	phoneID, bio := edKey(t), p256Key(t)
	r := h.ask(phoneID, map[string]any{"bio": bio.in})
	var phone Terminal
	require.Equal(t, 200, h.call("POST", "/v1/requests/"+r.ID+"/enroll", admin, EnrollIn{Code: r.Code,
		Terminal: &TerminalChange{Name: "Téléphone", Type: "phone", Floor: 1}}, &phone))
	yubikey2, stranger := p256Key(t), p256Key(t)
	entry := func(name, kind string, k signerKey) auth.AdminKeyEntry {
		return auth.AdminKeyEntry{Name: name, Kind: kind, Alg: k.in.Alg, Key: base64.RawURLEncoding.EncodeToString(k.in.Key), Kid: k.kid}
	}
	registry := func(priv ed25519.PrivateKey, version int64, keys ...auth.AdminKeyEntry) error {
		signed, err := auth.SignDocument(priv, auth.AdminKeysPrefix, auth.AdminKeys{Version: version, Keys: keys})
		require.NoError(t, err)
		return h.svc.ApplyAdminKeys(signed)
	}
	validator := func() bool {
		var v bool
		h.svc.store.db.QueryRow(`SELECT validator FROM terminals WHERE id = ?`, phone.ID).Scan(&v)
		return v
	}
	keyRole := func(kid string) string {
		var role string
		h.svc.store.db.QueryRow(`SELECT role FROM keys WHERE kid = ?`, kid).Scan(&role)
		return role
	}

	_, foreign, _ := ed25519.GenerateKey(rand.Reader)
	assert.ErrorIs(t, registry(foreign, 10, entry("phone", "phone", bio)), ErrDenied, "not the deployment key")
	assert.False(t, validator())

	bad := entry("yk", "yubikey", yubikey2)
	bad.Kid = "x"
	assert.ErrorIs(t, registry(deployPriv, 10, entry("phone", "phone", bio), bad), ErrInvalid)
	assert.False(t, validator(), "never half a registry")

	require.NoError(t, registry(deployPriv, 10, entry("phone", "phone", bio), entry("yk2", "yubikey", yubikey2),
		entry("future phone", "phone", stranger)))
	assert.True(t, validator(), "the phone, by its active bio key")
	assert.Equal(t, "validator", keyRole(yubikey2.kid))
	assert.Equal(t, "", keyRole(stranger.kid), "a phone not enrolled is no key of its own")
	assert.Contains(t, h.alert, "Nouveau téléphone validateur : phone")

	require.NoError(t, registry(deployPriv, 10, entry("phone", "phone", bio)), "the same version again: applied again")
	assert.ErrorIs(t, registry(deployPriv, 9), ErrDenied, "an older registry")
}
