package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/project-eria/go-wot/auth"
	"github.com/stretchr/testify/require"
)

// After new-key, the CSR carries the auth key's signature over its DER.
func TestCSRSignedByAuthKey(t *testing.T) {
	t.Chdir(t.TempDir())
	var keyLine, out bytes.Buffer
	require.NoError(t, cmdNewKey(nil, &keyLine))
	require.NoError(t, cmdCSR(nil, &out))
	block, rest := pem.Decode(out.Bytes())
	require.NotNil(t, block)
	sigText, ok := strings.CutPrefix(strings.TrimSpace(string(rest)), "csr-sig: ")
	require.True(t, ok, string(rest))
	sig, _ := base64.RawURLEncoding.DecodeString(sigText)
	key, err := readKey("auth-ed25519.key")
	require.NoError(t, err)
	require.True(t, ed25519.Verify(key.Public().(ed25519.PublicKey), append([]byte(auth.CSRPrefix), block.Bytes...), sig))
}
