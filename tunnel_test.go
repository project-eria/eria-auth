package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/project-eria/go-wot/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pki is a small deployment authority, as eria-manager's.
type pki struct {
	root     *x509.Certificate
	rootKey  ed25519.PrivateKey
	rootPool *x509.CertPool
}

func newPKI(t *testing.T) pki {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	require.NoError(t, err)
	root, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return pki{root, priv, pool}
}

func (p pki) leaf(t *testing.T, role string) tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: role},
		DNSNames: []string{role}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.root, &key.PublicKey, p.rootKey)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// client opens a tunnel as a relay with relayCert, then the app's own TLS
// session inside it, checking the "auth" role name.
func (p pki) client(addr string, relayCert tls.Certificate) *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			outer, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: p.rootPool, ServerName: "auth",
				Certificates: []tls.Certificate{relayCert}})
			if err != nil {
				return nil, err
			}
			inner := tls.Client(outer, &tls.Config{RootCAs: p.rootPool, ServerName: "auth"})
			return inner, inner.HandshakeContext(ctx)
		}}}
}

func TestTunnel(t *testing.T) {
	h := newHouse(t)
	h.bootstrapAdmin()
	p := newPKI(t)

	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ln := newTunnelListener(tcp, p.leaf(t, "auth"), p.rootPool)
	srv := NewServer(h.svc.Handler())
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	addr := tcp.Addr().String()

	// A terminal asks to enroll through the tunnel.
	enroll := func(c *http.Client) (int, error) {
		body := `{"identity":{"alg":"ed25519","key":"` + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" + `"}}`
		resp, err := c.Post("https://auth/v1/requests", "application/json", strings.NewReader(body))
		if err != nil {
			return 0, err
		}
		resp.Body.Close()
		return resp.StatusCode, nil
	}

	code, err := enroll(p.client(addr, p.leaf(t, roleOuter)))
	require.NoError(t, err)
	assert.Equal(t, 403, code, "the outer relay's role sets out")

	code, err = enroll(p.client(addr, p.leaf(t, roleInner)))
	require.NoError(t, err)
	assert.Equal(t, 200, code)

	_, err = enroll(p.client(addr, p.leaf(t, "maitre")))
	assert.Error(t, err, "only a relay certificate opens a tunnel")

	other := newPKI(t)
	_, err = enroll(p.client(addr, other.leaf(t, roleInner)))
	assert.Error(t, err, "a relay certificate of another authority")
}

func TestRelayToken(t *testing.T) {
	h := newHouse(t)
	_, _, admin := h.bootstrapAdmin()
	h.svc.ReceiveTD(TDIn{ID: "urn:eria:garage:1", Title: "Garage"}, "")
	h.svc.ReceiveTD(TDIn{ID: "urn:eria:meteo:1", Title: "Météo"}, "")
	h.svc.ReceiveTD(TDIn{ID: "urn:eria:new:1", Title: "Pas adopté"}, "")
	require.NoError(t, h.svc.AdoptThing("urn:eria:garage:1"))
	require.NoError(t, h.svc.AdoptThing("urn:eria:meteo:1"))
	require.NoError(t, h.svc.SetZones("urn:eria:garage:1", []string{"garage"}))
	_ = admin

	p := newPKI(t)
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := NewServer(h.svc.Handler())
	go srv.Serve(newTunnelListener(tcp, p.leaf(t, "auth"), p.rootPool))
	t.Cleanup(func() { srv.Close() })
	relay := p.leaf(t, roleInner)
	c := p.client(tcp.Addr().String(), relay)
	post := func(path, body string, out any) int {
		resp, err := c.Post("https://auth"+path, "application/json", strings.NewReader(body))
		require.NoError(t, err)
		defer resp.Body.Close()
		json.NewDecoder(resp.Body).Decode(out)
		return resp.StatusCode
	}
	var ch struct{ Challenge string }
	require.Equal(t, 200, post("/v1/relay/challenge", "", &ch))
	sign := func(key *ecdsa.PrivateKey, msg string) []byte {
		hash := sha256.Sum256([]byte(msg))
		r, s, _ := ecdsa.Sign(rand.Reader, key, hash[:])
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		return sig
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	body := func(key *ecdsa.PrivateKey) string {
		b, _ := json.Marshal(map[string]any{"challenge": ch.Challenge, "sig": sign(key, ch.Challenge+domainRelayToken)})
		return string(b)
	}
	var tok struct{ Token string }
	assert.Equal(t, 403, post("/v1/relay/token", body(other), &tok), "an app can't sign with the relay's key")
	require.Equal(t, 200, post("/v1/relay/token", body(relay.PrivateKey.(*ecdsa.PrivateKey)), &tok))
	claims := h.claims(tok.Token)
	assert.Equal(t, auth.KindService, claims.Kind)
	assert.ElementsMatch(t, []string{"room:garage:read", "thing:urn:eria:meteo:1:read"}, claims.Grants)
}
