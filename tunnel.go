package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"slices"
	"time"

	zlog "github.com/rs/zerolog/log"
)

// The tunnel listener (AUTH-DESIGN §2.2, §3.6): each connection comes from
// a relay, in mTLS with its role certificate; inside it, the app's own TLS
// session with auth, which the relay cannot read. The relay's role decides
// out, never a header or a parameter.

const (
	roleInner = "relais-interieur"
	roleOuter = "relais-exterieur"
)

// tunnelConn is the app's TLS session, tagged with the relay that carries it.
type tunnelConn struct {
	*tls.Conn
	out bool
}

type tunnelListener struct {
	net.Listener
	outer, inner *tls.Config
	conns        chan net.Conn
}

// ListenTunnel accepts relays on addr. cert is auth's certificate (role
// "auth"), roots the deployment roots that signed the relays' certificates.
func ListenTunnel(addr string, cert tls.Certificate, roots *x509.CertPool) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return newTunnelListener(ln, cert, roots), nil
}

func newTunnelListener(ln net.Listener, cert tls.Certificate, roots *x509.CertPool) *tunnelListener {
	l := &tunnelListener{
		Listener: ln,
		outer: &tls.Config{Certificates: []tls.Certificate{cert}, ClientCAs: roots,
			ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13},
		inner: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13},
		conns: make(chan net.Conn),
	}
	go l.serve()
	return l
}

func (l *tunnelListener) serve() {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			close(l.conns)
			return
		}
		go func() {
			if tc, err := l.open(c); err == nil {
				l.conns <- tc
			} else {
				zlog.Warn().Err(err).Str("from", c.RemoteAddr().String()).Msg("[tunnel] refused")
				c.Close()
			}
		}()
	}
}

// open checks the relay's certificate and returns the inner session; its TLS
// handshake is left to the HTTP server.
func (l *tunnelListener) open(c net.Conn) (net.Conn, error) {
	outer := tls.Server(c, l.outer)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := outer.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	names := outer.ConnectionState().PeerCertificates[0].DNSNames
	var out bool
	switch {
	case slices.Equal(names, []string{roleInner}):
	case slices.Equal(names, []string{roleOuter}):
		out = true
	default:
		return nil, errors.New("not a relay certificate")
	}
	return &tunnelConn{tls.Server(outer, l.inner), out}, nil
}

func (l *tunnelListener) Accept() (net.Conn, error) {
	c, ok := <-l.conns
	if !ok {
		return nil, net.ErrClosed
	}
	return c, nil
}

// NewServer serves h on tunnel connections, with out in each request's
// context.
func NewServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			tc, _ := c.(*tunnelConn)
			return withOut(ctx, tc == nil || tc.out) // unknown origin counts as outside
		},
	}
}
