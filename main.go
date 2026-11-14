// eria-auth: the auth service of ERIA (AUTH-DESIGN §1.3, §3). It checks
// people and terminals and issues the tokens the Things verify. One pinned
// instance; reached by the apps through a relay's tunnel only.
package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	eria "github.com/project-eria/eria-core"
	"github.com/project-eria/go-wot/auth"
	"github.com/project-eria/go-wot/inventory"
	zlog "github.com/rs/zerolog/log"
)

type AppConfig struct {
	Database   string `yaml:"database" default:"eria-auth.db"`
	KeyFile    string `yaml:"keyFile" default:"auth-ed25519.key"`   // signing key, made by `eria-auth bootstrap`
	Deployment string `yaml:"deployment" required:"true"`           // aud of the tokens: id of the house
	Listen     string `yaml:"listen" default:":8443"`               // tunnel listener, for the relays
	Channel    string `yaml:"channel" default:":8444"`              // Things channel: plain HTTP, home automation network only
	Cert       string `yaml:"cert" default:"auth.crt"`              // TLS certificate, role "auth", signed by the coordinator
	CertKey    string `yaml:"certKey" default:"auth-tls.key"`       // its private key, made by `eria-auth csr`
	Roots      string `yaml:"roots" default:"roots.pem"`            // deployment roots (eria-coordinator tls-root)
	Ntfy       string `yaml:"ntfy"`                                 // ntfy topic URL for the alerts
	StatesApp  string `yaml:"statesApp" default:"manager-contexts"` // the app that publishes the house states, its name in the deployment
	// Backups (§4.2): the coordinator's action storeAuthBackup, and the age public
	// key of its backup key (eria-coordinator auth-secrets). The journal's copy
	// goes to appendAuthJournal next to it (§4.5).
	BackupURL       string `yaml:"backupURL" required:"true"`
	BackupRecipient string `yaml:"backupRecipient" required:"true"`
	// First values only, copied at the first start, then edited by the admin.
	Hide   []string `yaml:"hide,omitempty"`   // glob patterns on TD ids of the Things never shown
	Levels []Level  `yaml:"levels,omitempty"` // names of the levels 1 to 9 (default: AUTH-DESIGN §2.1)
}

var config AppConfig

func main() {
	// The agent gives the app a data folder: the default file names live
	// there, for the local commands too.
	if dir := os.Getenv("ERIA_AUTH_DATA"); dir != "" {
		if err := os.Chdir(dir); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if len(os.Args) > 1 {
		if run, ok := commands[os.Args[1]]; ok {
			if err := run(os.Args[2:], os.Stdout); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			return
		}
	}

	eria.Init("ERIA auth", &config)
	defer eria.Close()

	// The pepper is injected at each start, never stored next to the state (§1.1).
	pepper, err := hex.DecodeString(os.Getenv("ERIA_AUTH_PEPPER"))
	if err != nil || len(pepper) != 32 {
		zlog.Fatal().Msg("[main] ERIA_AUTH_PEPPER must hold 64 hex characters")
	}
	key, err := readKey(config.KeyFile)
	if err != nil {
		zlog.Fatal().Err(err).Msg("[main] No signing key: run `eria-auth bootstrap` on this node first")
	}
	store, err := OpenStore(config.Database)
	if err != nil {
		zlog.Fatal().Err(err).Msg("[main] Can't open the database")
	}
	svc := NewService(store, pepper, key, config.Deployment)
	svc.notify = ntfy(config.Ntfy)
	svc.statesApp = config.StatesApp
	if err := svc.SeedConfig(config.Hide); err != nil {
		zlog.Fatal().Err(err).Msg("[main] Can't store the first settings")
	}
	if err := svc.SeedLevels(config.Levels); err != nil {
		zlog.Fatal().Err(err).Msg("[main] Can't store the first level names")
	}
	if err := svc.CheckClock(); err != nil {
		zlog.Fatal().Err(err).Msg("[main] Clock behind the last version issued")
	}
	// The coordinator is reached with its certificate checked against the
	// deployment roots (role coordinateur) once it serves HTTPS (§4.7 step 5d).
	rootsPEM, _ := os.ReadFile(config.Roots)
	coordinator, err := inventory.CoordinatorClient(rootsPEM, 30*time.Second)
	if err != nil {
		zlog.Fatal().Err(err).Str("file", config.Roots).Msg("[main] Bad deployment roots")
	}
	backup, err := NewBackup(store, key, svc.kid, config.BackupURL, config.BackupRecipient, coordinator)
	if err != nil {
		zlog.Fatal().Err(err).Msg("[main] Bad backupRecipient")
	}
	go backup.Run()
	go svc.WatchThings(nil)
	go store.PurgeJournal(nil)
	journalCopy, err := NewJournalCopy(svc, config.BackupURL, coordinator)
	if err != nil {
		zlog.Fatal().Err(err).Msg("[main] Bad backupURL")
	}
	go journalCopy.Run(nil)
	svc.Started()
	backup.Changed() // a first backup at each start
	zlog.Info().Str("fingerprint", svc.kid).Msg("[main] auth key (compare with eria-coordinator auth-keyset)")

	cert, err := tls.LoadX509KeyPair(config.Cert, config.CertKey)
	if err != nil {
		zlog.Fatal().Err(err).Msg("[main] No TLS certificate: `eria-auth csr`, then eria-coordinator tls-sign --role auth")
	}
	if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
		svc.certExpiry = leaf.NotAfter
	}
	go svc.SendSummaries(nil)
	roots := x509.NewCertPool()
	if data, err := os.ReadFile(config.Roots); err != nil || !roots.AppendCertsFromPEM(data) {
		zlog.Fatal().Str("file", config.Roots).Msg("[main] No deployment root (eria-coordinator tls-root)")
	}
	if svc.deploy, err = auth.DeploymentKeys(rootsPEM); err != nil {
		zlog.Fatal().Err(err).Str("file", config.Roots).Msg("[main] No deployment key in the roots")
	}
	ln, err := ListenTunnel(config.Listen, cert, roots)
	if err != nil {
		zlog.Fatal().Err(err).Msg("[main] Can't listen")
	}
	go func() {
		if err := NewServer(svc.Handler()).Serve(ln); err != nil {
			zlog.Fatal().Err(err).Msg("[main] Tunnel listener stopped")
		}
	}()
	go func() {
		srv := &http.Server{Addr: config.Channel, Handler: svc.ChannelHandler(), ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}
		if err := srv.ListenAndServe(); err != nil {
			zlog.Fatal().Err(err).Msg("[main] Things channel stopped")
		}
	}()
	eria.WaitForSignal()
}

// --- Local commands, in a shell on the auth node ---

var commands = map[string]func(args []string, out io.Writer) error{
	"bootstrap":   cmdBootstrap,
	"fingerprint": cmdFingerprint,
	"new-key":     cmdNewKey,
	"csr":         cmdCSR,
}

func commandFlags(name string) (*flag.FlagSet, *AppConfig) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	c := &AppConfig{}
	fs.StringVar(&c.Database, "database", "eria-auth.db", "SQLite file")
	fs.StringVar(&c.KeyFile, "key-file", "auth-ed25519.key", "signing key file")
	fs.StringVar(&c.CertKey, "cert-key", "auth-tls.key", "TLS private key file")
	return fs, c
}

// cmdBootstrap makes the signing key if there is none, and writes a one-time
// code (10 min) to the standard output, never to the journal (§3.5).
func cmdBootstrap(args []string, out io.Writer) error {
	fs, c := commandFlags("bootstrap")
	if err := fs.Parse(args); err != nil {
		return err
	}
	key, err := readKey(c.KeyFile)
	if errors.Is(err, os.ErrNotExist) {
		_, key, _ = ed25519.GenerateKey(rand.Reader)
		err = os.WriteFile(c.KeyFile, []byte(hex.EncodeToString(key.Seed())+"\n"), 0o600)
	}
	if err != nil {
		return err
	}
	store, err := OpenStore(c.Database)
	if err != nil {
		return err
	}
	svc := NewService(store, nil, key, "")
	code, err := svc.NewBootstrapCode()
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Bootstrap code (10 min): %s\n", code)
	return printFingerprint(key, out)
}

// cmdNewKey makes the signing key of a restored auth (§4.2): never over an
// existing one.
func cmdNewKey(args []string, out io.Writer) error {
	fs, c := commandFlags("new-key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	f, err := os.OpenFile(c.KeyFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(f, hex.EncodeToString(key.Seed())); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return printFingerprint(key, out)
}

func cmdFingerprint(args []string, out io.Writer) error {
	fs, c := commandFlags("fingerprint")
	if err := fs.Parse(args); err != nil {
		return err
	}
	key, err := readKey(c.KeyFile)
	if err != nil {
		return err
	}
	return printFingerprint(key, out)
}

// printFingerprint gives what eria-coordinator auth-keyset needs: the key, and
// its fingerprint to compare.
func printFingerprint(key ed25519.PrivateKey, out io.Writer) error {
	raw := key.Public().(ed25519.PublicKey)
	pub, err := auth.ParsePublicKey(auth.Ed25519, raw)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "eria-coordinator auth-keyset --key %s --expect %s\n",
		base64.RawURLEncoding.EncodeToString(raw), pub.KID())
	return err
}

// cmdCSR makes the TLS private key on this node (if absent) and prints its
// certificate request, for eria-coordinator tls-sign --role auth. With a signing
// key here, a last line « csr-sig: <base64url> » signs the request's DER
// (auth.CSRPrefix): the guided restore ties the CSR to the key the admin
// compared.
func cmdCSR(args []string, out io.Writer) error {
	fs, c := commandFlags("csr")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var priv *ecdsa.PrivateKey
	data, err := os.ReadFile(c.CertKey)
	switch {
	case errors.Is(err, os.ErrNotExist):
		priv, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		der, _ := x509.MarshalECPrivateKey(priv)
		if err := os.WriteFile(c.CertKey, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
			return err
		}
	case err != nil:
		return err
	default:
		block, _ := pem.Decode(data)
		if block == nil {
			return errors.New(c.CertKey + ": not PEM")
		}
		if priv, err = x509.ParseECPrivateKey(block.Bytes); err != nil {
			return err
		}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, priv)
	if err != nil {
		return err
	}
	if err := pem.Encode(out, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}); err != nil {
		return err
	}
	if key, err := readKey(c.KeyFile); err == nil {
		sig := ed25519.Sign(key, append([]byte(auth.CSRPrefix), der...))
		_, err = fmt.Fprintf(out, "csr-sig: %s\n", base64.RawURLEncoding.EncodeToString(sig))
		return err
	}
	return nil
}

func readKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New(path + ": expected 64 hex characters")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}
