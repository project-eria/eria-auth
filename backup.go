package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"filippo.io/age"
	zlog "github.com/rs/zerolog/log"
)

// Backup sends an encrypted copy of the whole state to the master after each
// change, and once a day as a safeguard (AUTH-DESIGN §4.2). Encrypted with
// age for the master's backup key: auth can write a backup, never read one.
// Neither the pepper nor the auth key are in it, nor the journal.
type Backup struct {
	store     *Store
	key       ed25519.PrivateKey
	kid       string
	url       string // master action storeAuthBackup
	recipient age.Recipient
	client    *http.Client
	changed   chan struct{}
}

// BackupPrefix is the domain of the signature on a backup.
const BackupPrefix = "eria-backup-v1"

func NewBackup(store *Store, key ed25519.PrivateKey, kid, url, recipient string) (*Backup, error) {
	r, err := age.ParseX25519Recipient(recipient)
	if err != nil {
		return nil, err
	}
	b := &Backup{store: store, key: key, kid: kid, url: url, recipient: r,
		client: &http.Client{Timeout: 30 * time.Second}, changed: make(chan struct{}, 1)}
	store.changed = b.Changed
	return b, nil
}

// Changed asks for a backup soon; changes close together make one backup.
func (b *Backup) Changed() {
	select {
	case b.changed <- struct{}{}:
	default:
	}
}

func (b *Backup) Run() {
	daily := time.NewTicker(24 * time.Hour)
	for {
		select {
		case <-b.changed:
			time.Sleep(2 * time.Second)
			select { // the changes of these 2 s are in this backup
			case <-b.changed:
			default:
			}
		case <-daily.C:
		}
		if err := b.Send(); err != nil {
			zlog.Error().Err(err).Msg("[backup] not sent: retried at the next change")
		}
	}
}

// Send encrypts the current state and posts it to the master.
func (b *Backup) Send() error {
	plain, err := b.snapshot()
	if err != nil {
		return err
	}
	var enc bytes.Buffer
	w, err := age.Encrypt(&enc, b.recipient)
	if err != nil {
		return err
	}
	w.Write(plain)
	if err := w.Close(); err != nil {
		return err
	}
	version := b.store.now().UnixMilli()
	body, _ := json.Marshal(map[string]any{
		"version": version, "kid": b.kid,
		"data": base64.StdEncoding.EncodeToString(enc.Bytes()),
		"sig":  base64.StdEncoding.EncodeToString(SignBackup(b.key, version, enc.Bytes())),
	})
	resp, err := b.client.Post(b.url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("master answered %s", resp.Status)
	}
	zlog.Info().Int64("version", version).Msg("[backup] sent")
	return nil
}

// SignBackup signs "eria-backup-v1" ‖ version ‖ sha256(data).
func SignBackup(key ed25519.PrivateKey, version int64, data []byte) []byte {
	h := sha256.Sum256(data)
	return ed25519.Sign(key, append([]byte(BackupPrefix+strconv.FormatInt(version, 10)), h[:]...))
}

// snapshot is a consistent copy of the database, without the journal.
func (b *Backup) snapshot() ([]byte, error) {
	dir, err := os.MkdirTemp("", "eria-auth-backup")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "state.db")
	if _, err := b.store.db.Exec(`VACUUM INTO ?`, path); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		return nil, err
	}
	_, err = db.Exec(`DELETE FROM journal; VACUUM`)
	db.Close()
	if err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}
