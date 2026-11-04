package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	zlog "github.com/rs/zerolog/log"
)

// Copy of the journal on the master's node (AUTH-DESIGN §4.5, step 5e-2):
// each line sent right after it is written, in order, to the master's
// append-only files (one per UTC day and class); once a day, the digests of
// yesterday's files compared with auth's own lines, a divergence alerted.

// JournalPrefix is the domain of the signature on a batch of lines.
const JournalPrefix = "eria-journal-v1"

const journalBatch = 200

type JournalCopy struct {
	svc      *Service
	url      string // master action appendAuthJournal
	client   *http.Client
	known    bool   // last is the master's last line
	lastAt   int64  // the master's last line: at…
	lastID   int64  // …and id
	compared string // last day compared, YYYY-MM-DD
}

// NewJournalCopy sends to appendAuthJournal, next to the backup's action.
func NewJournalCopy(svc *Service, backupURL string, client *http.Client) (*JournalCopy, error) {
	u, err := url.Parse(backupURL)
	if err != nil {
		return nil, err
	}
	u.Path = path.Join(path.Dir(u.Path), "appendAuthJournal")
	return &JournalCopy{svc: svc, url: u.String(), client: client}, nil
}

// Run copies after each line written, and every minute while the master
// doesn't answer or a day is to compare.
func (j *JournalCopy) Run(stop <-chan struct{}) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		if err := j.Sync(); err != nil {
			j.known = false
			zlog.Warn().Err(err).Msg("[journal] copy not sent: retried in a minute")
		}
		select {
		case <-stop:
			return
		case <-j.svc.store.written:
		case <-tick.C:
		}
	}
}

// Sync sends the lines the master doesn't have, then compares yesterday.
func (j *JournalCopy) Sync() error {
	if !j.known {
		if _, err := j.send(nil, ""); err != nil {
			return err
		}
	}
	for {
		// ponytail: a line written with a clock stepped back behind the
		// master's last is never sent; the daily comparison tells.
		lines, err := j.svc.store.journalWhere(`at > ? OR (at = ? AND id > ?)`, journalBatch,
			j.lastAt, j.lastAt, j.lastID)
		if err != nil {
			return err
		}
		if len(lines) == 0 {
			break
		}
		if _, err := j.send(lines, ""); err != nil {
			return err
		}
		if last := lines[len(lines)-1]; j.lastAt != last.At || j.lastID != last.ID {
			return fmt.Errorf("master kept up to %d.%d, not %d.%d", j.lastAt, j.lastID, last.At, last.ID)
		}
	}
	yesterday := j.svc.now().UTC().AddDate(0, 0, -1).Format(time.DateOnly)
	if j.compared == yesterday {
		return nil
	}
	theirs, err := j.send(nil, yesterday)
	if err != nil {
		return err
	}
	ours, err := j.svc.store.dayDigests(yesterday)
	if err != nil {
		return err
	}
	j.compared = yesterday
	for _, keep := range []string{"30", "365"} {
		if ours[keep] != theirs[keep] {
			j.svc.store.record(Entry{Type: "journal.diverged", Result: "denied", Reason: "digest",
				Object: yesterday + "." + keep, Keep: keepLong})
			j.svc.alertOnce("journal", "Journal divergent")
			break
		}
	}
	return nil
}

// send posts lines (and asks for the digests of day), and moves to the
// master's last line.
func (j *JournalCopy) send(lines []Entry, day string) (map[string]string, error) {
	text := journalText(lines)
	h := sha256.Sum256([]byte(text))
	body, _ := json.Marshal(map[string]any{"lines": text, "day": day,
		"sig": base64.StdEncoding.EncodeToString(ed25519.Sign(j.svc.key, append([]byte(JournalPrefix), h[:]...)))})
	resp, err := j.client.Post(j.url, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("master answered %s", resp.Status)
	}
	var out struct {
		At      int64             `json:"at"`
		ID      int64             `json:"id"`
		Digests map[string]string `json:"digests"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	j.known, j.lastAt, j.lastID = true, out.At, out.ID
	return out.Digests, nil
}

// journalText is the lines as JSON lines, as the master keeps them.
func journalText(lines []Entry) string {
	var b strings.Builder
	for _, e := range lines {
		data, _ := json.Marshal(e)
		b.Write(data)
		b.WriteByte('\n')
	}
	return b.String()
}

// dayDigests is the sha256 of auth's lines of a UTC day, per class, as the
// master's files would hold them; none for a class without line.
func (s *Store) dayDigests(day string) (map[string]string, error) {
	d, err := time.Parse(time.DateOnly, day)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, keep := range []int{keepShort, keepLong} {
		lines, err := s.journalWhere(`at >= ? AND at < ? AND keep = ?`, 0, d.Unix(), d.Unix()+86400, keep)
		if err != nil {
			return nil, err
		}
		if len(lines) > 0 {
			h := sha256.Sum256([]byte(journalText(lines)))
			out[fmt.Sprint(keep)] = hex.EncodeToString(h[:])
		}
	}
	return out, nil
}
