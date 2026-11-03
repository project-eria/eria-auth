package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/project-eria/go-wot/auth"
)

// Watching the Things (AUTH-DESIGN §4.4, step 5b-2): each app acknowledges
// the heartbeats, signed by its key, with the versions it holds. auth
// alerts once an app goes silent (isolated), when several go silent
// together, and when one stays behind a document (F024: refused, or never
// received), at most once a day per app and kind.
//
// ponytail: the acknowledgements live in memory: after a restart of auth an
// app is watched again from its next acknowledgement only.

const (
	ackFresh      = 5 * time.Minute  // an ack cites a heartbeat this recent
	silentAfter   = 2 * time.Minute  // 4 heartbeats missed
	isolatedAfter = 15 * time.Minute // alert « isolé »
	laggingAfter  = 5 * time.Minute  // alert « en retard de documents »
	burstCount    = 3                // silent together: alert at once
	alertEvery    = 24 * time.Hour
)

type ackSeen struct {
	at      time.Time // when it came
	ack     auth.Ack
	lagging time.Time // since when it holds an older version; zero: up to date
}

// ReceiveAck takes an app's signed acknowledgement of a recent heartbeat.
func (s *Service) ReceiveAck(body []byte) error {
	var signed auth.SignedBy
	if json.Unmarshal(body, &signed) != nil || signed.Kid == "" {
		return ErrInvalid
	}
	id, pub, err := s.appKey(signed.Kid)
	if err != nil {
		return ErrDenied
	}
	payload, err := signed.Verify(auth.AckPrefix, []auth.PublicKey{pub})
	if err != nil {
		return ErrDenied
	}
	var a auth.Ack
	if json.Unmarshal(payload, &a) != nil {
		return ErrInvalid
	}
	now := s.now()
	if beat := time.UnixMilli(a.Beat); beat.After(now.Add(time.Minute)) || now.Sub(beat) > ackFresh {
		return ErrDenied // an old acknowledgement replayed proves nothing
	}
	behind := s.behind(a)
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := &ackSeen{at: now, ack: a}
	if prev := s.acks[id]; prev != nil && behind {
		seen.lagging = prev.lagging
	}
	if behind && seen.lagging.IsZero() {
		seen.lagging = now
	}
	s.acks[id] = seen
	return nil
}

// behind tells whether the app holds an older revocation list or table than
// auth's.
func (s *Service) behind(a auth.Ack) bool {
	var revocation int64
	s.store.db.QueryRow(`SELECT value FROM state WHERE key = 'revocations'`).Scan(&revocation)
	if a.Revocation < max(revocation, 1) {
		return true
	}
	for id, held := range a.Tables {
		var version int64
		var adopted bool
		s.store.db.QueryRow(`SELECT version, adopted FROM things WHERE id = ?`, id).Scan(&version, &adopted)
		if adopted && held < max(version, 1) {
			return true
		}
	}
	return false
}

// WatchThings checks the acknowledgements every minute until stop closes.
func (s *Service) WatchThings(stop <-chan struct{}) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			s.checkThings()
		}
	}
}

func (s *Service) checkThings() {
	names := map[string]string{} // the apps holding a key
	if rows, err := s.store.db.Query(`SELECT id, name FROM apps WHERE kid != ''`); err == nil {
		for rows.Next() {
			var id, name string
			rows.Scan(&id, &name)
			names[id] = name
		}
		rows.Close()
	}
	now := s.now()
	var alerts []string
	s.mu.Lock()
	once := func(key, title string) {
		if now.Sub(s.alerted[key]) >= alertEvery {
			s.alerted[key] = now
			alerts = append(alerts, title)
		}
	}
	silent := 0
	for id, a := range s.acks {
		name, ok := names[id]
		if !ok {
			delete(s.acks, id) // cut or no longer deployed
			continue
		}
		if now.Sub(a.at) > silentAfter {
			silent++
		}
		if now.Sub(a.at) > isolatedAfter {
			once("isolated:"+id, "Appareil isolé : "+name)
		}
		if !a.lagging.IsZero() && now.Sub(a.lagging) > laggingAfter {
			once("lagging:"+id, "Appareil en retard de documents : "+name)
		}
	}
	if silent >= burstCount && !s.burst {
		alerts = append(alerts, fmt.Sprintf("Plusieurs appareils isolés : %d", silent))
	}
	s.burst = silent >= burstCount
	s.mu.Unlock()
	for _, a := range alerts {
		s.store.log("thing.alert", a)
		s.notify(a)
	}
}
