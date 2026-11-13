package main

import (
	"net/http"
	"strings"
	"time"

	"github.com/project-eria/go-wot/auth"
)

// The relay's service tokens (§3.6): its observations of the Things, and the
// TDs it reads, go with its own tokens, one per Thing (claim thing, like the
// apps' since step 4e): a Thing can't replay it at the others. Its grants
// cover read only: the rooms of the Thing once adopted, or the Thing itself
// without a room. Without a Thing: the coordinator's token, no grants (it only
// reads the inventory and the app's release). The relay proves its
// certificate key: a request it carries for an app can't (the app's TLS
// session goes through the same connection).
//
// ponytail: this is the relay part of the app keys (§4.7 step 3), proven by
// the TLS key the coordinator signed.

const (
	domainRelayToken = "eria-relay-token-v1"
	serviceTokenTTL  = 5 * time.Minute // the longest a Thing accepts (§2.7)
)

// RelayChallenge issues a challenge for the key of the relay carrying r.
func (s *Service) RelayChallenge(r *http.Request) (string, error) {
	key, ok := relayPublicKey(r)
	if !ok {
		return "", ErrDenied
	}
	return s.challenges.Issue(key.KID())
}

// RelayToken checks the relay's signature over challenge ‖ domain and
// issues its service token for thing (TD id, or DNS-SD instance), "" for the
// coordinator.
func (s *Service) RelayToken(r *http.Request, challenge string, sig []byte, thing string) (string, error) {
	key, ok := relayPublicKey(r)
	if !ok || !s.challenges.Redeem(challenge, key, []byte(challenge+domainRelayToken), sig) {
		s.store.record(Entry{Type: "proof.relay", Result: "denied", Reason: "proof"})
		return "", ErrDenied
	}
	var grants []string
	if thing != "" {
		t, err := s.findThing(thing)
		if err != nil {
			return "", err
		}
		thing, grants = t.ID, relayGrants(t)
	}
	which := "interieur"
	if isOut(r) {
		which = "exterieur"
	}
	s.mu.Lock()
	s.relayToken[which] = s.now().Unix()
	s.mu.Unlock()
	tok, c, err := s.serviceToken(auth.AppSubject+"eria-ui-server-"+which, thing, grants, s.now())
	if err == nil {
		s.store.record(Entry{Type: "token.service", Subject: c.Sub, Object: thing, Jti: c.Jti, Detail: strings.Join(c.Grants, " ")})
	}
	return tok, err
}

// relayGrants are the relay's read grants on t: its rooms, or t itself
// without a room; none before adoption.
func relayGrants(t ThingRecord) []string {
	if !t.Adopted {
		return nil
	}
	if len(t.Zones) == 0 {
		return []string{"thing:" + t.ID + ":read"}
	}
	grants := make([]string, len(t.Zones))
	for i, z := range t.Zones {
		grants[i] = "room:" + z + ":read"
	}
	return grants
}
