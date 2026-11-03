package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/project-eria/go-wot/auth"
)

// The relay's service token (§3.6): its observations of the Things, and the
// TDs it reads, go with its own token. Its grants cover read only: a room
// grant per room of the adopted Things, a Thing grant for those without a
// room. The relay proves its certificate key: a request it carries for an
// app can't (the app's TLS session goes through the same connection).
//
// ponytail: this is the relay part of the app keys (§4.7 step 3), proven by
// the TLS key the master signed; at most 32 grants, the others left out with
// an alert.

const (
	domainRelayToken = "eria-relay-token-v1"
	serviceTokenTTL  = 15 * time.Minute
	// A service granted a confirmable command gets 5 min tokens (§2.7 step 8).
	confirmableTokenTTL = 5 * time.Minute
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
// issues its service token.
func (s *Service) RelayToken(r *http.Request, challenge string, sig []byte) (string, error) {
	key, ok := relayPublicKey(r)
	if !ok || !s.challenges.Redeem(challenge, key, []byte(challenge+domainRelayToken), sig) {
		return "", ErrDenied
	}
	grants, err := s.relayGrants()
	if err != nil {
		return "", err
	}
	which := "interieur"
	if isOut(r) {
		which = "exterieur"
	}
	s.mu.Lock()
	s.relayToken[which] = s.now().Unix()
	s.mu.Unlock()
	return s.serviceToken(auth.AppSubject+"eria-ui-server-"+which, grants, s.now())
}

func (s *Service) relayGrants() ([]string, error) {
	things, err := s.Things()
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var grants []string
	add := func(g string) {
		if !seen[g] {
			seen[g] = true
			grants = append(grants, g)
		}
	}
	for _, t := range things {
		if !t.Adopted {
			continue
		}
		for _, z := range t.Zones {
			add("room:" + z + ":read")
		}
		if len(t.Zones) == 0 {
			add("thing:" + t.ID + ":read")
		}
	}
	if len(grants) > auth.MaxGrants {
		s.notify("Trop de pièces pour le relais")
		s.store.log("relay.grants", fmt.Sprintf("%d grants, %d kept", len(grants), auth.MaxGrants))
		grants = grants[:auth.MaxGrants]
	}
	return grants, nil
}
