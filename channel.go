package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/project-eria/go-wot/auth"
	"github.com/project-eria/go-wot/auth/authz"
)

// The Things channel (§2.4, F017): plain HTTP without token, in the home
// automation network, integrity by signature. A Thing sends its TD and pulls
// its table and the revocation list; manager-contexts publishes the states.
// Only a rate limit: everything served is public, and what comes in can
// only add unclassified functions or close functions.

const maxTD = 64 << 10

func (s *Service) ChannelHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/things/td", func(w http.ResponseWriter, r *http.Request) {
		var td TDIn
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxTD)).Decode(&td); err != nil {
			reply(w, nil, ErrInvalid)
			return
		}
		reply(w, nil, s.ReceiveTD(td))
	})
	mux.HandleFunc("GET /v1/things/{id}/table", func(w http.ResponseWriter, r *http.Request) {
		tok, version, err := s.TableDoc(r.PathValue("id"))
		signedDoc(w, r, tok, version, err)
	})
	mux.HandleFunc("GET /v1/revocation", func(w http.ResponseWriter, r *http.Request) {
		tok, err := s.RevocationDoc()
		var d auth.Doc
		if err == nil {
			d, err = auth.ParseDoc(tok, s.lookup, s.aud, auth.DocRevocation, "*")
		}
		signedDoc(w, r, tok, d.Version, err)
	})
	// App keys from the master, and the service proofs of the apps (§1.3).
	mux.HandleFunc("POST /v1/apps/keys", handle(func(r *http.Request, in auth.Signed) (any, error) {
		return nil, s.RegisterAppKey(in)
	}))
	mux.HandleFunc("POST /v1/service/challenge", handle(func(r *http.Request, in struct{ Kid string }) (any, error) {
		ch, err := s.ServiceChallenge(in.Kid)
		return map[string]string{"challenge": ch}, err
	}))
	mux.HandleFunc("POST /v1/service/token", handle(func(r *http.Request, in struct {
		Kid       string
		Challenge string
		Sig       []byte
	}) (any, error) {
		tok, err := s.ServiceToken(in.Kid, in.Challenge, in.Sig)
		return map[string]string{"token": tok}, err
	}))
	mux.HandleFunc("PUT /v1/states", handle(func(r *http.Request, states []string) (any, error) {
		return nil, s.SetActiveStates(states)
	}))
	return limit(mux, 20, 50)
}

// signedDoc answers a signed document, or 304 when the Thing holds this
// version already (If-None-Match).
func signedDoc(w http.ResponseWriter, r *http.Request, tok string, version int64, err error) {
	if err != nil {
		reply(w, nil, err)
		return
	}
	etag := `"` + strconv.FormatInt(version, 10) + `"`
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/jwt")
	w.Write([]byte(tok))
}

// limit is a token bucket shared by every caller: perSecond, up to burst.
// ponytail: one bucket for the channel, per source address if a Thing ever
// floods it.
func limit(h http.Handler, perSecond, burst float64) http.Handler {
	var mu sync.Mutex
	tokens, last := burst, time.Now()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		now := time.Now()
		tokens = min(burst, tokens+now.Sub(last).Seconds()*perSecond)
		last = now
		ok := tokens >= 1
		if ok {
			tokens--
		}
		mu.Unlock()
		if !ok {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// --- Simulator (F106) ---

// SimulateIn is a question of the admin: this terminal, this profile (0:
// signed out), from outside or not, this function of this Thing.
type SimulateIn struct {
	Terminal string `json:"terminal"`
	Profile  int64  `json:"profile"`
	Out      bool   `json:"out"`
	Thing    string `json:"thing"`
	Key      string `json:"key"`
	Minimal  bool   `json:"minimal"`
}

type SimulateOut struct {
	Allow  bool   `json:"allow"`
	Step   int    `json:"step"`
	Reason string `json:"reason"`
	Level  int    `json:"level"` // level the token carries
}

// Simulate runs the decision of the Thing on the token auth would issue
// now, with the Thing's effective table. A confirmation is never given: a
// command that needs one ends at step 8.
func (s *Service) Simulate(in SimulateIn) (SimulateOut, error) {
	t, err := s.terminal(in.Terminal)
	if err != nil {
		return SimulateOut{}, err
	}
	var p *Profile
	if in.Profile != 0 {
		prof, _, err := s.profile(in.Profile)
		if err != nil {
			return SimulateOut{}, err
		}
		if prof.Level == 0 {
			return SimulateOut{}, Invalid("an admin session never reaches a Thing")
		}
		p = &prof
	}
	th, err := s.thing(in.Thing)
	if err != nil {
		return SimulateOut{}, err
	}
	kind, name, op := splitKey(in.Key)
	if kind == "" {
		return SimulateOut{}, Invalid("bad function")
	}
	tok, err := s.issue(t, p, in.Out, terminalTokenTTL)
	if err != nil {
		return SimulateOut{}, err
	}
	mode := authz.Normal
	if in.Minimal {
		mode = authz.Minimal
	}
	revocation, err := s.RevocationDoc()
	if err != nil {
		return SimulateOut{}, err
	}
	revoked, err := auth.ParseDoc(revocation, s.lookup, s.aud, auth.DocRevocation, th.ID)
	if err != nil {
		return SimulateOut{}, err
	}
	d := authz.Decide(authz.Check{
		Request:  authz.Request{Mode: mode, Verifier: authz.Thing, Token: tok, Keys: s.lookup, Aud: s.aud, Now: s.now()},
		Thing:    th.ID,
		Zones:    th.Zones,
		Table:    th.Effective,
		Revoked:  &revoked,
		Function: authz.Function{Kind: kind, Name: name, Op: authz.Op(op)},
	})
	out := SimulateOut{Allow: d.Allow, Step: d.Step, Reason: d.Reason}
	if d.Claims.Lvl != nil {
		out.Level = *d.Claims.Lvl
	} else if c, _, err := auth.Parse(tok, s.lookup); err == nil && c.Lvl != nil {
		out.Level = *c.Lvl
	}
	return out, nil
}
