package main

import (
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/project-eria/go-wot/auth"
	"github.com/project-eria/go-wot/auth/authz"
)

// The Things channel (§2.4, F017): plain HTTP without token, in the home
// automation network, integrity by signature. A Thing sends its TD, signed by
// its app key, and pulls its table and the revocation list; manager-contexts
// publishes the states, signed too.
// Only a rate limit: everything served is public, and what comes in can
// only add unclassified functions or close functions.

const maxTD = 64 << 10

func (s *Service) ChannelHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/things/td", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2*maxTD)) // base64 when signed
		if err != nil {
			reply(w, nil, ErrInvalid)
			return
		}
		reply(w, nil, s.ReceiveSignedTD(body))
	})
	mux.HandleFunc("GET /v1/things/{id}/table", func(w http.ResponseWriter, r *http.Request) {
		tok, version, err := s.TableDoc(r.PathValue("id"))
		signedDoc(w, r, tok, version, err)
	})
	mux.HandleFunc("GET /v1/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		tok, err := s.HeartbeatDoc(r.URL.Query().Get("nonce"), r.URL.Query()["thing"])
		if err != nil {
			reply(w, nil, err)
			return
		}
		w.Header().Set("Content-Type", "application/jwt")
		w.Write([]byte(tok))
	})
	mux.HandleFunc("POST /v1/heartbeat/ack", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxTD))
		if err != nil {
			reply(w, nil, ErrInvalid)
			return
		}
		reply(w, nil, s.ReceiveAck(body))
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
	// The master's registry of admin keys (piste 7), signed by the deployment key.
	mux.HandleFunc("POST /v1/admin/keys", handle(func(r *http.Request, in auth.Signed) (any, error) {
		return nil, s.ApplyAdminKeys(in)
	}))
	// The master's journal lines (§4.5), signed by the deployment key.
	mux.HandleFunc("POST /v1/journal", receiveBatch(func(r *http.Request, doc auth.Signed) error {
		return s.ReceiveJournal(sourceMaster, s.deploy, doc)
	}))
	// Whole days erased (§4.5), by the master's validated order.
	mux.HandleFunc("POST /v1/journal/erase", receiveBatch(func(r *http.Request, doc auth.Signed) error {
		return s.EraseJournal(doc)
	}))
	// The Things' journal lines (§4.5, step 5e-4), signed by their app's key.
	mux.HandleFunc("POST /v1/things/journal", func(w http.ResponseWriter, r *http.Request) {
		var in auth.SignedBy
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&in); err != nil {
			reply(w, nil, ErrInvalid)
			return
		}
		reply(w, nil, s.ReceiveThingJournal(in))
	})
	mux.HandleFunc("POST /v1/service/challenge", handle(func(r *http.Request, in struct{ Kid string }) (any, error) {
		ch, err := s.ServiceChallenge(in.Kid)
		return map[string]string{"challenge": ch}, err
	}))
	mux.HandleFunc("POST /v1/service/token", handle(func(r *http.Request, in struct {
		Kid       string
		Challenge string
		Sig       []byte
		Thing     string // the Thing it is for; "" for the master
	}) (any, error) {
		tok, err := s.ServiceToken(in.Kid, in.Challenge, in.Sig, in.Thing)
		return map[string]string{"token": tok}, err
	}))
	mux.HandleFunc("PUT /v1/states", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<10))
		if err != nil {
			reply(w, nil, ErrInvalid)
			return
		}
		reply(w, nil, s.ReceiveStates(body))
	})
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
// signed out), from outside or not, this function of this Thing. With App
// (an app id), its service token instead: no terminal, no profile.
type SimulateIn struct {
	App      string `json:"app"`
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
	// The grant that made it allowed: denied without it ("" when the level
	// was enough), and the step it would have ended at then.
	Grant       string `json:"grant,omitempty"`
	WithoutStep int    `json:"withoutStep,omitempty"`
	// Past step 5: where the request comes from (local, remote, outside)
	// and the level the function requires there (0: nobody), for the
	// admin's explanation of a refusal.
	Place string `json:"place,omitempty"`
	Need  int    `json:"need"`
}

// Simulate runs the decision of the Thing on the token auth would issue
// now, with the Thing's effective table. A confirmation is never given: a
// command that needs one ends at step 8.
func (s *Service) Simulate(in SimulateIn) (SimulateOut, error) {
	var t Terminal
	var err error
	if in.App == "" {
		t, err = s.terminal(in.Terminal)
	}
	if err != nil {
		return SimulateOut{}, err
	}
	var p *Profile
	if in.Profile != 0 && in.App == "" {
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
	var tok string
	if in.App != "" {
		var kid string
		if s.store.db.QueryRow(`SELECT kid FROM apps WHERE id = ? AND kid != ''`, in.App).Scan(&kid) != nil {
			return SimulateOut{}, ErrNotFound
		}
		tok, _, err = s.appToken(in.App, th.ID, s.now())
	} else {
		tok, _, err = s.issue(t, p, in.Out, terminalTokenTTL, "")
	}
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
	decide := func(tok string) authz.Decision {
		return authz.Decide(authz.Check{
			Request:  authz.Request{Mode: mode, Verifier: authz.Thing, Token: tok, Keys: s.lookup, Aud: s.aud, Now: s.now()},
			Thing:    th.ID,
			Zones:    th.Zones,
			Table:    th.Effective,
			Revoked:  &revoked,
			Function: authz.Function{Kind: kind, Name: name, Op: authz.Op(op)},
		})
	}
	d := decide(tok)
	out := SimulateOut{Allow: d.Allow, Step: d.Step, Reason: d.Reason}
	if d.Allow || d.Step >= 7 {
		// Step 5's locality, as authz.Decide: the table's rule at that place.
		c, loc := d.Claims, authz.Remote
		switch {
		case c.Out != nil && *c.Out:
			loc = authz.Outside
		case c.Zone != "" && slices.Contains(th.Zones, c.Zone):
			loc = authz.Local
		}
		fn := authz.Function{Kind: kind, Name: name, Op: authz.Op(op)}
		out.Place, out.Need = loc.String(), th.Effective[fn.Key()].Levels[loc]
	}
	// Allowed with grants: which one? Denied without them, the first
	// that alone allows it.
	if c := d.Claims; d.Allow && len(c.Grants) > 0 {
		with := func(grants []string) authz.Decision {
			c.Grants = grants
			t, _ := auth.Sign(s.key, s.kid, c)
			return decide(t)
		}
		if without := with(nil); !without.Allow {
			out.WithoutStep = without.Step
			for _, g := range d.Claims.Grants {
				if with([]string{g}).Allow {
					out.Grant = g
					break
				}
			}
		}
	}
	if d.Claims.Lvl != nil {
		out.Level = *d.Claims.Lvl
	} else if c, err := auth.Parse(tok, s.lookup); err == nil && c.Lvl != nil {
		out.Level = *c.Lvl
	}
	return out, nil
}
