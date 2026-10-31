package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/project-eria/go-wot/auth"
	"github.com/project-eria/go-wot/auth/authz"
)

// The API is served inside the TLS tunnel from the app (§3.6): the relay
// carries it without reading it. out comes from the relay's certificate,
// never from the request.

type outKey struct{}

func isOut(r *http.Request) bool {
	out, _ := r.Context().Value(outKey{}).(bool)
	return out
}

func withOut(ctx context.Context, out bool) context.Context {
	return context.WithValue(ctx, outKey{}, out)
}

const maxRequest = 16 << 10

func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/challenge", handle(func(r *http.Request, in struct{ Kid string }) (any, error) {
		ch, err := s.Challenge(in.Kid)
		return map[string]string{"challenge": ch}, err
	}))
	// A terminal asks to enroll (inner relay only), then waits for the admin.
	mux.HandleFunc("POST /v1/requests", handle(func(r *http.Request, in struct {
		Identity KeyIn
		Bio      *KeyIn
		Device   string
	}) (any, error) {
		return s.Ask(in.Identity, in.Bio, in.Device, isOut(r))
	}))
	mux.HandleFunc("GET /v1/requests/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !s.RequestOpen(r.PathValue("id")) {
			reply(w, nil, ErrNotFound)
			return
		}
		reply(w, map[string]string{"status": "open"}, nil)
	})
	mux.HandleFunc("POST /v1/bootstrap", handle(func(r *http.Request, in BootstrapIn) (any, error) {
		id, err := s.Bootstrap(in, isOut(r))
		return map[string]string{"terminal": id}, err
	}))
	mux.HandleFunc("POST /v1/terminal-token", handle(func(r *http.Request, in struct{ Proof Proof }) (any, error) {
		tok, err := s.TerminalToken(in.Proof, isOut(r))
		return map[string]string{"token": tok}, err
	}))
	mux.HandleFunc("POST /v1/sessions", handle(func(r *http.Request, in struct {
		Proof   Proof
		Profile int64
		Pin     string
		Bio     bool
	}) (any, error) {
		if in.Bio {
			return s.OpenBioSession(in.Proof, isOut(r))
		}
		return s.OpenSession(in.Proof, in.Profile, in.Pin, isOut(r))
	}))
	mux.HandleFunc("POST /v1/sessions/renew", handle(func(r *http.Request, in struct {
		Session string
		Proof   Proof
		Gesture bool
	}) (any, error) {
		return s.Renew(in.Session, in.Proof, in.Gesture, isOut(r))
	}))
	mux.HandleFunc("POST /v1/sessions/end", handle(func(r *http.Request, in struct{ Session string }) (any, error) {
		s.EndSession(in.Session)
		return nil, nil
	}))
	mux.HandleFunc("POST /v1/admin/open", handle(func(r *http.Request, in struct {
		Proof      Proof
		Passphrase string
	}) (any, error) {
		return s.AdminOpen(in.Proof, in.Passphrase, isOut(r))
	}))
	mux.HandleFunc("POST /v1/admin/validate", handle(func(r *http.Request, in struct {
		Request string
		Proof   Proof
	}) (any, error) {
		return nil, s.AdminValidate(in.Request, in.Proof, isOut(r))
	}))
	// The admin's phone lists the requests it may validate.
	mux.HandleFunc("POST /v1/validations", handle(func(r *http.Request, in struct{ Proof Proof }) (any, error) {
		return s.Validations(in.Proof, isOut(r))
	}))
	mux.HandleFunc("POST /v1/admin/session", handle(func(r *http.Request, in struct {
		Request string
		Proof   Proof
	}) (any, error) {
		return s.AdminSession(in.Request, in.Proof, isOut(r))
	}))

	// Names for the sign-in screen: never levels nor the admin.
	mux.HandleFunc("GET /v1/profiles/names", func(w http.ResponseWriter, r *http.Request) {
		list, err := s.Profiles()
		names := []Profile{}
		for _, p := range list {
			if p.Level > 0 {
				names = append(names, Profile{ID: p.ID, Name: p.Name})
			}
		}
		reply(w, names, err)
	})

	// The interfaces' configuration: read by the relays (nothing secret in
	// it), changed by the people allowed to.
	mux.HandleFunc("GET /v1/config", func(w http.ResponseWriter, r *http.Request) {
		if since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64); since > 0 && since >= s.configVersion() {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		c, err := s.Config()
		reply(w, c, err)
	})
	// Pages: level ≤ 1 and a signed-in person, never a terminal token, inner
	// relay only (§3.6); or the admin.
	pageEditor := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			c, err := s.authenticate(bearer(r), authz.Relay)
			person := err == nil && c.Profile == auth.ProfilePerson && *c.Lvl <= 1
			if _, err := s.asAdmin(bearer(r)); (err != nil && !person) || isOut(r) {
				reply(w, nil, ErrDenied)
				return
			}
			h(w, r)
		}
	}
	mux.HandleFunc("POST /v1/pages", pageEditor(handle(func(r *http.Request, in Page) (any, error) {
		return s.SavePage(in)
	})))
	mux.HandleFunc("DELETE /v1/pages/{id}", pageEditor(func(w http.ResponseWriter, r *http.Request) {
		reply(w, nil, s.DeletePage(r.PathValue("id")))
	}))
	// The screen the app deduced, on any token of the terminal itself.
	mux.HandleFunc("POST /v1/screen", handle(func(r *http.Request, in struct{ Screen string }) (any, error) {
		c, err := s.authenticate(bearer(r), authz.Relay)
		if err != nil {
			return nil, err
		}
		return nil, s.ReportScreen(c.Term, in.Screen)
	}))

	// The revocation list is public and signed: relays fetch it.
	mux.HandleFunc("GET /v1/revocations", func(w http.ResponseWriter, r *http.Request) {
		doc, err := s.RevocationDoc()
		reply(w, map[string]string{"doc": doc}, err)
	})
	// So are the tables: the relay decides on the observations (§3.6).
	mux.HandleFunc("GET /v1/tables/{id}", func(w http.ResponseWriter, r *http.Request) {
		doc, _, err := s.TableDoc(r.PathValue("id"))
		reply(w, map[string]string{"doc": doc}, err)
	})

	// Blocking: the admin, or a parent from another terminal (§2.10).
	mux.HandleFunc("POST /v1/terminals/{id}/block", func(w http.ResponseWriter, r *http.Request) {
		c, err := s.authenticate(bearer(r), authz.Relay) // a person token, as Things and relays take it
		if err != nil {
			c, err = s.asAdmin(bearer(r))
		}
		if err == nil {
			err = s.BlockTerminal(r.PathValue("id"), c)
		}
		reply(w, nil, err)
	})

	// Administration: an admin token, never through the outer relay.
	admin := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if _, err := s.asAdmin(bearer(r)); err != nil || isOut(r) {
				reply(w, nil, ErrDenied)
				return
			}
			h(w, r)
		}
	}
	mux.HandleFunc("GET /v1/profiles", admin(func(w http.ResponseWriter, r *http.Request) {
		list, err := s.Profiles()
		reply(w, list, err)
	}))
	mux.HandleFunc("POST /v1/profiles", admin(handle(func(r *http.Request, in struct {
		Name   string
		Level  int
		Secret string
	}) (any, error) {
		return s.CreateProfile(in.Name, in.Level, in.Secret)
	})))
	mux.HandleFunc("PATCH /v1/profiles/{id}", admin(handle(func(r *http.Request, in struct {
		Name   *string
		Level  *int
		Secret *string
	}) (any, error) {
		return nil, s.UpdateProfile(pathID(r), in.Name, in.Level, in.Secret)
	})))
	mux.HandleFunc("DELETE /v1/profiles/{id}", admin(func(w http.ResponseWriter, r *http.Request) {
		reply(w, nil, s.DeleteProfile(pathID(r)))
	}))
	mux.HandleFunc("GET /v1/terminals", admin(func(w http.ResponseWriter, r *http.Request) {
		list, err := s.Terminals()
		reply(w, list, err)
	}))
	mux.HandleFunc("GET /v1/requests", admin(func(w http.ResponseWriter, r *http.Request) {
		list, err := s.Requests()
		reply(w, list, err)
	}))
	mux.HandleFunc("POST /v1/requests/{id}/enroll", handle(func(r *http.Request, in EnrollIn) (any, error) {
		c, err := s.asAdmin(bearer(r))
		if err != nil || isOut(r) {
			return nil, ErrDenied
		}
		return s.Enroll(r.PathValue("id"), in, c)
	}))
	mux.HandleFunc("PATCH /v1/terminals/{id}", admin(handle(func(r *http.Request, in TerminalChange) (any, error) {
		return nil, s.UpdateTerminal(r.PathValue("id"), in)
	})))
	mux.HandleFunc("DELETE /v1/terminals/{id}", admin(func(w http.ResponseWriter, r *http.Request) {
		reply(w, nil, s.DeleteTerminal(r.PathValue("id")))
	}))
	for path, op := range map[string]func(string) error{
		"unblock": s.UnblockTerminal, "reset-counter": s.ResetCounter,
	} {
		mux.HandleFunc("POST /v1/terminals/{id}/"+path, admin(func(w http.ResponseWriter, r *http.Request) {
			reply(w, nil, op(r.PathValue("id")))
		}))
	}
	mux.HandleFunc("PATCH /v1/terminals/{id}/screen", admin(handle(func(r *http.Request, in struct {
		Screen   string
		HomePage string
	}) (any, error) {
		return nil, s.SetScreen(r.PathValue("id"), in.Screen, in.HomePage)
	})))
	mux.HandleFunc("PUT /v1/config/home-page", pageEditor(handle(func(r *http.Request, in struct{ Page string }) (any, error) {
		return nil, s.SetHomePage(in.Page)
	})))
	mux.HandleFunc("PUT /v1/config/contexts", admin(handle(func(r *http.Request, in []Context) (any, error) {
		return nil, s.SetContexts(in)
	})))
	mux.HandleFunc("PUT /v1/config/hidden", admin(handle(func(r *http.Request, in []string) (any, error) {
		return nil, s.SetHidden(in)
	})))
	mux.HandleFunc("POST /v1/config/manual", admin(handle(func(r *http.Request, in ManualThing) (any, error) {
		return nil, s.AddManual(in)
	})))
	mux.HandleFunc("DELETE /v1/config/manual/{id}", admin(func(w http.ResponseWriter, r *http.Request) {
		reply(w, nil, s.RemoveManual(r.PathValue("id")))
	}))
	mux.HandleFunc("POST /v1/terminals/{id}/validator", admin(handle(func(r *http.Request, in struct{ Proof Proof }) (any, error) {
		return nil, s.SetValidator(r.PathValue("id"), true, &in.Proof)
	})))
	mux.HandleFunc("DELETE /v1/terminals/{id}/validator", admin(func(w http.ResponseWriter, r *http.Request) {
		reply(w, nil, s.SetValidator(r.PathValue("id"), false, nil))
	}))
	// A new bio key (§1.2): the phone asks, the admin confirms or refuses.
	mux.HandleFunc("POST /v1/bio", handle(func(r *http.Request, in struct {
		Proof Proof
		Key   KeyIn
	}) (any, error) {
		return s.NewBio(in.Proof, in.Key, isOut(r))
	}))
	mux.HandleFunc("POST /v1/bio/state", handle(func(r *http.Request, in struct{ Proof Proof }) (any, error) {
		return s.BioStateOf(in.Proof)
	}))
	mux.HandleFunc("POST /v1/terminals/{id}/bio", admin(handle(func(r *http.Request, in struct{ Proof *Proof }) (any, error) {
		return nil, s.ConfirmBio(r.PathValue("id"), in.Proof)
	})))
	mux.HandleFunc("DELETE /v1/terminals/{id}/bio", admin(func(w http.ResponseWriter, r *http.Request) {
		reply(w, nil, s.RefuseBio(r.PathValue("id")))
	}))
	// Orders to the master (§3.5): the admin's computer hands one to the
	// phone and takes its signature back; the phone signs without a token.
	mux.HandleFunc("POST /v1/orders", handle(func(r *http.Request, in OrderIn) (any, error) {
		c, err := s.asAdmin(bearer(r))
		if err != nil || isOut(r) {
			return nil, ErrDenied
		}
		return s.AskOrder(c, in)
	}))
	mux.HandleFunc("GET /v1/orders/{id}", func(w http.ResponseWriter, r *http.Request) {
		c, err := s.asAdmin(bearer(r))
		if err != nil || isOut(r) {
			reply(w, nil, ErrDenied)
			return
		}
		v, err := s.OrderSignature(r.PathValue("id"), c)
		reply(w, v, err)
	})
	mux.HandleFunc("POST /v1/orders/{id}/sign", handle(func(r *http.Request, in struct {
		Kid string
		Sig []byte
	}) (any, error) {
		return nil, s.SignOrder(r.PathValue("id"), in.Kid, in.Sig, isOut(r))
	}))
	// The relay's own service token (§3.6).
	mux.HandleFunc("POST /v1/relay/challenge", func(w http.ResponseWriter, r *http.Request) {
		ch, err := s.RelayChallenge(r)
		reply(w, map[string]string{"challenge": ch}, err)
	})
	mux.HandleFunc("POST /v1/relay/token", handle(func(r *http.Request, in struct {
		Challenge string
		Sig       []byte
	}) (any, error) {
		tok, err := s.RelayToken(r, in.Challenge, in.Sig)
		return map[string]string{"token": tok}, err
	}))
	// Requirements per Thing (§2.4, §2.5) and the simulator (F106).
	mux.HandleFunc("GET /v1/things", admin(func(w http.ResponseWriter, r *http.Request) {
		list, err := s.Things()
		reply(w, list, err)
	}))
	mux.HandleFunc("POST /v1/things/{id}/adopt", admin(func(w http.ResponseWriter, r *http.Request) {
		reply(w, nil, s.AdoptThing(r.PathValue("id")))
	}))
	mux.HandleFunc("DELETE /v1/things/{id}", admin(func(w http.ResponseWriter, r *http.Request) {
		reply(w, nil, s.ForgetThing(r.PathValue("id")))
	}))
	mux.HandleFunc("PUT /v1/things/{id}/zones", admin(handle(func(r *http.Request, zones []string) (any, error) {
		return nil, s.SetZones(r.PathValue("id"), zones)
	})))
	mux.HandleFunc("PUT /v1/things/{id}/rules", admin(handle(func(r *http.Request, in struct {
		State string
		Key   string
		Rule  *Rule
	}) (any, error) {
		return nil, s.SetRule(r.PathValue("id"), in.State, in.Key, in.Rule)
	})))
	mux.HandleFunc("POST /v1/simulate", admin(handle(func(r *http.Request, in SimulateIn) (any, error) {
		return s.Simulate(in)
	})))
	mux.HandleFunc("POST /v1/terminals/revoke-all", handle(func(r *http.Request, in struct{ Proof Proof }) (any, error) {
		c, err := s.asAdmin(bearer(r))
		if err != nil || isOut(r) {
			return nil, ErrDenied
		}
		n, err := s.RevokeAll(in.Proof, c)
		return map[string]int{"revoked": n}, err
	}))
	return mux
}

// handle decodes a bounded, strict JSON body into In and replies with the
// result.
func handle[In any](f func(*http.Request, In) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in In
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequest))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&in); err != nil {
			reply(w, nil, ErrInvalid)
			return
		}
		out, err := f(r, in)
		reply(w, out, err)
	}
}

func reply(w http.ResponseWriter, v any, err error) {
	w.Header().Set("Content-Type", "application/json")
	if err == nil {
		if v == nil {
			v = map[string]bool{"ok": true}
		}
		json.NewEncoder(w).Encode(v)
		return
	}
	// Only a weak new secret says why: a credential is never detailed.
	status, msg := http.StatusBadRequest, "invalid request"
	var retry *RetryError
	switch {
	case errors.As(err, &retry):
		w.Header().Set("Retry-After", strconv.Itoa(int(retry.Wait.Seconds())))
		status, msg = http.StatusTooManyRequests, "retry later"
	case errors.Is(err, ErrDenied):
		status, msg = http.StatusForbidden, "denied"
	case errors.Is(err, ErrNotFound):
		status, msg = http.StatusNotFound, "not found"
	case errors.As(err, new(Invalid)):
		msg = err.Error()
	}
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func bearer(r *http.Request) string {
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
}

func pathID(r *http.Request) int64 {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id
}
