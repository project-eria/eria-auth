package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

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
	mux.HandleFunc("POST /v1/enroll", handle(func(r *http.Request, in struct {
		Code     string
		Identity KeyIn
		Bio      *KeyIn
	}) (any, error) {
		id, err := s.Enroll(in.Code, in.Identity, in.Bio, isOut(r))
		return map[string]string{"terminal": id, "status": "pending"}, err
	}))
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
		return nil, s.AdminValidate(in.Request, in.Proof)
	}))
	mux.HandleFunc("POST /v1/admin/session", handle(func(r *http.Request, in struct {
		Request string
		Proof   Proof
	}) (any, error) {
		return s.AdminSession(in.Request, in.Proof, isOut(r))
	}))

	// The revocation list is public and signed: relays fetch it.
	mux.HandleFunc("GET /v1/revocations", func(w http.ResponseWriter, r *http.Request) {
		doc, err := s.RevocationDoc()
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
	mux.HandleFunc("POST /v1/terminals", admin(handle(func(r *http.Request, in TerminalChange) (any, error) {
		return s.CreateTerminal(in)
	})))
	mux.HandleFunc("PATCH /v1/terminals/{id}", admin(handle(func(r *http.Request, in TerminalChange) (any, error) {
		return nil, s.UpdateTerminal(r.PathValue("id"), in)
	})))
	mux.HandleFunc("DELETE /v1/terminals/{id}", admin(func(w http.ResponseWriter, r *http.Request) {
		reply(w, nil, s.DeleteTerminal(r.PathValue("id")))
	}))
	for path, op := range map[string]func(string) error{
		"confirm": s.ConfirmTerminal, "unblock": s.UnblockTerminal, "reset-counter": s.ResetCounter,
	} {
		mux.HandleFunc("POST /v1/terminals/{id}/"+path, admin(func(w http.ResponseWriter, r *http.Request) {
			reply(w, nil, op(r.PathValue("id")))
		}))
	}
	mux.HandleFunc("POST /v1/terminals/{id}/enrollment", admin(func(w http.ResponseWriter, r *http.Request) {
		e, err := s.NewEnrollment(r.PathValue("id"))
		reply(w, e, err)
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
