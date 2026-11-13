package main

import (
	"encoding/base64"
	"fmt"

	"github.com/project-eria/go-wot/auth"
)

// ApplyAdminKeys takes the coordinator's registry of admin keys (revue de
// simplification, piste 7), signed by a deployment key: one registry, the
// coordinator's, here only applied. A YubiKey becomes a validator key; a phone
// whose ACTIVE bio key is the one named becomes a validator phone (a pending
// bio key is ignored: its activation stays the admin's « has Léa changed
// Face ID? », G35). It only adds: removing a validator stays a gesture here
// (block the phone, or unset it) as well as at the coordinator. The bootstrap's
// YubiKey stays, so a first admin session needs no coordinator (F065).
//
// An older registry is refused; the same version again is applied again
// (idempotent), so a phone enrolled after the publication becomes a
// validator at the coordinator's next one.
func (s *Service) ApplyAdminKeys(signed auth.Signed) error {
	var k auth.AdminKeys
	if err := signed.Open(auth.AdminKeysPrefix, s.deploy, &k); err != nil || k.Version <= 0 {
		s.store.record(Entry{Type: "document.refused", Object: "admin-keys", Result: "denied", Reason: "signature"})
		s.alertOnce("signature:coordinator", "Signature invalide : coordinateur")
		return ErrDenied
	}
	var held int64
	s.store.db.QueryRow(`SELECT value FROM state WHERE key = 'admin_keys'`).Scan(&held)
	if k.Version < held {
		return ErrDenied // replayed, older than the registry applied
	}
	// Every entry checked before any is applied: never half a registry.
	pubs := make([]auth.PublicKey, len(k.Keys))
	for i, e := range k.Keys {
		raw, err := base64.RawURLEncoding.Strict().DecodeString(e.Key)
		if err != nil {
			return ErrInvalid
		}
		pub, err := auth.ParsePublicKey(auth.Alg(e.Alg), raw)
		if err != nil || pub.KID() != e.Kid {
			return ErrInvalid
		}
		pubs[i] = pub
	}
	for i, e := range k.Keys {
		pub := pubs[i]
		// A phone first: its ACTIVE bio key, on an active phone.
		res, err := s.store.db.Exec(`UPDATE terminals SET validator = 1 WHERE type = 'phone' AND status = 'active'
			AND validator = 0 AND id IN (SELECT terminal FROM keys WHERE kid = ? AND role = 'bio' AND status = 'active')`, pub.KID())
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			s.store.log("terminal.validator", fmt.Sprintf("%s true (coordinator's registry)", pub.KID()))
			s.notify("Nouveau téléphone validateur : " + e.Name)
		}
		// A key of its own only when the registry says YubiKey: a phone
		// not enrolled yet never becomes a validator key by itself.
		if e.Kind == "yubikey" && pub.Alg() == auth.P256 {
			res, err := s.store.db.Exec(`INSERT INTO keys (kid, role, alg, raw, name) VALUES (?, 'validator', ?, ?, ?)
				ON CONFLICT (kid) DO NOTHING`, pub.KID(), pub.Alg(), pub.Bytes(), e.Name)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n > 0 {
				s.store.log("validator.key", fmt.Sprintf("%s %s (coordinator's registry)", e.Name, pub.KID()))
				s.notify("Nouvelle clé validatrice : " + e.Name)
			}
		}
	}
	_, err := s.store.db.Exec(`INSERT INTO state (key, value) VALUES ('admin_keys', ?)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value`, k.Version)
	return err
}
