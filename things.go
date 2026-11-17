package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	zlog "github.com/rs/zerolog/log"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/project-eria/eria-core/model"
	"github.com/project-eria/go-wot/auth"
	"github.com/project-eria/go-wot/auth/authz"
)

// Requirements per Thing (AUTH-DESIGN §2.4, §2.5). A Thing sends its TD on
// the Things channel; auth lists its functions. It gets a table only once
// the admin adopted it: an unknown TD changes nothing, and the defaults come
// from the capabilities seen at adoption. A function with no default and no
// rule from the admin is None (« fonction non classée »). The effective
// table (defaults, then the admin's rules, then the overrides of the active
// states) is signed for the Thing, with its rooms.
//
// ponytail: the TD is not signed until the app keys (§4.7 step 3); a forged
// TD can only add unclassified functions or ask for a new adoption.

// ThingRecord is a Thing as the admin sees it.
type ThingRecord struct {
	ID        string            `json:"id"`
	Title     string            `json:"title"`
	Types     []string          `json:"types"`            // capabilities adopted
	SeenTypes []string          `json:"seenTypes"`        // capabilities of the last TD
	Functions []string          `json:"functions"`        // keys of the last TD
	Zones     []string          `json:"zones"`            // rooms (§2.2)
	Adopted   bool              `json:"adopted"`          // has a table
	Seen      int64             `json:"seen"`             // last TD received
	App       string            `json:"app"`              // id of the app that signs its TD, "" before step 3
	Rules     map[string]Rule   `json:"rules"`            // set by the admin
	Defaults  map[string]Rule   `json:"defaults"`         // from the adopted capabilities
	// The defaults the capabilities of the last TD would give, while they
	// differ from the adopted ones: what accepting them (adopt again) opens.
	SeenDefaults map[string]Rule `json:"seenDefaults"` // null unless the types changed: never absent, so the app tells « nothing changes » from an older auth
	Effective auth.Table        `json:"effective"`        // what the Thing gets now
	States    map[string]States `json:"states,omitempty"` // overrides, by state then key
	Groups    []GroupView       `json:"groups"`           // eria:groups of the last TD, with the admin's choices
}

// Rule is a requirement as stored: levels local, remote, outside (0 = None)
// and confirm_when.
type Rule = auth.Rule

// States are the overrides of one state, by function key.
type States = map[string]Rule

var (
	thingID  = regexp.MustCompile(`^[A-Za-z0-9:._@-]{1,128}$`) // @: app controllers, urn:eria:app:controler:<app>@<node>
	nameRe   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	zoneRe   = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	maxFuncs = 200
)

// TDIn is the part of a TD auth reads.
type TDIn struct {
	ID         string                     `json:"id"`
	Title      string                     `json:"title"`
	Types      json.RawMessage            `json:"@type"`
	Properties map[string]json.RawMessage `json:"properties"`
	Actions    map[string]json.RawMessage `json:"actions"`
	Events     map[string]json.RawMessage `json:"events"`
	Groups     []Group                    `json:"eria:groups"`
}

// functions lists the keys of a TD's functions (§2.4): a property is read,
// and written unless readOnly; an action invoked; an event read.
func (td TDIn) functions() ([]string, error) {
	var keys []string
	for name, raw := range td.Properties {
		var p struct {
			ReadOnly  bool `json:"readOnly"`
			WriteOnly bool `json:"writeOnly"`
		}
		json.Unmarshal(raw, &p)
		if !p.WriteOnly {
			keys = append(keys, "property/"+name+"/read")
		}
		if !p.ReadOnly {
			keys = append(keys, "property/"+name+"/write")
		}
	}
	for name := range td.Actions {
		keys = append(keys, "action/"+name+"/invoke")
	}
	for name := range td.Events {
		keys = append(keys, "event/"+name+"/read")
	}
	for _, k := range keys {
		_, name, _ := splitKey(k)
		for _, seg := range strings.Split(name, "/") {
			if !nameRe.MatchString(seg) {
				return nil, Invalid("affordance name not allowed: " + k)
			}
		}
	}
	if len(keys) > maxFuncs {
		return nil, Invalid("too many functions")
	}
	slices.Sort(keys)
	return keys, nil
}

// types reads @type, a string or a list.
func (td TDIn) types() []string {
	var list []string
	if json.Unmarshal(td.Types, &list) != nil {
		var one string
		if json.Unmarshal(td.Types, &one) == nil && one != "" {
			list = []string{one}
		}
	}
	list = slices.DeleteFunc(list, func(t string) bool { _, ok := model.Models[t]; return !ok })
	slices.Sort(list)
	return slices.Compact(list)
}

// ReceiveTD records the TD a Thing sent. A new Thing waits for the admin; an
// adopted one whose capabilities changed is flagged.
// ReceiveSignedTD takes a TD as a Thing sends it: signed by its app key
// (auth.SignedBy, step 3d), or plain from a Thing without a key yet.
func (s *Service) ReceiveSignedTD(body []byte) error {
	app := ""
	var signed auth.SignedBy
	if json.Unmarshal(body, &signed) == nil && signed.Kid != "" {
		id, pub, err := s.appKey(signed.Kid)
		if err != nil {
			return ErrDenied
		}
		if body, err = signed.Verify(auth.TDPrefix, []auth.PublicKey{pub}); err != nil {
			s.badSignature(id, "td")
			return ErrDenied
		}
		app = id
	}
	var td TDIn
	if err := json.Unmarshal(body, &td); err != nil {
		return ErrInvalid
	}
	if err := s.ReceiveTD(td, app); err != nil {
		return err
	}
	// Only from a TD taken above, and only manager-contexts' Thing.
	if list, ok := contextsOfTD(td); ok && td.ID == statesThing && s.fromStatesApp(app) {
		s.takeContexts(list)
	}
	return nil
}

// statesThing is manager-contexts' Thing, whose TD lists the contexts.
const statesThing = "urn:eria:manager:context"

// contextsOfTD reads the contexts manager-contexts offers to people, the one
// source of the list: the choices (const, title) of its property "chosen",
// in their order.
func contextsOfTD(td TDIn) ([]Context, bool) {
	raw, ok := td.Properties["chosen"]
	if !ok {
		return nil, false
	}
	var p struct {
		Items struct {
			OneOf []struct {
				Const string `json:"const"`
				Title string `json:"title"`
			} `json:"oneOf"`
		} `json:"items"`
	}
	if json.Unmarshal(raw, &p) != nil {
		return nil, false
	}
	list := []Context{}
	for _, c := range p.Items.OneOf {
		if c.Const == "" {
			continue
		}
		label := c.Title
		if label == "" {
			label = c.Const
		}
		list = append(list, Context{ID: c.Const, Label: label})
	}
	return list, true
}

// fromStatesApp: a TD signed by the states app (manager-contexts), or a
// plain TD while that app has no key here, as for its states.
func (s *Service) fromStatesApp(app string) bool {
	var name string
	if app != "" {
		s.store.db.QueryRow(`SELECT name FROM apps WHERE id = ?`, app).Scan(&name)
		return name == s.statesApp
	}
	var n int
	s.store.db.QueryRow(`SELECT count(*) FROM apps WHERE name = ? AND kid != ''`, s.statesApp).Scan(&n)
	return n == 0
}

// takeContexts replaces the contexts when manager-contexts' list changed.
func (s *Service) takeContexts(list []Context) {
	c, err := s.Config()
	if err == nil && slices.Equal(c.Contexts, list) {
		return
	}
	if err := s.SetContexts(list); err != nil {
		zlog.Warn().Err(err).Msg("[things] contexts of manager-contexts not taken")
	}
}

// ReceiveTD records the TD of a Thing. The first app to sign it owns the
// Thing: from then on only that app's TDs are taken.
//
// ponytail: a Thing nobody signed for still takes plain TDs (the ESP32 until
// step 3e, the apps the agent did not install); refused once activated (step 5).
func (s *Service) ReceiveTD(td TDIn, app string) error {
	if !thingID.MatchString(td.ID) || len(td.Title) > 128 {
		return Invalid("bad id or title")
	}
	funcs, err := td.functions()
	if err != nil {
		return err
	}
	types := td.types()
	groups := td.groups(funcs)
	old, err := s.thing(td.ID)
	switch {
	case errors.Is(err, ErrNotFound):
		_, err = s.store.db.Exec(`INSERT INTO things (id, title, seen_types, functions, groups, seen, app) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			td.ID, td.Title, jsonText(types), jsonText(funcs), jsonText(groups), s.now().Unix(), app)
		if err == nil {
			s.store.log("thing.new", td.ID)
			s.mu.Lock()
			alert := s.now().Sub(s.newAt) > 10*time.Minute // a node starting sends many
			if alert {
				s.newAt = s.now()
			}
			s.mu.Unlock()
			if alert {
				s.notify("Nouvel appareil à classer")
			}
		}
		return err
	case err != nil:
		return err
	case old.App != "" && old.App != app:
		return ErrDenied // another app, or a plain TD for a Thing that has one
	}
	_, err = s.store.db.Exec(`UPDATE things SET title = ?, seen_types = ?, functions = ?, groups = ?, seen = ?, app = ? WHERE id = ?`,
		td.Title, jsonText(types), jsonText(funcs), jsonText(groups), s.now().Unix(), app, td.ID)
	if err != nil {
		return err
	}
	if err := s.pruneGroups(td.ID, groups); err != nil {
		return err
	}
	// Regrouping changes what « accept » applies: journaled like a new TD.
	declared := []Group{}
	for _, g := range old.Groups {
		declared = append(declared, g.Group)
	}
	if jsonText(declared) != jsonText(groups) {
		s.store.log("thing.groups", fmt.Sprintf("%s %s", td.ID, jsonText(groups)))
	}
	if old.App == "" && app != "" {
		s.store.log("thing.app", td.ID+" signed by app "+app)
	}
	if !slices.Equal(old.Functions, funcs) || !slices.Equal(old.SeenTypes, types) {
		s.store.log("thing.td", td.ID)
		if old.Adopted && !slices.Equal(old.Types, types) {
			s.notify("Capacités d'un appareil changées")
		}
		s.bumpThing(td.ID)
	}
	return nil
}

// --- Defaults (§2.4): deduced from the capability ---

var (
	read    = Rule{Levels: [3]int{9, 9, 8}}
	command = Rule{Levels: [3]int{9, 8, authz.None}, Confirm: auth.Never}
	parents = Rule{Levels: [3]int{1, 1, authz.None}, Confirm: auth.Never}
)

// exceptions to read / command, by capability then key.
var exceptions = map[string]map[string]Rule{
	"GarageDoor": {
		"property/open/read":   {Levels: [3]int{9, 1, 1}},
		"property/closed/read": {Levels: [3]int{9, 1, 1}},
		"property/moving/read": {Levels: [3]int{9, 1, 1}},
		"action/open/invoke":   {Levels: [3]int{1, 1, 1}, Confirm: auth.OutsideRoom},
		"action/close/invoke":  {Levels: [3]int{1, 1, 1}, Confirm: auth.OutsideRoom},
	},
	"EriaAppController": {
		"property/logLevel/read":  {Levels: [3]int{1, 1, authz.None}},
		"property/logLevel/write": parents,
	},
}

// eriaDefault is ERIA's rule for a function of a model, false when the
// function is not the model's.
func eriaDefault(modelID, key string) (Rule, bool) {
	m, ok := model.Models[modelID]
	if !ok {
		return Rule{}, false
	}
	kind, name, op := splitKey(key)
	_, prop := m.Properties[name]
	_, act := m.Actions[name]
	_, ev := m.Events[name]
	var r Rule
	switch {
	case kind == "property" && prop || kind == "event" && ev:
		r = read
		if op == "write" {
			r = command
		}
	case kind == "action" && act:
		r = command
		if strings.HasPrefix(name, "calibrate") {
			r = parents
		}
	default:
		return Rule{}, false
	}
	if e, ok := exceptions[modelID][key]; ok {
		r = e
	}
	return r, true
}

// defaults gives the default rule of each function of the capabilities: the
// admin's rule of the model (models.go), else ERIA's; the most restrictive
// when two capabilities share a function.
func defaults(types []string, funcs []string, admin modelRules) map[string]Rule {
	out := map[string]Rule{}
	for _, t := range types {
		for _, key := range funcs {
			r, ok := eriaDefault(t, key)
			if !ok {
				continue
			}
			if a, ok := admin[t][key]; ok {
				r = a
			}
			if prev, ok := out[key]; ok {
				r = strictest(prev, r)
			}
			out[key] = r
		}
	}
	return out
}

// splitKey cuts kind/name/op; the name may hold "/" (service-astral's
// today/sunrise, routed by the guard since go-wot v1.16.1).
func splitKey(key string) (kind, name, op string) {
	parts := strings.Split(key, "/")
	if len(parts) < 3 {
		return "", "", ""
	}
	return parts[0], strings.Join(parts[1:len(parts)-1], "/"), parts[len(parts)-1]
}

// strictest is the min of the levels (None lowest) and the widest confirmation.
func strictest(a, b Rule) Rule {
	for i := range a.Levels {
		a.Levels[i] = min(a.Levels[i], b.Levels[i])
	}
	if confirmRank(b.Confirm) > confirmRank(a.Confirm) {
		a.Confirm = b.Confirm
	}
	return a
}

func confirmRank(c auth.Confirm) int {
	return map[auth.Confirm]int{auth.OutsideHome: 1, auth.OutsideRoom: 2, auth.Always: 3}[c]
}

// checkRule refuses what the admin may not set (§2.4): levels outside
// None..9, a confirmation on a read, and a confirmed command open beyond 1.
func checkRule(key string, r Rule) error {
	_, _, op := splitKey(key)
	for _, l := range r.Levels {
		if l < authz.None || l > 9 {
			return Invalid("level outside 1-9 or None")
		}
	}
	switch {
	case op == "read" && r.Confirm != "":
		return Invalid("no confirmation on a read")
	case op != "read" && r.Confirm == "":
		return Invalid("confirm_when required on a write or invoke")
	case op != "read" && confirmRank(r.Confirm) == 0 && r.Confirm != auth.Never:
		return Invalid("unknown confirm_when")
	case confirmRank(r.Confirm) > 0 && slices.Max(r.Levels[:]) > 1:
		return Invalid("a confirmed command is for level 1 at most")
	}
	return nil
}

// --- Records ---

func jsonText(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func (s *Service) thing(id string) (ThingRecord, error) {
	var t ThingRecord
	var types, seen, funcs, zones, groups string
	err := s.store.db.QueryRow(`SELECT id, title, types, seen_types, functions, zones, groups, adopted, seen, app FROM things WHERE id = ?`, id).
		Scan(&t.ID, &t.Title, &types, &seen, &funcs, &zones, &groups, &t.Adopted, &t.Seen, &t.App)
	if errors.Is(err, sql.ErrNoRows) {
		return t, ErrNotFound
	}
	if err != nil {
		return t, err
	}
	json.Unmarshal([]byte(types), &t.Types)
	json.Unmarshal([]byte(seen), &t.SeenTypes)
	json.Unmarshal([]byte(funcs), &t.Functions)
	json.Unmarshal([]byte(zones), &t.Zones)
	// A TD without @type stores null: the admin screen wants lists.
	for _, l := range []*[]string{&t.Types, &t.SeenTypes, &t.Functions, &t.Zones} {
		if *l == nil {
			*l = []string{}
		}
	}
	t.Rules = map[string]Rule{}
	t.States = map[string]States{}
	rows, err := s.store.db.Query(`SELECT state, key, l0, l1, l2, confirm FROM rules WHERE thing = ?`, id)
	if err != nil {
		return t, err
	}
	defer rows.Close()
	for rows.Next() {
		var state, key string
		var r Rule
		rows.Scan(&state, &key, &r.Levels[0], &r.Levels[1], &r.Levels[2], &r.Confirm)
		if state == "" {
			t.Rules[key] = r
		} else {
			if t.States[state] == nil {
				t.States[state] = States{}
			}
			t.States[state][key] = r
		}
	}
	if err := rows.Err(); err != nil {
		return t, err
	}
	admin, err := s.modelRules()
	if err != nil {
		return t, err
	}
	t.Defaults = defaults(t.Types, t.Functions, admin)
	if t.Adopted && !slices.Equal(t.Types, t.SeenTypes) {
		t.SeenDefaults = defaults(t.SeenTypes, t.Functions, admin)
	}
	t.Effective = s.effective(t)
	var declared []Group
	json.Unmarshal([]byte(groups), &declared)
	t.Groups, err = s.groupViews(t, declared)
	return t, err
}

// effective is the table the Thing gets (§2.5): default, else the admin's
// rule, else None; then min with the override of each active state.
func (s *Service) effective(t ThingRecord) auth.Table {
	if !t.Adopted {
		return nil
	}
	active := s.activeStates()
	table := auth.Table{}
	for _, key := range t.Functions {
		r, ok := t.Rules[key]
		if !ok {
			r = t.Defaults[key]
		}
		for _, st := range active {
			if o, ok := t.States[st][key]; ok {
				r.Levels = strictest(r, o).Levels
			}
		}
		if r.Levels == [3]int{} {
			continue // None everywhere: absent is None
		}
		table[key] = r
	}
	return table
}

// Things lists the Things for the admin.
func (s *Service) Things() ([]ThingRecord, error) {
	rows, err := s.store.db.Query(`SELECT id FROM things ORDER BY adopted, title`)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		rows.Scan(&id)
		ids = append(ids, id)
	}
	rows.Close()
	list := []ThingRecord{}
	for _, id := range ids {
		t, err := s.thing(id)
		if err != nil {
			return nil, err
		}
		list = append(list, t)
	}
	return list, nil
}

// AdoptThing gives the Thing a table, with the capabilities of its last TD.
func (s *Service) AdoptThing(id string) error {
	t, err := s.thing(id)
	if err != nil {
		return err
	}
	if _, err := s.store.db.Exec(`UPDATE things SET adopted = 1, types = seen_types WHERE id = ?`, id); err != nil {
		return err
	}
	s.store.log("thing.adopt", fmt.Sprintf("%s %v", id, t.SeenTypes))
	s.bumpThing(id)
	return nil
}

// ForgetThing removes a Thing and its rules: it gets no table any more, and
// comes back as new with its next TD.
func (s *Service) ForgetThing(id string) error {
	res, err := s.store.db.Exec(`DELETE FROM things WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	s.store.db.Exec(`DELETE FROM rules WHERE thing = ?`, id)
	s.store.db.Exec(`DELETE FROM group_rules WHERE thing = ?`, id)
	s.store.log("thing.forget", id)
	return nil
}

// SetZones sets the rooms of a Thing.
func (s *Service) SetZones(id string, zones []string) error {
	slices.Sort(zones)
	zones = slices.Compact(zones)
	if len(zones) > 8 {
		return Invalid("8 rooms at most")
	}
	for _, z := range zones {
		if !zoneRe.MatchString(z) {
			return Invalid("room: lowercase letters, digits and -")
		}
	}
	if zones == nil {
		zones = []string{}
	}
	old, err := s.thing(id)
	if err != nil {
		return err
	}
	if _, err := s.store.db.Exec(`UPDATE things SET zones = ? WHERE id = ?`, jsonText(zones), id); err != nil {
		return err
	}
	s.alertRooms(id, old.Zones, zones)
	s.store.log("thing.zones", fmt.Sprintf("%s %v", id, zones))
	s.bumpThing(id)
	return nil
}

// SetRule sets (or, with nil, removes) the admin's rule of a function, or
// the override of state. An override may only restrict (§2.5).
func (s *Service) SetRule(id, state, key string, r *Rule) error {
	t, err := s.thing(id)
	if err != nil {
		return err
	}
	if !slices.Contains(t.Functions, key) {
		return Invalid("unknown function")
	}
	if state != "" && !s.knownState(state) {
		return Invalid("unknown state")
	}
	if state == "" && t.inSetGroup(key) {
		return Invalid("set by its group: set the group function by function first")
	}
	if r == nil {
		_, err = s.store.db.Exec(`DELETE FROM rules WHERE thing = ? AND state = ? AND key = ?`, id, state, key)
	} else {
		if state != "" {
			r.Confirm = "" // an override only changes the levels
			base, ok := t.Rules[key]
			if !ok {
				base = t.Defaults[key]
			}
			if strictest(base, *r).Levels != r.Levels {
				return Invalid("an override may only restrict")
			}
		} else if err := checkRule(key, *r); err != nil {
			return err
		}
		_, err = s.store.db.Exec(`INSERT INTO rules (thing, state, key, l0, l1, l2, confirm) VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (thing, state, key) DO UPDATE SET l0 = excluded.l0, l1 = excluded.l1, l2 = excluded.l2, confirm = excluded.confirm`,
			id, state, key, r.Levels[0], r.Levels[1], r.Levels[2], r.Confirm)
	}
	if err != nil {
		return err
	}
	s.store.log("thing.rule", fmt.Sprintf("%s %s %s %v", id, state, key, r))
	s.bumpThing(id)
	return nil
}

// bumpThing gives the Thing's table a new version (time in ms, never back).
func (s *Service) bumpThing(id string) {
	s.store.db.Exec(`UPDATE things SET version = max(version + 1, ?) WHERE id = ?`, s.now().UnixMilli(), id)
}

// TableDoc is the signed effective table of an adopted Thing, with its
// version (§2.4). Over 4000 bytes, it is refused and the admin alerted.
func (s *Service) TableDoc(id string) (string, int64, error) {
	t, err := s.thing(id)
	if err != nil {
		return "", 0, err
	}
	if !t.Adopted {
		return "", 0, ErrNotFound
	}
	var version int64
	s.store.db.QueryRow(`SELECT version FROM things WHERE id = ?`, id).Scan(&version)
	d := auth.Doc{Iss: "auth", Aud: s.aud, Doc: auth.DocTable, Thing: id, Version: max(version, 1),
		Issued: s.now().Unix(), Table: t.Effective, Zones: t.Zones}
	tok, err := auth.SignDoc(s.key, s.kid, d)
	if err == nil && len(tok) > auth.MaxDocSize {
		s.notify("Table d'un appareil trop grande")
		return "", 0, errors.New("table over 4000 bytes")
	}
	return tok, d.Version, err
}

// HeartbeatDoc is the signed time (§4.3) for a Thing's nonce, with the
// versions auth holds for it: the tables of the Things it asks for (at most
// maxBeatThings, 0 when not adopted) and the revocation list (§4.4).
func (s *Service) HeartbeatDoc(nonce string, things []string) (string, error) {
	if nonce == "" || len(nonce) > 64 || len(things) > maxBeatThings {
		return "", ErrInvalid
	}
	now := s.now()
	v := &auth.Versions{Tables: map[string]int64{}}
	s.store.db.QueryRow(`SELECT value FROM state WHERE key = 'revocations'`).Scan(&v.Revocation)
	v.Revocation = max(v.Revocation, 1) // as RevocationDoc
	for _, id := range things {
		var version int64
		var adopted bool
		s.store.db.QueryRow(`SELECT version, adopted FROM things WHERE id = ?`, id).Scan(&version, &adopted)
		if adopted {
			version = max(version, 1) // as TableDoc
		} else {
			version = 0
		}
		v.Tables[id] = version
	}
	tok, err := auth.SignDoc(s.key, s.kid, auth.Doc{Iss: "auth", Aud: s.aud, Doc: auth.DocHeartbeat, Thing: "*",
		Version: now.UnixMilli(), Issued: now.Unix(), Nonce: nonce, Versions: v})
	if err == nil && len(tok) > auth.MaxDocSize {
		return "", Invalid("heartbeat over 4000 bytes: fewer Things per request")
	}
	return tok, err
}

// maxBeatThings bounds the tables a heartbeat carries: the document stays
// under 4000 bytes.
const maxBeatThings = 16

// --- States of the house (§2.5) ---

// knownState: the states are the contexts offered to people.
func (s *Service) knownState(id string) bool {
	var n int
	s.store.db.QueryRow(`SELECT count(*) FROM contexts WHERE id = ?`, id).Scan(&n)
	return n > 0
}

func (s *Service) activeStates() []string {
	var list []string
	rows, err := s.store.db.Query(`SELECT state FROM active_states ORDER BY state`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	for rows.Next() {
		var st string
		rows.Scan(&st)
		list = append(list, st)
	}
	return list
}

// ReceiveStates takes the states as the states app (manager-contexts)
// publishes them: signed by its key, with a version higher than the last
// one (auth.States). A plain list is taken only while that app has no key
// here (generation 0): an override only restricts, so a forged state can
// only close functions.
func (s *Service) ReceiveStates(body []byte) error {
	var signed auth.SignedBy
	if json.Unmarshal(body, &signed) != nil || signed.Kid == "" {
		var n int
		s.store.db.QueryRow(`SELECT count(*) FROM apps WHERE name = ? AND kid != ''`, s.statesApp).Scan(&n)
		if n > 0 {
			return ErrDenied
		}
		var states []string
		if json.Unmarshal(body, &states) != nil {
			return ErrInvalid
		}
		return s.SetActiveStates(states)
	}
	var id, name string
	var raw []byte
	if s.store.db.QueryRow(`SELECT id, name, raw FROM apps WHERE kid = ?`, signed.Kid).Scan(&id, &name, &raw) != nil || name != s.statesApp {
		return ErrDenied
	}
	pub, err := auth.ParsePublicKey(auth.Ed25519, raw)
	if err != nil {
		return ErrDenied
	}
	var st auth.States
	if signed.Open(auth.StatesPrefix, []auth.PublicKey{pub}, &st) != nil {
		s.badSignature(id, "states")
		return ErrDenied
	}
	var last int64
	s.store.db.QueryRow(`SELECT value FROM state WHERE key = 'states'`).Scan(&last)
	if st.Version <= last {
		return ErrDenied // replayed or older
	}
	s.store.db.Exec(`INSERT INTO state (key, value) VALUES ('states', ?)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value`, st.Version)
	return s.SetActiveStates(st.States)
}

// SetActiveStates replaces the active states of the house (the unknown ones
// left out); every Thing with an override of a state gets a new table.
func (s *Service) SetActiveStates(states []string) error {
	if len(states) > 64 {
		return Invalid("too many states")
	}
	// The other contexts (daily ones: weekday, holidays…) are no states.
	states = slices.DeleteFunc(slices.Clone(states), func(st string) bool { return !s.knownState(st) })
	slices.Sort(states)
	states = slices.Compact(states)
	old := s.activeStates()
	if slices.Equal(old, states) {
		return nil
	}
	tx, err := s.store.db.Begin()
	if err != nil {
		return err
	}
	tx.Exec(`DELETE FROM active_states`)
	for _, st := range states {
		tx.Exec(`INSERT INTO active_states (state) VALUES (?)`, st)
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.store.log("states", strings.Join(states, ","))
	// ponytail: every Thing with an override gets a new version, not only
	// those of the states that changed.
	rows, err := s.store.db.Query(`SELECT DISTINCT thing FROM rules WHERE state != ''`)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		rows.Scan(&id)
		ids = append(ids, id)
	}
	rows.Close()
	for _, id := range ids {
		s.bumpThing(id)
	}
	return nil
}
