package main

// Groups of functions (AUTH-DESIGN §2.4, groups, decided 2026-11-15): an app
// declares in its signed TD (eria:groups) groups of functions with a title,
// each of one operation. The admin sets a group's rule at once, written as
// one rule per member: the Things' tables and decision do not change. A
// function new in a group already set arrives without a right (pending)
// until the admin accepts it: an app update never opens a function alone.

import (
	"encoding/json"
	"fmt"
	"slices"

	zlog "github.com/rs/zerolog/log"
)

const (
	maxGroups     = 32
	maxGroupTitle = 64
)

// Group is a group as the TD declares it.
type Group struct {
	ID        string   `json:"id"`
	Title     string   `json:"title"`
	Functions []string `json:"functions"`
}

// GroupView is a group as the admin sees it: set as a group (Rule, the
// group's), or function by function (Individual). Without a choice yet, a
// group whose members share one rule shows as a group with it.
type GroupView struct {
	Group
	Individual bool     `json:"individual"`
	Rule       *Rule    `json:"rule"`    // nil when individual
	Pending    []string `json:"pending"` // new in a group set, without its rule
}

// groups keeps the TD's valid groups: a known id, a title, functions of the
// TD of one operation, each in one group only. A bad group is dropped, the
// TD still taken.
func (td TDIn) groups(funcs []string) []Group {
	out := []Group{}
	seen := map[string]bool{}
	for _, g := range td.Groups {
		bad := func(why string) {
			zlog.Warn().Str("thing", td.ID).Str("group", g.ID).Msg("[groups] group dropped: " + why)
		}
		switch {
		case len(out) == maxGroups:
			bad("too many groups")
			continue
		case !nameRe.MatchString(g.ID) || seen[g.ID]:
			bad("bad or repeated id")
			continue
		case g.Title == "" || len(g.Title) > maxGroupTitle:
			bad("bad title")
			continue
		case len(g.Functions) == 0:
			bad("no function")
			continue
		}
		_, _, op := splitKey(g.Functions[0])
		ok := true
		for _, key := range g.Functions {
			_, _, o := splitKey(key)
			if o != op || !slices.Contains(funcs, key) || seen["f:"+key] {
				ok = false
				break
			}
		}
		if !ok {
			bad("unknown, repeated or mixed functions")
			continue
		}
		seen[g.ID] = true
		for _, key := range g.Functions {
			seen["f:"+key] = true
		}
		fs := slices.Clone(g.Functions)
		slices.Sort(fs)
		out = append(out, Group{ID: g.ID, Title: g.Title, Functions: fs})
	}
	return out
}

// groupRow is a group's row in group_rules.
type groupRow struct {
	individual        bool
	rule              Rule
	members, declined []string
}

func (s *Service) groupRows(thing string) (map[string]groupRow, error) {
	rows, err := s.store.db.Query(`SELECT grp, individual, l0, l1, l2, confirm, members, declined FROM group_rules WHERE thing = ?`, thing)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]groupRow{}
	for rows.Next() {
		var id, members, declined string
		var g groupRow
		rows.Scan(&id, &g.individual, &g.rule.Levels[0], &g.rule.Levels[1], &g.rule.Levels[2], &g.rule.Confirm, &members, &declined)
		json.Unmarshal([]byte(members), &g.members)
		json.Unmarshal([]byte(declined), &g.declined)
		out[id] = g
	}
	return out, rows.Err()
}

// groupViews joins the TD's groups and the admin's choices.
func (s *Service) groupViews(t ThingRecord, groups []Group) ([]GroupView, error) {
	rows, err := s.groupRows(t.ID)
	if err != nil {
		return nil, err
	}
	views := []GroupView{}
	for _, g := range groups {
		v := GroupView{Group: g, Pending: []string{}}
		row, set := rows[g.ID]
		switch {
		case set && row.individual:
			v.Individual = true
		case set:
			r := row.rule
			v.Rule = &r
			for _, key := range g.Functions {
				if !slices.Contains(row.members, key) && !slices.Contains(row.declined, key) {
					v.Pending = append(v.Pending, key)
				}
			}
		default:
			// No choice yet: a group if its members agree.
			r := t.ruleOf(g.Functions[0])
			for _, key := range g.Functions[1:] {
				if t.ruleOf(key) != r {
					v.Individual = true
				}
			}
			if !v.Individual {
				v.Rule = &r
			}
		}
		views = append(views, v)
	}
	return views, nil
}

// ruleOf is a function's rule outside states: the admin's, else the
// default, else None.
func (t ThingRecord) ruleOf(key string) Rule {
	if r, ok := t.Rules[key]; ok {
		return r
	}
	return t.Defaults[key]
}

// groupOf finds a group of the Thing's last TD.
func (t ThingRecord) groupOf(id string) (GroupView, bool) {
	for _, g := range t.Groups {
		if g.ID == id {
			return g, true
		}
	}
	return GroupView{}, false
}

// inSetGroup says whether a function is ruled by a group set as a group.
func (t ThingRecord) inSetGroup(key string) bool {
	for _, g := range t.Groups {
		if g.Rule != nil && !g.Individual && slices.Contains(g.Functions, key) {
			return true
		}
	}
	return false
}

// SetGroupRule sets a group's rule, written on every member (the pending
// ones too: the admin chose it with the list in front of him); nil sets the
// group function by function, each keeping its rule.
func (s *Service) SetGroupRule(id, group string, r *Rule) error {
	t, err := s.thing(id)
	if err != nil {
		return err
	}
	g, ok := t.groupOf(group)
	if !ok {
		return ErrNotFound
	}
	if r == nil {
		_, err = s.store.db.Exec(`INSERT INTO group_rules (thing, grp, individual) VALUES (?, ?, 1)
			ON CONFLICT (thing, grp) DO UPDATE SET individual = 1, members = '[]', declined = '[]'`, id, group)
		if err == nil {
			s.store.log("thing.group", fmt.Sprintf("%s %s individual", id, group))
		}
		return err
	}
	for _, key := range g.Functions {
		if err := checkRule(key, *r); err != nil {
			return err
		}
	}
	tx, err := s.store.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, key := range g.Functions {
		if _, err := tx.Exec(`INSERT INTO rules (thing, state, key, l0, l1, l2, confirm) VALUES (?, '', ?, ?, ?, ?, ?)
			ON CONFLICT (thing, state, key) DO UPDATE SET l0 = excluded.l0, l1 = excluded.l1, l2 = excluded.l2, confirm = excluded.confirm`,
			id, key, r.Levels[0], r.Levels[1], r.Levels[2], r.Confirm); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`INSERT INTO group_rules (thing, grp, individual, l0, l1, l2, confirm, members, declined) VALUES (?, ?, 0, ?, ?, ?, ?, ?, '[]')
		ON CONFLICT (thing, grp) DO UPDATE SET individual = 0, l0 = excluded.l0, l1 = excluded.l1, l2 = excluded.l2,
			confirm = excluded.confirm, members = excluded.members, declined = '[]'`,
		id, group, r.Levels[0], r.Levels[1], r.Levels[2], r.Confirm, jsonText(g.Functions)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.store.log("thing.group", fmt.Sprintf("%s %s %v", id, group, *r))
	s.bumpThing(id)
	return nil
}

// SettlePending accepts a function new in a group set (it gets the group's
// rule) or declines it (it stays without a right, no longer pending).
func (s *Service) SettlePending(id, group, key string, accept bool) error {
	t, err := s.thing(id)
	if err != nil {
		return err
	}
	g, ok := t.groupOf(group)
	if !ok || !slices.Contains(g.Pending, key) {
		return ErrNotFound
	}
	rows, err := s.groupRows(id)
	if err != nil {
		return err
	}
	row := rows[group]
	if !accept {
		_, err = s.store.db.Exec(`UPDATE group_rules SET declined = ? WHERE thing = ? AND grp = ?`,
			jsonText(append(row.declined, key)), id, group)
		if err == nil {
			s.store.log("thing.group", fmt.Sprintf("%s %s declined %s", id, group, key))
		}
		return err
	}
	tx, err := s.store.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	r := *g.Rule
	if _, err := tx.Exec(`INSERT INTO rules (thing, state, key, l0, l1, l2, confirm) VALUES (?, '', ?, ?, ?, ?, ?)
		ON CONFLICT (thing, state, key) DO UPDATE SET l0 = excluded.l0, l1 = excluded.l1, l2 = excluded.l2, confirm = excluded.confirm`,
		id, key, r.Levels[0], r.Levels[1], r.Levels[2], r.Confirm); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE group_rules SET members = ? WHERE thing = ? AND grp = ?`,
		jsonText(append(row.members, key)), id, group); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.store.log("thing.group", fmt.Sprintf("%s %s accepted %s", id, group, key))
	s.bumpThing(id)
	return nil
}
