package main

// Rules of the models (AUTH-DESIGN §2.4, models, decided 2026-11-17): the
// default of a function comes from the eria-core models of its Thing
// (LightBasic…). The admin may change a model's rule for a function, ERIA's
// staying the starting point; every Thing of the model follows it where it
// has no rule of its own. Own rule = a row in rules, never removed but by the
// admin (« suivre le modèle »): a rule equal to the model's stays one.

import (
	"fmt"
	"slices"
	"sort"

	"github.com/project-eria/eria-core/model"
)

// modelRules are the admin's rules, by model then function key.
type modelRules = map[string]map[string]Rule

// ModelView is a model as the admin sees it: its adopted Things and the
// functions they have of it.
type ModelView struct {
	ID        string          `json:"id"`
	Things    []string        `json:"things"`
	Functions []ModelFunction `json:"functions"`
}

// ModelFunction is a function of a model: ERIA's rule and the admin's.
type ModelFunction struct {
	Key  string `json:"key"`
	ERIA Rule   `json:"eria"`
	Rule *Rule  `json:"rule"` // the admin's, nil: ERIA's
}

func (s *Service) modelRules() (modelRules, error) {
	rows, err := s.store.db.Query(`SELECT model, key, l0, l1, l2, confirm FROM model_rules`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := modelRules{}
	for rows.Next() {
		var m, key string
		var r Rule
		if err := rows.Scan(&m, &key, &r.Levels[0], &r.Levels[1], &r.Levels[2], &r.Confirm); err != nil {
			return nil, err
		}
		if out[m] == nil {
			out[m] = map[string]Rule{}
		}
		out[m][key] = r
	}
	return out, rows.Err()
}

// Models lists every model, with the adopted Things of each and the
// functions they have of it; an unused model has none.
func (s *Service) Models() ([]ModelView, error) {
	things, err := s.Things()
	if err != nil {
		return nil, err
	}
	admin, err := s.modelRules()
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(model.Models))
	for id := range model.Models {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := []ModelView{}
	for _, id := range ids {
		v := ModelView{ID: id, Things: []string{}, Functions: []ModelFunction{}}
		keys := []string{}
		for _, t := range things {
			if !t.Adopted || !slices.Contains(t.Types, id) {
				continue
			}
			v.Things = append(v.Things, t.ID)
			for _, key := range t.Functions {
				if _, ok := eriaDefault(id, key); ok && !slices.Contains(keys, key) {
					keys = append(keys, key)
				}
			}
		}
		sort.Strings(keys)
		for _, key := range keys {
			f := ModelFunction{Key: key}
			f.ERIA, _ = eriaDefault(id, key)
			if r, ok := admin[id][key]; ok {
				f.Rule = &r
			}
			v.Functions = append(v.Functions, f)
		}
		out = append(out, v)
	}
	return out, nil
}

// SetModelRule sets a model's rule for one of its functions; nil gives it
// ERIA's again. The Things of the model get their new table.
func (s *Service) SetModelRule(modelID, key string, r *Rule) error {
	if _, ok := eriaDefault(modelID, key); !ok {
		return Invalid("not a function of this model")
	}
	var err error
	if r == nil {
		_, err = s.store.db.Exec(`DELETE FROM model_rules WHERE model = ? AND key = ?`, modelID, key)
	} else {
		if err := checkRule(key, *r); err != nil {
			return err
		}
		_, err = s.store.db.Exec(`INSERT INTO model_rules (model, key, l0, l1, l2, confirm) VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT (model, key) DO UPDATE SET l0 = excluded.l0, l1 = excluded.l1, l2 = excluded.l2, confirm = excluded.confirm`,
			modelID, key, r.Levels[0], r.Levels[1], r.Levels[2], r.Confirm)
	}
	if err != nil {
		return err
	}
	s.store.log("model.rule", fmt.Sprintf("%s %s %v", modelID, key, r))
	return s.bumpModel(modelID)
}

// FollowModel removes the own rules of the Things of a model on its
// functions: they follow the model again. A function ruled by a group set
// as a group keeps its rule (the group's). Gives how many rules went.
func (s *Service) FollowModel(modelID string) (int, error) {
	if _, ok := model.Models[modelID]; !ok {
		return 0, ErrNotFound
	}
	things, err := s.Things()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, t := range things {
		if !t.Adopted || !slices.Contains(t.Types, modelID) {
			continue
		}
		for key := range t.Rules {
			if _, ok := eriaDefault(modelID, key); !ok || t.inSetGroup(key) {
				continue
			}
			if _, err := s.store.db.Exec(`DELETE FROM rules WHERE thing = ? AND state = '' AND key = ?`, t.ID, key); err != nil {
				return n, err
			}
			n++
		}
	}
	s.store.log("model.follow", fmt.Sprintf("%s %d", modelID, n))
	return n, s.bumpModel(modelID)
}

// bumpModel gives the adopted Things of a model a new table version.
func (s *Service) bumpModel(modelID string) error {
	things, err := s.Things()
	if err != nil {
		return err
	}
	for _, t := range things {
		if t.Adopted && slices.Contains(t.Types, modelID) {
			s.bumpThing(t.ID)
		}
	}
	return nil
}
