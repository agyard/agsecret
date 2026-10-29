package cli

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/agyard/agsecret/internal/remote"
	"github.com/agyard/agsecret/internal/store"
)

// sources lives for one CLI operation. Records carry their resolved source so
// a later rename, rotation or outage cannot change the destination of a use.
type sources struct {
	local   *store.Store
	mounts  []store.Remote
	clients map[string]*remote.Client
}

func (o *options) withSources(fn func(*sources) error) error {
	return o.withStore(func(s *store.Store) error {
		mounts, err := s.Remotes()
		if err != nil {
			return err
		}
		all := &sources{local: s, mounts: mounts, clients: make(map[string]*remote.Client)}
		defer func() {
			for _, c := range all.clients {
				c.Close()
			}
		}()
		return fn(all)
	})
}

func (s *sources) client(name string) (*remote.Client, error) {
	if c := s.clients[name]; c != nil {
		return c, nil
	}
	for _, m := range s.mounts {
		if m.Name == name {
			c, err := remote.NewClient(m.URL, m.Key)
			if err != nil {
				return nil, err
			}
			s.clients[name] = c
			return c, nil
		}
	}
	return nil, fmt.Errorf("remote %s %w", name, store.ErrNotFound)
}

func (s *sources) get(ctx context.Context, ref string) (store.Record, error) {
	r, err := s.local.Get(ref, false)
	if err == nil {
		r.Source = "local"
		return r, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return store.Record{}, err
	}
	var failures []error
	for _, m := range s.mounts {
		c, err := s.client(m.Name)
		if err == nil {
			r, err = c.Get(ctx, ref)
		}
		if err == nil {
			r.Source = m.Name
			return r, nil
		}
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		err = fmt.Errorf("%s: %w", m.Name, err)
		if !store.ValidID(ref) {
			return store.Record{}, err
		}
		failures = append(failures, err)
	}
	if len(failures) > 0 {
		return store.Record{}, fmt.Errorf("incomplete ID lookup: %w", errors.Join(failures...))
	}
	return store.Record{}, fmt.Errorf("secret %s %w", ref, store.ErrNotFound)
}

func clearRecords(records []store.Record) {
	for _, r := range records {
		clear(r.Secret)
	}
}

func (s *sources) list(ctx context.Context) ([]store.Record, error) {
	local, err := s.local.List(false)
	if err != nil {
		return nil, err
	}
	out := []store.Record{}
	seen := make(map[string]bool)
	merge := func(records []store.Record, source string) {
		for _, r := range records {
			if seen[r.Name] {
				clear(r.Secret)
				continue
			}
			seen[r.Name], r.Source = true, source
			out = append(out, r)
		}
	}
	merge(local, "local")
	for _, m := range s.mounts {
		c, err := s.client(m.Name)
		var records []store.Record
		if err == nil {
			records, err = c.List(ctx)
		}
		if err != nil {
			clearRecords(out)
			return nil, fmt.Errorf("%s: %w", m.Name, err)
		}
		merge(records, m.Name)
	}
	slices.SortFunc(out, func(a, b store.Record) int {
		ag, _, aq := strings.Cut(a.Name, ":")
		bg, _, bq := strings.Cut(b.Name, ":")
		if aq != bq {
			if aq {
				return 1
			}
			return -1
		}
		return cmp.Or(cmp.Compare(ag, bg), cmp.Compare(a.Name, b.Name))
	})
	return out, nil
}

// use returns actual values, including current TOTP codes. Each source commits
// independently; after any failure, returned values are erased and no child runs.
func (s *sources) use(ctx context.Context, selected []store.Record, action string) ([]store.Record, error) {
	groups := make(map[string][]string)
	for _, r := range selected {
		if err := checkUse(r, time.Now(), action); err != nil {
			return nil, err
		}
		groups[r.Source] = append(groups[r.Source], r.ID)
	}
	order := []string{"local"}
	for _, m := range s.mounts {
		order = append(order, m.Name)
	}
	out := []store.Record{}
	for _, name := range order {
		ids := groups[name]
		if len(ids) == 0 {
			continue
		}
		var records []store.Record
		var err error
		if name == "local" {
			records, err = s.local.ConsumeMany(ids, action)
			if err == nil {
				for i := range records {
					value, valueErr := currentValue(records[i], time.Now())
					clear(records[i].Secret)
					records[i].Secret = value
					if valueErr != nil {
						err = valueErr
						break
					}
				}
			}
		} else {
			var c *remote.Client
			if c, err = s.client(name); err == nil {
				records, err = c.Use(ctx, ids, action)
			}
		}
		if err != nil {
			clearRecords(records)
			clearRecords(out)
			if len(out) > 0 || name != "local" {
				if strings.Contains(err.Error(), "uses may have been consumed") {
					return nil, fmt.Errorf("%s: %w", name, err)
				}
				return nil, fmt.Errorf("%s: %w; uses may have been consumed", name, err)
			}
			return nil, err
		}
		for i := range records {
			records[i].Source = name
		}
		out = append(out, records...)
	}
	return out, nil
}

func (s *sources) report(ctx context.Context, id, reason string) ([]store.Record, error) {
	r, err := s.get(ctx, id)
	if err != nil {
		return nil, err
	}
	defer clear(r.Secret)
	var records []store.Record
	if r.Source == "local" {
		records, err = s.local.Report(id, reason)
	} else {
		var c *remote.Client
		if c, err = s.client(r.Source); err == nil {
			records, err = c.Report(ctx, id, reason)
		}
	}
	for i := range records {
		records[i].Source = r.Source
	}
	return records, err
}
