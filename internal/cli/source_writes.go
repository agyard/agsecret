package cli

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/agyard/agsecret/internal/store"
)

// Resolve once before reading input, then pin writes to that source. Network
// writes also pin the ID. Failures never fall back or silently create a copy.
func (s *sources) putTarget(ctx context.Context, name string) (store.Record, error) {
	r, err := s.get(ctx, name)
	if errors.Is(err, store.ErrNotFound) {
		source := s.selected
		if source == "" {
			source = "local"
		}
		r = store.Record{Name: name, Type: "password", Source: source}
	} else if err != nil {
		return store.Record{}, err
	}
	if r.Source != "local" {
		c, err := s.client(r.Source)
		if err != nil {
			clear(r.Secret)
			return store.Record{}, err
		}
		key, err := c.Capabilities(ctx)
		if err == nil {
			if r.ID == "" && !key.AllowCreate {
				err = store.ErrCreateNotAllowed
			}
			if r.ID != "" && !key.AllowEdit {
				err = store.ErrEditNotAllowed
			}
		}
		if err != nil {
			clear(r.Secret)
			return store.Record{}, fmt.Errorf("%s: %w", r.Source, err)
		}
	}
	return r, nil
}

func (s *sources) put(ctx context.Context, target store.Record, change store.Change) (store.PutResult, error) {
	if target.Source != "local" {
		change.ExpectedID = &target.ID
	}
	var result store.PutResult
	var err error
	if target.Source == "local" {
		result, err = s.local.Put(target.Name, change)
	} else {
		c, clientErr := s.client(target.Source)
		if clientErr != nil {
			return result, clientErr
		}
		result, err = c.Put(ctx, target.Name, change)
	}
	if err != nil {
		return store.PutResult{}, fmt.Errorf("%s: %w", target.Source, err)
	}
	result.Record.Source = target.Source
	return result, nil
}

func (s *sources) rename(ctx context.Context, ref, name string) (store.Record, error) {
	r, err := s.get(ctx, ref)
	if err != nil {
		return store.Record{}, err
	}
	defer clear(r.Secret)
	var renamed store.Record
	if r.Source == "local" {
		renamed, err = s.local.Rename(r.ID, name)
	} else {
		c, clientErr := s.client(r.Source)
		if clientErr != nil {
			return store.Record{}, clientErr
		}
		renamed, err = c.Rename(ctx, r.ID, name)
	}
	if err != nil {
		return store.Record{}, fmt.Errorf("%s: %w", r.Source, err)
	}
	renamed.Source = r.Source
	return renamed, nil
}

func (s *sources) delete(ctx context.Context, ref string) (store.Record, error) {
	r, err := s.get(ctx, ref)
	if err != nil {
		return store.Record{}, err
	}
	owner := r.Source
	if r.Source == "local" {
		err = s.local.Delete(r.ID)
	} else {
		c, clientErr := s.client(r.Source)
		if clientErr != nil {
			clear(r.Secret)
			return store.Record{}, clientErr
		}
		deleted, deleteErr := c.Delete(ctx, r.ID)
		clear(r.Secret)
		deleted.Source = r.Source
		r, err = deleted, deleteErr
	}
	if err != nil {
		clear(r.Secret)
		return store.Record{}, fmt.Errorf("%s: %w", owner, err)
	}
	return r, nil
}

func (s *sources) credentialTarget(ctx context.Context, name string) (string, []string, error) {
	records, err := s.list(ctx)
	if err != nil {
		return "", nil, err
	}
	defer clearRecords(records)
	owners := map[string]bool{}
	var owner string
	ids := []string{}
	for _, r := range records {
		if group, _ := store.SplitName(r.Name); group == name {
			owner = r.Source
			owners[r.Source] = true
			ids = append(ids, r.ID)
		}
	}
	if len(owners) == 0 {
		return "", nil, fmt.Errorf("credential %s %w", name, store.ErrNotFound)
	}
	if len(owners) > 1 {
		names := make([]string, 0, len(owners))
		for name := range owners {
			names = append(names, name)
		}
		slices.Sort(names)
		return "", nil, fmt.Errorf("credential %s contains fields from multiple sources (%s); choose --source local or a remote name", name, strings.Join(names, ", "))
	}
	return owner, ids, nil
}

func (s *sources) renameCredential(ctx context.Context, name, newName string) ([]store.Record, error) {
	owner, ids, err := s.credentialTarget(ctx, name)
	if err != nil {
		return nil, err
	}
	var records []store.Record
	if owner == "local" {
		records, err = s.local.RenameCredentialChecked(name, newName, ids)
	} else {
		c, clientErr := s.client(owner)
		if clientErr != nil {
			return nil, clientErr
		}
		records, err = c.RenameCredential(ctx, name, newName, ids)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", owner, err)
	}
	for i := range records {
		records[i].Source = owner
	}
	return records, nil
}

func (s *sources) deleteCredential(ctx context.Context, name string) (int64, error) {
	owner, ids, err := s.credentialTarget(ctx, name)
	if err != nil {
		return 0, err
	}
	if owner == "local" {
		return s.local.DeleteCredentialChecked(name, ids)
	}
	c, err := s.client(owner)
	if err != nil {
		return 0, err
	}
	count, err := c.DeleteCredential(ctx, name, ids)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", owner, err)
	}
	return count, nil
}
