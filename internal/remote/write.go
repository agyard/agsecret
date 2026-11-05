package remote

import (
	"context"
	"errors"
	"strings"

	"github.com/agyard/agsecret/internal/store"
)

func (c *Client) Capabilities(ctx context.Context) (store.APIKey, error) {
	var key store.APIKey
	if err := c.request(ctx, "/v1/capabilities", nil, &key); err != nil {
		return store.APIKey{}, err
	}
	if store.ValidateAPIKeyName(key.Name) != nil || store.ValidateRules(key.Rules) != nil {
		return store.APIKey{}, errors.New("invalid remote capabilities")
	}
	return key, nil
}

func (c *Client) Put(ctx context.Context, name string, change store.Change) (store.PutResult, error) {
	if change.SkipCheck {
		return store.PutResult{}, errors.New("--dangerously-skip-check is available only for local writes")
	}
	if change.ExpectedID == nil {
		return store.PutResult{}, store.ErrInvalidChange
	}
	request := putRequest{Name: name, ExpectedID: change.ExpectedID, Value: change.Secret, Type: change.Type, AllowGet: change.AllowGet, AllowExec: change.AllowExec, MaxUses: change.MaxUses}
	if change.ExpiresAt != nil {
		request.Expiry = &expiryChange{At: *change.ExpiresAt}
	}
	var response putResponse
	const path = "/v1/put"
	if err := c.request(ctx, path, request, &response); err != nil {
		return store.PutResult{}, err
	}
	records, err := fromFields([]field{response.Field}, false)
	if err != nil {
		return store.PutResult{}, uncertainMutation(path, err)
	}
	valid := response.Field.Name == name && response.Created == (*change.ExpectedID == "")
	if response.Created {
		valid = valid && response.PreviousID == ""
	} else if response.PreviousID == "" {
		valid = valid && response.Field.ID == *change.ExpectedID
	} else {
		valid = valid && response.PreviousID == *change.ExpectedID && response.Field.ID != response.PreviousID
	}
	for _, duplicate := range response.Duplicates {
		valid = valid && store.ValidateName(duplicate) == nil && duplicate != name
	}
	if !valid {
		clearRecords(records)
		return store.PutResult{}, uncertainMutation(path, errors.New("invalid remote put response"))
	}
	return store.PutResult{Record: records[0], Created: response.Created, PreviousID: response.PreviousID, Duplicates: response.Duplicates}, nil
}

func (c *Client) Rename(ctx context.Context, id, name string) (store.Record, error) {
	return c.mutateField(ctx, "/v1/rename", renameRequest{ID: id, Name: name}, id, name)
}

func (c *Client) Delete(ctx context.Context, id string) (store.Record, error) {
	return c.mutateField(ctx, "/v1/delete", deleteRequest{ID: id}, id, "")
}

func (c *Client) mutateField(ctx context.Context, path string, request any, id, name string) (store.Record, error) {
	var response field
	if err := c.request(ctx, path, request, &response); err != nil {
		return store.Record{}, err
	}
	records, err := fromFields([]field{response}, false)
	if err != nil {
		return store.Record{}, uncertainMutation(path, err)
	}
	if response.ID != id || name != "" && response.Name != name {
		clearRecords(records)
		return store.Record{}, uncertainMutation(path, errors.New("invalid remote field change response"))
	}
	return records[0], nil
}

func (c *Client) RenameCredential(ctx context.Context, name, newName string, ids []string) ([]store.Record, error) {
	const path = "/v1/credential/rename"
	var response []field
	if err := c.request(ctx, path, credentialRequest{Name: name, NewName: newName, IDs: ids}, &response); err != nil {
		return nil, err
	}
	records, err := fromFields(response, false)
	if err != nil {
		return nil, uncertainMutation(path, err)
	}
	expected := make(map[string]bool, len(ids))
	for _, id := range ids {
		expected[id] = true
	}
	valid := len(records) == len(ids)
	for _, r := range records {
		valid = valid && expected[r.ID] && strings.HasPrefix(r.Name, newName+":")
		delete(expected, r.ID)
	}
	if !valid || len(expected) != 0 {
		clearRecords(records)
		return nil, uncertainMutation(path, errors.New("invalid remote credential rename response"))
	}
	return records, nil
}

func (c *Client) DeleteCredential(ctx context.Context, name string, ids []string) (int64, error) {
	const path = "/v1/credential/delete"
	var response credentialDeleted
	if err := c.request(ctx, path, credentialRequest{Name: name, IDs: ids}, &response); err != nil {
		return 0, err
	}
	if response.Name != name || response.Fields != int64(len(ids)) {
		return 0, uncertainMutation(path, errors.New("invalid remote credential deletion response"))
	}
	return response.Fields, nil
}
