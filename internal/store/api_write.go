package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

var (
	ErrEditNotAllowed   = errors.New("the API key does not allow editing existing fields")
	ErrCreateNotAllowed = errors.New("the API key does not allow creating fields")
)

type APIKeyChange struct {
	Rules       *[]string
	AllowEdit   *bool
	AllowCreate *bool
}

// UpdateAPIKey changes policy without rotating the token. Every API operation
// reauthenticates inside its transaction, so revocations affect the next write.
func (s *Store) UpdateAPIKey(name string, change APIKeyChange) error {
	if err := ValidateAPIKeyName(name); err != nil {
		return err
	}
	if change.Rules != nil {
		if err := ValidateRules(*change.Rules); err != nil {
			return err
		}
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(serverSchema); err != nil {
		return err
	}
	var digest []byte
	if err := tx.QueryRow("SELECT digest FROM api_keys WHERE name=?", name).Scan(&digest); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if change.Rules != nil {
		encoded, _ := json.Marshal(*change.Rules)
		if _, err := tx.Exec("UPDATE api_keys SET rules=? WHERE name=?", string(encoded), name); err != nil {
			return err
		}
	}
	if _, err := tx.Exec("INSERT INTO api_key_permissions(digest) VALUES(?) ON CONFLICT(digest) DO NOTHING", digest); err != nil {
		return err
	}
	if change.AllowEdit != nil {
		if _, err := tx.Exec("UPDATE api_key_permissions SET allow_edit=? WHERE digest=?", *change.AllowEdit, digest); err != nil {
			return err
		}
	}
	if change.AllowCreate != nil {
		if _, err := tx.Exec("UPDATE api_key_permissions SET allow_create=? WHERE digest=?", *change.AllowCreate, digest); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func authenticateKey(tx *sql.Tx, token string) (APIKey, error) {
	rules, err := authenticate(tx, token)
	if err != nil {
		return APIKey{}, err
	}
	key := APIKey{Rules: rules}
	digest := sha256.Sum256([]byte(token))
	if err := tx.QueryRow("SELECT name FROM api_keys WHERE digest=?", digest[:]).Scan(&key.Name); err != nil {
		return APIKey{}, err
	}
	exists, err := hasTable(tx, "api_key_permissions")
	if err != nil {
		return APIKey{}, err
	}
	if exists {
		err := tx.QueryRow("SELECT allow_edit,allow_create FROM api_key_permissions WHERE digest=?", digest[:]).Scan(&key.AllowEdit, &key.AllowCreate)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return APIKey{}, err
		}
	}
	return key, nil
}

func (s *Store) APICapabilities(token string) (APIKey, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return APIKey{}, err
	}
	defer tx.Rollback()
	return authenticateKey(tx, token)
}

func (s *Store) APIPut(token, name string, change Change) (PutResult, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return PutResult{}, err
	}
	defer tx.Rollback()
	key, err := authenticateKey(tx, token)
	if err != nil {
		return PutResult{}, err
	}
	if !rulesAllow(key.Rules, name) {
		return PutResult{}, ErrNotFound
	}
	if change.SkipCheck {
		return PutResult{}, ErrNotAllowed
	}
	if change.ExpectedID == nil {
		return PutResult{}, ErrInvalidChange
	}
	r, err := getRecord(tx, name, false)
	defer clear(r.Secret)
	switch {
	case errors.Is(err, ErrNotFound):
		if !key.AllowCreate {
			return PutResult{}, ErrCreateNotAllowed
		}
	case err != nil:
		return PutResult{}, err
	default:
		if !key.AllowEdit {
			return PutResult{}, ErrEditNotAllowed
		}
	}
	result, err := putInTransaction(tx, name, change)
	if err != nil {
		return PutResult{}, err
	}
	visible := result.Duplicates[:0]
	for _, duplicate := range result.Duplicates {
		if rulesAllow(key.Rules, duplicate) {
			visible = append(visible, duplicate)
		}
	}
	clear(result.Duplicates[len(visible):])
	result.Duplicates = visible
	if err := tx.Commit(); err != nil {
		clear(result.Record.Secret)
		return PutResult{}, err
	}
	return result, nil
}

func editRecord(tx *sql.Tx, token, id string) (Record, APIKey, error) {
	key, err := authenticateKey(tx, token)
	if err != nil {
		return Record{}, key, err
	}
	if !key.AllowEdit {
		return Record{}, key, ErrEditNotAllowed
	}
	if err := CheckID(id); err != nil {
		return Record{}, key, ErrInvalidChange
	}
	r, err := getRecord(tx, id, false)
	if err != nil {
		return Record{}, key, err
	}
	if !rulesAllow(key.Rules, r.Name) {
		clear(r.Secret)
		return Record{}, key, ErrNotFound
	}
	return r, key, nil
}

func (s *Store) APIRename(token, id, newName string) (Record, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return Record{}, err
	}
	defer tx.Rollback()
	r, key, err := editRecord(tx, token, id)
	defer clear(r.Secret)
	if err != nil {
		return Record{}, err
	}
	if ValidateName(newName) != nil {
		return Record{}, ErrInvalidChange
	}
	if !rulesAllow(key.Rules, newName) {
		return Record{}, ErrNotAllowed
	}
	renamed, err := rename(tx, id, newName)
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		clear(renamed.Secret)
		return Record{}, err
	}
	return renamed, nil
}

func (s *Store) APIDelete(token, id string) (Record, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return Record{}, err
	}
	defer tx.Rollback()
	r, _, err := editRecord(tx, token, id)
	if err != nil {
		return Record{}, err
	}
	if _, err = tx.Exec("DELETE FROM secrets WHERE id=?", id); err == nil {
		err = tx.Commit()
	}
	if err != nil {
		clear(r.Secret)
		return Record{}, err
	}
	return r, nil
}

func editCredential(tx *sql.Tx, token, name string, ids []string) error {
	key, err := authenticateKey(tx, token)
	if err != nil {
		return err
	}
	if !key.AllowEdit {
		return ErrEditNotAllowed
	}
	if ValidateCredential(name) != nil || len(ids) == 0 {
		return ErrInvalidChange
	}
	for _, id := range ids {
		if !ValidID(id) {
			return ErrInvalidChange
		}
	}
	records, err := credentialRecords(tx, name)
	if err != nil {
		return err
	}
	defer clearRecords(records)
	if len(records) == 0 {
		return ErrNotFound
	}
	visible := 0
	for _, r := range records {
		if rulesAllow(key.Rules, r.Name) {
			visible++
		}
	}
	if visible == 0 {
		return ErrNotFound
	}
	if visible != len(records) {
		return fmt.Errorf("credential is only partially authorized: %w", ErrNotAllowed)
	}
	return checkCredentialIDs(records, ids)
}

func (s *Store) APIRenameCredential(token, name, newName string, ids []string) ([]Record, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := editCredential(tx, token, name, ids); err != nil {
		return nil, err
	}
	key, err := authenticateKey(tx, token)
	if err != nil {
		return nil, err
	}
	if ValidateCredential(newName) != nil {
		return nil, ErrInvalidChange
	}
	records, err := credentialRecords(tx, name)
	if err != nil {
		return nil, err
	}
	defer clearRecords(records)
	for _, r := range records {
		_, field := SplitName(r.Name)
		if ValidateName(newName+":"+field) != nil {
			return nil, ErrInvalidChange
		}
		if !rulesAllow(key.Rules, newName+":"+field) {
			return nil, ErrNotAllowed
		}
	}
	renamed, err := renameCredential(tx, name, newName, ids)
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		clearRecords(renamed)
		return nil, err
	}
	return renamed, nil
}

func (s *Store) APIDeleteCredential(token, name string, ids []string) (int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if err := editCredential(tx, token, name, ids); err != nil {
		return 0, err
	}
	count, err := deleteCredential(tx, name, ids)
	if err == nil {
		err = tx.Commit()
	}
	return count, err
}
