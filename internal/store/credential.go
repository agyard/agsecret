package store

import (
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// SplitName splits a validated name into its optional credential and field.
func SplitName(name string) (credential, field string) {
	if credential, field, ok := strings.Cut(name, ":"); ok {
		return credential, field
	}
	return "", name
}

// ValidateName accepts a standalone name or one credential:field pair.
func ValidateName(name string) error {
	if len(name) > maxNameBytes {
		return errors.New("a full name must be 1 to 128 bytes long")
	}
	credential, field, qualified := strings.Cut(name, ":")
	if !qualified {
		return ValidateCredential(name)
	}
	if err := ValidateCredential(credential); err != nil {
		return fmt.Errorf("invalid credential name: %w", err)
	}
	if err := ValidateCredential(field); err != nil {
		return fmt.Errorf("invalid field name: %w", err)
	}
	return nil
}

// ValidateCredential accepts a namespace or local field name without a colon.
func ValidateCredential(name string) error {
	switch {
	case name == "" || len(name) > maxNameBytes:
		return errors.New("a name must be 1 to 128 bytes long")
	case strings.HasPrefix(strings.ToLower(name), "ags_"):
		return errors.New("names cannot start with ags_")
	case strings.ContainsFunc(name, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._/@+-", r))
	}):
		return errors.New("a name may contain only letters, digits, '.', '_', '/', '@', '+' and '-'; use one ':' to separate a credential and field")
	}
	return nil
}

// Rename moves a secret without changing its value, identity or policies.
func (s *Store) Rename(ref, newName string) (Record, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return Record{}, err
	}
	defer tx.Rollback()
	r, err := rename(tx, ref, newName)
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		clear(r.Secret)
		return Record{}, err
	}
	return r, err
}

func rename(tx *sql.Tx, ref, newName string) (Record, error) {
	if err := validateRef(ref); err != nil {
		return Record{}, err
	}
	if err := ValidateName(newName); err != nil {
		return Record{}, err
	}
	r, err := getRecord(tx, ref, false)
	if err != nil || r.Name == newName {
		return r, err
	}
	var exists bool
	if err := tx.QueryRow("SELECT EXISTS(SELECT 1 FROM secrets WHERE name=?)", newName).Scan(&exists); err != nil {
		clear(r.Secret)
		return Record{}, err
	}
	if exists {
		clear(r.Secret)
		return Record{}, fmt.Errorf("secret %s already exists: %w", newName, ErrAlreadyExists)
	}
	r.Name, r.UpdatedAt = newName, now()
	if _, err := tx.Exec("UPDATE secrets SET name=?,updated_at=? WHERE id=?", r.Name, encodeTime(r.UpdatedAt), r.ID); err != nil {
		clear(r.Secret)
		return Record{}, err
	}
	return r, nil
}

const credentialWhere = "substr(name,1,instr(name,':'))=?"

// Credential returns the fields in a namespace, including plain values.
func (s *Store) Credential(name string) ([]Record, error) {
	if err := ValidateCredential(name); err != nil {
		return nil, err
	}
	rows, err := s.db.Query("SELECT "+columns(false)+" FROM secrets WHERE "+credentialWhere+" ORDER BY name", name+":")
	records, err := scanRecords(rows, err, false)
	if err == nil && len(records) == 0 {
		err = fmt.Errorf("credential %s %w", name, ErrNotFound)
	}
	return records, err
}

// RenameCredential atomically moves all fields to an unused namespace.
func (s *Store) RenameCredential(name, newName string) ([]Record, error) {
	return s.RenameCredentialChecked(name, newName, nil)
}

// RenameCredentialChecked also rejects changed group membership or rotated IDs.
func (s *Store) RenameCredentialChecked(name, newName string, ids []string) ([]Record, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	records, err := renameCredential(tx, name, newName, ids)
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		clearRecords(records)
		return nil, err
	}
	return records, nil
}

func credentialRecords(tx *sql.Tx, name string) ([]Record, error) {
	rows, err := tx.Query("SELECT "+columns(false)+" FROM secrets WHERE "+credentialWhere+" ORDER BY name", name+":")
	return scanRecords(rows, err, false)
}

func checkCredentialIDs(records []Record, expected []string) error {
	if expected == nil {
		return nil
	}
	ids := make([]string, len(records))
	for i, r := range records {
		ids[i] = r.ID
	}
	slices.Sort(ids)
	want := slices.Clone(expected)
	slices.Sort(want)
	if !slices.Equal(ids, want) {
		return ErrConflict
	}
	return nil
}

func renameCredential(tx *sql.Tx, name, newName string, ids []string) ([]Record, error) {
	if err := ValidateCredential(name); err != nil {
		return nil, err
	}
	if err := ValidateCredential(newName); err != nil {
		return nil, err
	}
	records, err := credentialRecords(tx, name)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("credential %s %w", name, ErrNotFound)
	}
	if err := checkCredentialIDs(records, ids); err != nil {
		clearRecords(records)
		return nil, err
	}
	if name == newName {
		return records, nil
	}
	var exists bool
	if err := tx.QueryRow("SELECT EXISTS(SELECT 1 FROM secrets WHERE "+credentialWhere+")", newName+":").Scan(&exists); err != nil {
		clearRecords(records)
		return nil, err
	}
	if exists {
		clearRecords(records)
		return nil, fmt.Errorf("credential %s already exists: %w", newName, ErrAlreadyExists)
	}
	updated := now()
	for i := range records {
		_, field := SplitName(records[i].Name)
		records[i].Name, records[i].UpdatedAt = newName+":"+field, updated
		if err := ValidateName(records[i].Name); err != nil {
			clearRecords(records)
			return nil, err
		}
	}
	if _, err := tx.Exec("UPDATE secrets SET name=?||substr(name,instr(name,':')),updated_at=? WHERE "+credentialWhere, newName, encodeTime(updated), name+":"); err != nil {
		clearRecords(records)
		return nil, err
	}
	return records, nil
}

// DeleteCredential atomically deletes all fields in a namespace.
func (s *Store) DeleteCredential(name string) (int64, error) {
	return s.DeleteCredentialChecked(name, nil)
}

func (s *Store) DeleteCredentialChecked(name string, ids []string) (int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	count, err := deleteCredential(tx, name, ids)
	if err == nil {
		err = tx.Commit()
	}
	return count, err
}

func deleteCredential(tx *sql.Tx, name string, ids []string) (int64, error) {
	if err := ValidateCredential(name); err != nil {
		return 0, err
	}
	records, err := credentialRecords(tx, name)
	if err != nil {
		return 0, err
	}
	defer clearRecords(records)
	if err := checkCredentialIDs(records, ids); err != nil {
		return 0, err
	}
	result, err := tx.Exec("DELETE FROM secrets WHERE "+credentialWhere, name+":")
	if err != nil {
		return 0, err
	}
	n, err := result.RowsAffected()
	if err == nil && n == 0 {
		err = fmt.Errorf("credential %s %w", name, ErrNotFound)
	}
	return n, err
}
