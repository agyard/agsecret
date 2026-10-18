package store

import (
	"errors"
	"fmt"
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
	if err := validateRef(ref); err != nil {
		return Record{}, err
	}
	if err := ValidateName(newName); err != nil {
		return Record{}, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return Record{}, err
	}
	defer tx.Rollback()
	r, err := getRecord(tx, ref, false)
	if err != nil || r.Name == newName {
		return r, err
	}
	var exists bool
	if err := tx.QueryRow("SELECT EXISTS(SELECT 1 FROM secrets WHERE name=?)", newName).Scan(&exists); err != nil {
		return Record{}, err
	}
	if exists {
		return Record{}, fmt.Errorf("secret %s already exists", newName)
	}
	r.Name, r.UpdatedAt = newName, now()
	if _, err := tx.Exec("UPDATE secrets SET name=?,updated_at=? WHERE id=?", r.Name, encodeTime(r.UpdatedAt), r.ID); err != nil {
		return Record{}, err
	}
	return r, tx.Commit()
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
	if err := ValidateCredential(name); err != nil {
		return nil, err
	}
	if err := ValidateCredential(newName); err != nil {
		return nil, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.Query("SELECT "+columns(false)+" FROM secrets WHERE "+credentialWhere+" ORDER BY name", name+":")
	records, err := scanRecords(rows, err, false)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("credential %s %w", name, ErrNotFound)
	}
	if name == newName {
		return records, nil
	}
	var exists bool
	if err := tx.QueryRow("SELECT EXISTS(SELECT 1 FROM secrets WHERE "+credentialWhere+")", newName+":").Scan(&exists); err != nil {
		return nil, err
	}
	if exists {
		return nil, fmt.Errorf("credential %s already exists", newName)
	}
	updated := now()
	for i := range records {
		_, field := SplitName(records[i].Name)
		records[i].Name, records[i].UpdatedAt = newName+":"+field, updated
		if err := ValidateName(records[i].Name); err != nil {
			return nil, err
		}
	}
	if _, err := tx.Exec("UPDATE secrets SET name=?||substr(name,instr(name,':')),updated_at=? WHERE "+credentialWhere, newName, encodeTime(updated), name+":"); err != nil {
		return nil, err
	}
	return records, tx.Commit()
}

// DeleteCredential atomically deletes all fields in a namespace.
func (s *Store) DeleteCredential(name string) (int64, error) {
	if err := ValidateCredential(name); err != nil {
		return 0, err
	}
	result, err := s.db.Exec("DELETE FROM secrets WHERE "+credentialWhere, name+":")
	if err != nil {
		return 0, err
	}
	n, err := result.RowsAffected()
	if err == nil && n == 0 {
		err = fmt.Errorf("credential %s %w", name, ErrNotFound)
	}
	return n, err
}
