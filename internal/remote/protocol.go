// Package remote provides the credential server and its HTTP client.
package remote

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/agyard/agsecret/internal/store"
)

const (
	maxRequestBytes  = 1 << 20
	maxResponseBytes = 64 << 20
)

// field separates the wire format from the vault model. Value is present for
// plain metadata and for a successful use; TOTP use contains a generated code.
type field struct {
	Name      string       `json:"name"`
	ID        string       `json:"id"`
	Type      string       `json:"type"`
	CreatedAt time.Time    `json:"created_at"`
	UpdatedAt time.Time    `json:"updated_at"`
	ExpiresAt *time.Time   `json:"expires_at,omitempty"`
	AllowGet  bool         `json:"allow_get"`
	AllowExec bool         `json:"allow_exec"`
	MaxUses   int64        `json:"max_uses"`
	UsedCount int64        `json:"used_count"`
	Leaks     []store.Leak `json:"leaks,omitempty"`
	Value     string       `json:"value,omitempty"`
}

type useRequest struct {
	IDs    []string `json:"ids"`
	Action string   `json:"action"`
}

type reportRequest struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func toField(r store.Record, used bool) field {
	f := field{
		Name: r.Name, ID: r.ID, Type: r.Type, CreatedAt: r.CreatedAt,
		UpdatedAt: r.UpdatedAt, ExpiresAt: r.ExpiresAt, AllowGet: r.AllowGet,
		AllowExec: r.AllowExec, MaxUses: r.MaxUses, UsedCount: r.UsedCount, Leaks: r.Leaks,
	}
	if used || r.Type == "plain" {
		f.Value = string(r.Secret)
	}
	return f
}

func fromFields(fields []field, used bool) ([]store.Record, error) {
	if fields == nil {
		return nil, errors.New("invalid remote field response")
	}
	records := make([]store.Record, 0, len(fields))
	seenIDs, seenNames := map[string]bool{}, map[string]bool{}
	for _, f := range fields {
		if err := f.validate(used); err != nil || seenIDs[f.ID] || seenNames[f.Name] {
			clearRecords(records)
			return nil, errors.New("invalid remote field response")
		}
		seenIDs[f.ID], seenNames[f.Name] = true, true
		if f.Leaks == nil {
			f.Leaks = []store.Leak{}
		}
		records = append(records, store.Record{
			Name: f.Name, ID: f.ID, Type: f.Type, CreatedAt: f.CreatedAt,
			UpdatedAt: f.UpdatedAt, ExpiresAt: f.ExpiresAt, AllowGet: f.AllowGet,
			AllowExec: f.AllowExec, MaxUses: f.MaxUses, UsedCount: f.UsedCount,
			Leaks: f.Leaks, Secret: []byte(f.Value),
		})
	}
	return records, nil
}

func (f field) validate(used bool) error {
	if !store.ValidID(f.ID) || store.ValidateName(f.Name) != nil ||
		f.CreatedAt.IsZero() || f.UpdatedAt.IsZero() || f.MaxUses < 0 || f.UsedCount < 0 {
		return errors.New("invalid metadata")
	}
	switch f.Type {
	case "plain", "password", "totp":
	default:
		return errors.New("invalid type")
	}
	if !used && f.Type != "plain" {
		if f.Value != "" {
			return errors.New("unexpected sensitive value")
		}
		return nil
	}
	if f.Value == "" || len(f.Value) > store.MaxSecretLen || !utf8.ValidString(f.Value) || strings.IndexByte(f.Value, 0) >= 0 {
		return errors.New("invalid value")
	}
	if f.Type == "totp" && (len(f.Value) != 6 && len(f.Value) != 8 || strings.ContainsFunc(f.Value, func(r rune) bool { return r < '0' || r > '9' })) {
		return errors.New("invalid TOTP code")
	}
	return nil
}

func clearRecords(records []store.Record) {
	for i := range records {
		clear(records[i].Secret)
	}
}

func decodeJSON(r io.Reader, dst any) error {
	d := json.NewDecoder(r)
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("expected one JSON value")
	}
	return nil
}
