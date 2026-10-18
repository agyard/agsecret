package store

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestCredentialNames(t *testing.T) {
	for _, name := range []string{"standalone", "site:user", "site.example:otp", "personal/work:api-key", strings.Repeat("x", 126) + ":y"} {
		if err := ValidateName(name); err != nil {
			t.Errorf("valid name %q: %v", name, err)
		}
	}
	for _, name := range []string{"", ":field", "site:", "site:field:extra", "site:with space", "ags_0000000000000000", "site:ags_reserved", strings.Repeat("x", 127) + ":y"} {
		if err := ValidateName(name); err == nil {
			t.Errorf("invalid name %q accepted", name)
		}
	}
	if err := ValidateCredential("site:field"); err == nil {
		t.Fatal("qualified credential name accepted")
	}
	for _, tc := range []struct{ name, credential, field string }{{"site:user", "site", "user"}, {"standalone", "", "standalone"}} {
		credential, field := SplitName(tc.name)
		if credential != tc.credential || field != tc.field {
			t.Errorf("SplitName(%q) = %q, %q", tc.name, credential, field)
		}
	}
}

func TestPlainValues(t *testing.T) {
	s, _ := newTestStore(t)
	value := []byte("user@example.org")
	created, err := s.Put("site:user", Change{Secret: value, Type: ptr("plain")})
	if err != nil || string(created.Record.Secret) != string(value) {
		t.Fatalf("put plain: %+v %v", created, err)
	}
	clear(value)
	if string(created.Record.Secret) != "user@example.org" {
		t.Fatal("put result aliases input")
	}
	put(t, s, "site:password", "sensitive-value")
	for _, load := range []func() ([]Record, error){
		func() ([]Record, error) { r, err := s.Get(created.Record.ID, false); return []Record{r}, err },
		func() ([]Record, error) { return s.List(false) },
		func() ([]Record, error) { return s.Credential("site") },
	} {
		records, err := load()
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range records {
			if r.Type == "plain" && string(r.Secret) != "user@example.org" || r.Type == "password" && r.Secret != nil {
				t.Fatalf("metadata value: %+v", r)
			}
		}
	}
	for _, action := range []string{"get", "exec", "send"} {
		used, err := s.Consume(created.Record.ID, action)
		if err != nil || used.UsedCount != 0 || !used.UpdatedAt.Equal(created.Record.UpdatedAt) || string(used.Secret) != "user@example.org" {
			t.Fatalf("plain %s: %+v %v", action, used, err)
		}
	}
	if _, err := s.Report(created.Record.ID, "exposed"); err == nil {
		t.Fatal("plain report accepted")
	}
	for _, change := range []Change{
		{ExpiresAt: ptr[*time.Time](nil)}, {AllowGet: ptr(true)}, {AllowExec: ptr(true)}, {MaxUses: ptr[int64](0)}, {SkipCheck: true},
	} {
		if _, err := s.Put("site:user", change); err == nil {
			t.Fatalf("plain controls accepted: %+v", change)
		}
		change.Secret, change.Type = []byte("value"), ptr("plain")
		if _, err := s.Put("new", change); err == nil {
			t.Fatalf("new plain controls accepted: %+v", change)
		}
	}
}

func TestChangeToPlainClearsSensitiveState(t *testing.T) {
	s, _ := newTestStore(t)
	expires := time.Now().Add(time.Hour)
	created, err := s.Put("api", Change{Secret: []byte("value"), MaxUses: ptr[int64](2), ExpiresAt: ptr(&expires), AllowExec: ptr(false)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Consume(created.Record.ID, "get"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Report(created.Record.ID, "exposed"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put("api", Change{Type: ptr("plain")}); !errors.Is(err, ErrNeedsValue) {
		t.Fatalf("changing to plain without value: %v", err)
	}
	changed, err := s.Put("api", Change{Secret: []byte("value"), Type: ptr("plain")})
	if err != nil {
		t.Fatal(err)
	}
	r := changed.Record
	if r.ID == created.Record.ID || changed.PreviousID != created.Record.ID || string(r.Secret) != "value" || r.ExpiresAt != nil || !r.AllowGet || !r.AllowExec || r.MaxUses != 0 || r.UsedCount != 0 || len(r.Leaks) != 0 {
		t.Fatalf("type change kept sensitive state: %+v", changed)
	}
	if _, err := s.Get(created.Record.ID, false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old ID resolves: %v", err)
	}
}

func TestRenamePreservesRecordAndMovesNamespace(t *testing.T) {
	s, _ := newTestStore(t)
	expires := time.Now().Add(time.Hour)
	created, err := s.Put("password", Change{Secret: []byte("value"), ExpiresAt: ptr(&expires), MaxUses: ptr[int64](2)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Consume(created.Record.ID, "exec"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Report(created.Record.ID, "exposed"); err != nil {
		t.Fatal(err)
	}
	before, err := s.Get(created.Record.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"site:password", "another:pass", "standalone"} {
		r, err := s.Rename(created.Record.ID, name)
		if err != nil {
			t.Fatal(err)
		}
		before.Name, before.UpdatedAt = name, r.UpdatedAt
		if !reflect.DeepEqual(r, before) {
			t.Fatalf("rename changed record: got %+v want %+v", r, before)
		}
		stored, err := s.Get(name, true)
		if err != nil || string(stored.Secret) != "value" {
			t.Fatalf("renamed value: %+v %v", stored, err)
		}
	}
	put(t, s, "taken", "other")
	if _, err := s.Rename(created.Record.ID, "taken"); err == nil {
		t.Fatal("rename overwrote target")
	}
	if r, err := s.Rename("standalone", "standalone"); err != nil || r.ID != created.Record.ID {
		t.Fatalf("same-name rename: %+v %v", r, err)
	}
	if _, err := s.Rename("standalone", created.Record.ID); err == nil {
		t.Fatal("rename accepted ID as target")
	}
	if _, err := s.Credential("site"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty credential persists: %v", err)
	}
}

func TestCredentialGroupingAndAtomicChanges(t *testing.T) {
	s, _ := newTestStore(t)
	for _, name := range []string{"z", "alpha:x", "alpha-:b", "alpha:a", "a", "alpha-:a", "alpha", "other:z"} {
		put(t, s, name, "value-"+name)
	}
	all, err := s.List(false)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(all))
	for _, r := range all {
		names = append(names, r.Name)
	}
	if !slices.Equal(names, []string{"a", "alpha", "z", "alpha:a", "alpha:x", "alpha-:a", "alpha-:b", "other:z"}) {
		t.Fatalf("group order: %v", names)
	}
	before, err := s.Credential("alpha")
	if err != nil || len(before) != 2 {
		t.Fatalf("credential selection: %+v %v", before, err)
	}
	for _, target := range []string{"other", strings.Repeat("n", 127)} {
		if _, err := s.RenameCredential("alpha", target); err == nil {
			t.Fatalf("invalid credential rename to %s accepted", target)
		}
		after, err := s.Credential("alpha")
		if err != nil || !reflect.DeepEqual(before, after) {
			t.Fatalf("failed rename changed source: %+v %v", after, err)
		}
	}
	renamed, err := s.RenameCredential("alpha", "new")
	if err != nil || len(renamed) != 2 {
		t.Fatalf("credential rename: %+v %v", renamed, err)
	}
	for i, r := range renamed {
		before[i].Name, before[i].UpdatedAt = strings.Replace(before[i].Name, "alpha:", "new:", 1), r.UpdatedAt
		if !reflect.DeepEqual(before[i], r) {
			t.Fatalf("group rename changed record: %+v", r)
		}
	}
	if _, err := s.Credential("alpha"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old namespace persists: %v", err)
	}
	if n, err := s.DeleteCredential("new"); err != nil || n != 2 {
		t.Fatalf("delete credential: %d %v", n, err)
	}
	if _, err := s.DeleteCredential("new"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete empty credential: %v", err)
	}
	if remaining, err := s.Credential("alpha-"); err != nil || len(remaining) != 2 {
		t.Fatalf("namespace prefix damaged: %+v %v", remaining, err)
	}
	if _, err := s.Get("alpha", false); err != nil {
		t.Fatalf("standalone sharing namespace name damaged: %v", err)
	}
}

func TestMigrateV2PreservesRecordsAndAllowsPlain(t *testing.T) {
	s, path := newTestStore(t)
	expires := time.Now().Add(time.Hour)
	created, err := s.Put("api", Change{Secret: []byte("value"), ExpiresAt: ptr(&expires), MaxUses: ptr[int64](4), AllowGet: ptr(false)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Consume(created.Record.ID, "exec"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Report(created.Record.ID, "exposed"); err != nil {
		t.Fatal(err)
	}
	before, err := s.Get(created.Record.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	// Restore the actual v2 type constraint, so accepting plain proves the
	// migration rebuilt the table rather than only changing user_version.
	v2Schema := strings.ReplaceAll(strings.ReplaceAll(schema, ",'plain'", ""), "user_version=3", "user_version=2")
	if _, err := s.db.Exec("ALTER TABLE secrets RENAME TO v3_secrets;" + v2Schema +
		"INSERT INTO secrets SELECT * FROM v3_secrets; DROP TABLE v3_secrets;"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	migrated, err := Open(path, []byte(testPass))
	if err != nil {
		t.Fatal(err)
	}
	defer migrated.Close()
	after, err := migrated.Get(created.Record.ID, true)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("migration changed record: %+v %v", after, err)
	}
	if _, err := migrated.Put("site:user", Change{Secret: []byte("username"), Type: ptr("plain")}); err != nil {
		t.Fatalf("plain after migration: %v", err)
	}
}
