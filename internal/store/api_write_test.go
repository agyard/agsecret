package store

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func writableKey(t *testing.T, s *Store, permissions KeyPermissions, rules ...string) string {
	t.Helper()
	key, err := s.CreateAPIKeyWithPermissions("writer", rules, permissions)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestAPIWritePermissionMatrix(t *testing.T) {
	for _, edit := range []bool{false, true} {
		for _, create := range []bool{false, true} {
			t.Run(fmt.Sprintf("edit=%t/create=%t", edit, create), func(t *testing.T) {
				s, _ := newTestStore(t)
				r := put(t, s, "account:password", "synthetic-old").Record
				other := put(t, s, "other", "synthetic-other").Record
				key := writableKey(t, s, KeyPermissions{AllowEdit: edit, AllowCreate: create}, "*")
				if _, err := s.APIGet(key, r.ID); err != nil {
					t.Fatal(err)
				}
				used, err := s.APIConsume(key, []string{r.ID}, "exec")
				if err != nil {
					t.Fatal(err)
				}
				clearRecords(used)
				if _, err := s.APIReport(key, r.ID, "synthetic"); err != nil {
					t.Fatal(err)
				}
				created, err := s.APIPut(key, "new:password", Change{ExpectedID: ptr(""), Secret: []byte("synthetic-new")})
				if create && (err != nil || !created.Created) || !create && !errors.Is(err, ErrCreateNotAllowed) {
					t.Fatalf("create: %+v %v", created, err)
				}
				updated, err := s.APIPut(key, r.Name, Change{ExpectedID: &r.ID, Secret: []byte("synthetic-rotated")})
				if edit && (err != nil || updated.PreviousID != r.ID || updated.Record.ID == r.ID) || !edit && !errors.Is(err, ErrEditNotAllowed) {
					t.Fatalf("update: %+v %v", updated, err)
				}
				_, err = s.APIRename(key, other.ID, "renamed")
				if edit && err != nil || !edit && !errors.Is(err, ErrEditNotAllowed) {
					t.Fatalf("rename: %v", err)
				}
				_, err = s.APIDelete(key, other.ID)
				if edit && err != nil || !edit && !errors.Is(err, ErrEditNotAllowed) {
					t.Fatalf("delete: %v", err)
				}
				current, err := s.Get(r.Name, false)
				if err != nil {
					t.Fatal(err)
				}
				group, err := s.APIRenameCredential(key, "account", "moved", []string{current.ID})
				if edit && (err != nil || group[0].ID != current.ID) || !edit && !errors.Is(err, ErrEditNotAllowed) {
					t.Fatalf("group rename: %+v %v", group, err)
				}
				if edit {
					if n, err := s.APIDeleteCredential(key, "moved", []string{current.ID}); err != nil || n != 1 {
						t.Fatalf("group delete: %d %v", n, err)
					}
				} else if _, err := s.APIDeleteCredential(key, "account", []string{current.ID}); !errors.Is(err, ErrEditNotAllowed) {
					t.Fatalf("read-only group delete: %v", err)
				}
			})
		}
	}
}

func TestLegacyKeyPermissionsAndLiveChanges(t *testing.T) {
	s, _ := newTestStore(t)
	r := put(t, s, "work:password", "synthetic").Record
	key := testAPIKey(t, s, "legacy", "work:*")
	if _, err := s.db.Exec("DROP TABLE api_key_permissions"); err != nil {
		t.Fatal(err)
	}
	policy, err := s.APICapabilities(key)
	if err != nil || policy.AllowEdit || policy.AllowCreate {
		t.Fatalf("legacy capabilities: %+v %v", policy, err)
	}
	if _, err := s.APIRename(key, r.ID, "work:renamed"); !errors.Is(err, ErrEditNotAllowed) {
		t.Fatal(err)
	}
	if keys, err := s.APIKeys(); err != nil || len(keys) != 1 || keys[0].AllowEdit || keys[0].AllowCreate {
		t.Fatalf("legacy keys: %+v %v", keys, err)
	}
	if exists, _ := hasTable(s.db, "api_key_permissions"); exists {
		t.Fatal("legacy reads migrated the schema")
	}
	if err := s.UpdateAPIKey("legacy", APIKeyChange{AllowEdit: ptr(true)}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.APIRename(key, r.ID, "work:renamed"); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateAPIKey("legacy", APIKeyChange{AllowEdit: ptr(false), AllowCreate: ptr(true)}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.APIDelete(key, r.ID); !errors.Is(err, ErrEditNotAllowed) {
		t.Fatalf("edit revocation: %v", err)
	}
	if _, err := s.APIPut(key, "work:new", Change{ExpectedID: ptr(""), Secret: []byte("synthetic-new")}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateAPIKey("legacy", APIKeyChange{Rules: ptr([]string{"other:*"})}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.APIGet(key, r.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("scope revocation: %v", err)
	}
	if err := s.DeleteAPIKey("legacy"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.APICapabilities(key); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked token: %v", err)
	}
	newKey := testAPIKey(t, s, "legacy", "*")
	policy, err = s.APICapabilities(newKey)
	if err != nil || policy.AllowEdit || policy.AllowCreate {
		t.Fatalf("recreated key inherited permissions: %+v %v", policy, err)
	}
}

func TestAPIWriteScopeAndAtomicCredentialChanges(t *testing.T) {
	s, _ := newTestStore(t)
	password := put(t, s, "work:password", "synthetic-shared").Record
	username := put(t, s, "work:username", "synthetic-user").Record
	put(t, s, "private:password", "synthetic-shared")
	key := writableKey(t, s, KeyPermissions{AllowEdit: true, AllowCreate: true}, "work:*", "moved:*", "!work:hidden", "!moved:username")
	if _, err := s.APIRename(key, password.ID, "private:renamed"); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("rename escaped scope: %v", err)
	}
	if _, err := s.APIPut(key, "private:new", Change{ExpectedID: ptr(""), Secret: []byte("synthetic")}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("create escaped scope: %v", err)
	}
	result, err := s.APIPut(key, password.Name, Change{ExpectedID: &password.ID, Secret: []byte("synthetic-shared")})
	if err != nil || len(result.Duplicates) != 0 || len(result.Record.Secret) != 0 {
		t.Fatalf("put exposed hidden duplicates or values: %+v %v", result, err)
	}
	ids := []string{password.ID, username.ID}
	if _, err := s.APIRenameCredential(key, "work", "moved", ids); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("destination scope not checked: %v", err)
	}
	if current, err := s.Credential("work"); err != nil || len(current) != 2 {
		t.Fatalf("failed rename was partial: %+v %v", current, err)
	}
	hidden := put(t, s, "work:hidden", "synthetic-hidden").Record
	for _, allIDs := range [][]string{ids, {password.ID, username.ID, hidden.ID}} {
		if _, err := s.APIDeleteCredential(key, "work", allIDs); !errors.Is(err, ErrNotAllowed) {
			t.Fatalf("partial group deleted: %v", err)
		}
	}
	if current, err := s.Credential("work"); err != nil || len(current) != 3 {
		t.Fatalf("group delete was partial: %+v %v", current, err)
	}
	if err := s.UpdateAPIKey("writer", APIKeyChange{Rules: ptr([]string{"*"})}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.APIDeleteCredential(key, "work", ids); !errors.Is(err, ErrConflict) {
		t.Fatalf("membership change ignored: %v", err)
	}
	put(t, s, "destination:other", "synthetic-occupied")
	if _, err := s.APIRenameCredential(key, "work", "destination", append(ids, hidden.ID)); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("group conflict: %v", err)
	}
	rotated := put(t, s, password.Name, "synthetic-rotated").Record
	if _, err := s.APIPut(key, password.Name, Change{ExpectedID: &password.ID, Secret: []byte("late-write")}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale put changed a replacement: %v", err)
	}
	if _, err := s.APIDelete(key, password.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stale ID deleted a replacement: %v", err)
	}
	if current, _ := s.Get(rotated.ID, false); current.ID != rotated.ID {
		t.Fatal("replacement lost")
	}
}

func TestAPIWritePreservesPolicyAndRequiresValueToWiden(t *testing.T) {
	s, _ := newTestStore(t)
	key := writableKey(t, s, KeyPermissions{AllowEdit: true, AllowCreate: true}, "*")
	expires := time.Now().Add(time.Hour)
	result, err := s.APIPut(key, "account:password", Change{ExpectedID: ptr(""), Secret: []byte("synthetic"), MaxUses: ptr(int64(2)), ExpiresAt: ptr(&expires), AllowGet: ptr(false)})
	if err != nil {
		t.Fatal(err)
	}
	r := result.Record
	used, err := s.APIConsume(key, []string{r.ID}, "exec")
	if err != nil {
		t.Fatal(err)
	}
	clearRecords(used)
	if _, err := s.APIReport(key, r.ID, "synthetic"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.APIPut(key, r.Name, Change{ExpectedID: &r.ID, MaxUses: ptr(int64(3))}); !errors.Is(err, ErrNeedsValue) {
		t.Fatalf("policy widened without value: %v", err)
	}
	if _, err := s.APIPut(key, r.Name, Change{ExpectedID: &r.ID, SkipCheck: true}); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("remote bypass allowed: %v", err)
	}
	moved, err := s.APIRenameCredential(key, "account", "renamed", []string{r.ID})
	if err != nil || moved[0].ID != r.ID || moved[0].UsedCount != 1 || moved[0].MaxUses != 2 || moved[0].AllowGet || len(moved[0].Leaks) != 1 || moved[0].ExpiresAt == nil {
		t.Fatalf("rename lost state: %+v %v", moved, err)
	}
	if _, err := s.APIPut(key, moved[0].Name, Change{ExpectedID: &r.ID, MaxUses: ptr(int64(1))}); err != nil {
		t.Fatal(err)
	}
}

func TestAPIConcurrentCreatesDoNotOverwrite(t *testing.T) {
	s, name := newTestStore(t)
	other, err := Open(name, []byte(testPass))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	key := writableKey(t, s, KeyPermissions{AllowEdit: true, AllowCreate: true}, "*")
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i, vault := range []*Store{s, other} {
		wg.Go(func() {
			_, err := vault.APIPut(key, "new", Change{ExpectedID: ptr(""), Secret: []byte(fmt.Sprintf("synthetic-%d", i))})
			results <- err
		})
	}
	wg.Wait()
	close(results)
	errorsSeen := []string{}
	for err := range results {
		if err == nil {
			errorsSeen = append(errorsSeen, "success")
		} else if errors.Is(err, ErrConflict) {
			errorsSeen = append(errorsSeen, "conflict")
		} else {
			t.Fatal(err)
		}
	}
	slices.Sort(errorsSeen)
	if strings.Join(errorsSeen, ",") != "conflict,success" {
		t.Fatal(errorsSeen)
	}
}
