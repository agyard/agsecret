package remote

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agyard/agsecret/internal/store"
)

func TestRequestBodyClearsSerializedValuesOnClose(t *testing.T) {
	data := []byte("synthetic-serialized-value")
	body := newRequestBody(data)
	var wg sync.WaitGroup
	wg.Go(func() { _, _ = io.Copy(io.Discard, body) })
	wg.Go(func() { _ = body.Close() })
	wg.Wait()
	if !bytes.Equal(data, make([]byte, len(data))) {
		t.Fatal("serialized value was retained after close")
	}
	if _, err := body.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("closed body remained readable: %v", err)
	}
	if err := body.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRemoteWriteRoundTripAndMaximumValue(t *testing.T) {
	s := testVault(t)
	key, err := s.CreateAPIKeyWithPermissions("writer", []string{"*"}, store.KeyPermissions{AllowEdit: true, AllowCreate: true})
	if err != nil {
		t.Fatal(err)
	}
	c := testClient(t, NewHandler(s), key)
	ctx := context.Background()
	policy, err := c.Capabilities(ctx)
	if err != nil || !policy.AllowCreate || !policy.AllowEdit {
		t.Fatalf("capabilities: %+v %v", policy, err)
	}
	absent := ""
	const synthetic = "synthetic-password"
	maximum := strings.Repeat("x", store.MaxSecretLen)
	created, err := c.Put(ctx, "account:password", store.Change{ExpectedID: &absent, Secret: []byte(maximum)})
	if err != nil || !created.Created || len(created.Record.Secret) != 0 {
		t.Fatalf("maximum-size create: %v", err)
	}
	id := created.Record.ID
	expires := time.Now().Add(time.Hour)
	expiry := &expires
	updated, err := c.Put(ctx, "account:password", store.Change{ExpectedID: &id, Secret: []byte(synthetic), ExpiresAt: &expiry})
	if err != nil || updated.PreviousID != id || updated.Record.ExpiresAt == nil || len(updated.Record.Secret) != 0 {
		t.Fatalf("expiry put: %+v %v", updated, err)
	}
	id = updated.Record.ID
	var noExpiry *time.Time
	updated, err = c.Put(ctx, "account:password", store.Change{ExpectedID: &id, Secret: []byte(synthetic), ExpiresAt: &noExpiry})
	if err != nil || updated.Record.ExpiresAt != nil || updated.Record.ID != id {
		t.Fatalf("clear expiry: %+v %v", updated, err)
	}
	if _, err := c.Put(ctx, "account:password", store.Change{ExpectedID: &absent, Secret: []byte("synthetic-conflict")}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale create: %v", err)
	}
	if _, err := c.Rename(ctx, id, "account:pass"); err != nil {
		t.Fatal(err)
	}
	plain := "plain"
	user, err := c.Put(ctx, "account:username", store.Change{ExpectedID: &absent, Secret: []byte("synthetic-user"), Type: &plain})
	if err != nil || string(user.Record.Secret) != "synthetic-user" {
		t.Fatalf("plain put: %+v %v", user, err)
	}
	ids := []string{id, user.Record.ID}
	renamed, err := c.RenameCredential(ctx, "account", "renamed", ids)
	if err != nil || len(renamed) != 2 {
		t.Fatalf("group rename: %+v %v", renamed, err)
	}
	if n, err := c.DeleteCredential(ctx, "renamed", ids); err != nil || n != 2 {
		t.Fatalf("group delete: %d %v", n, err)
	}
	if _, err := c.Get(ctx, id); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("group deletion retained a field")
	}
	for _, kind := range []string{"password", "totp", "plain"} {
		value := "synthetic-value"
		if kind == "totp" {
			value = "JBSWY3DPEHPK3PXP"
		}
		result, err := c.Put(ctx, kind, store.Change{ExpectedID: &absent, Secret: []byte(value), Type: &kind})
		if err != nil || kind != "plain" && len(result.Record.Secret) != 0 {
			t.Fatalf("%s create: %v", kind, err)
		}
		if _, err := c.Delete(ctx, result.Record.ID); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRemoteWriteErrorsAndWireValidation(t *testing.T) {
	s := testVault(t)
	r := testPut(t, s, "account:password", "password", "synthetic-password")
	key, err := s.CreateAPIKey("readonly", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	c := testClient(t, NewHandler(s), key)
	absent := ""
	if _, err := c.Put(context.Background(), "new", store.Change{ExpectedID: &absent, Secret: []byte("synthetic")}); !errors.Is(err, store.ErrCreateNotAllowed) {
		t.Fatalf("create mapping: %v", err)
	}
	if _, err := c.Rename(context.Background(), r.ID, "renamed"); !errors.Is(err, store.ErrEditNotAllowed) {
		t.Fatalf("edit mapping: %v", err)
	}
	if err := s.UpdateAPIKey("readonly", store.APIKeyChange{AllowEdit: boolPointer(true), AllowCreate: boolPointer(true)}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Put(context.Background(), r.Name, store.Change{ExpectedID: &r.ID, Secret: []byte{0}}); !errors.Is(err, store.ErrInvalidChange) {
		t.Fatalf("invalid value mapping: %v", err)
	}
	noAccess := false
	if _, err := c.Put(context.Background(), r.Name, store.Change{ExpectedID: &r.ID, AllowGet: &noAccess}); err != nil {
		t.Fatal(err)
	}
	yesAccess := true
	if _, err := c.Put(context.Background(), r.Name, store.Change{ExpectedID: &r.ID, AllowGet: &yesAccess}); !errors.Is(err, store.ErrNeedsValue) {
		t.Fatalf("needs-value mapping: %v", err)
	}
	for _, body := range []string{
		`{"name":"new","value":"c3ludGhldGlj"}`,
		`{"name":"new","expected_id":"","value":"c3ludGhldGlj","skip_check":true}`,
		`{"name":"new","expected_id":"invalid","value":"c3ludGhldGlj"}`,
		`{"name":"new","expected_id":"","value":"c3ludGhldGlj"} {}`,
	} {
		request := httptest.NewRequest(http.MethodPost, "/v1/put", strings.NewReader(body))
		request.Header.Set("Authorization", "Bearer "+key)
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		NewHandler(s).ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("invalid put status: %d", response.Code)
		}
	}
	if _, err := s.Get("new", false); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("invalid write created a field")
	}
}

func boolPointer(value bool) *bool { return &value }

func TestClientRejectsMismatchedWriteResponses(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	f := field{Name: "other:field", ID: "ags_1111111111111111", Type: "password", CreatedAt: now, UpdatedAt: now}
	id := "ags_0123456789abcdef"
	for _, operation := range []string{"put", "rename", "delete", "credential rename", "credential delete"} {
		t.Run(operation, func(t *testing.T) {
			c := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch operation {
				case "put":
					_ = json.NewEncoder(w).Encode(putResponse{Field: f})
				case "rename", "delete":
					_ = json.NewEncoder(w).Encode(f)
				case "credential rename":
					_ = json.NewEncoder(w).Encode([]field{f})
				case "credential delete":
					_ = json.NewEncoder(w).Encode(credentialDeleted{Name: "other", Fields: 2})
				}
			}), syntheticKey)
			var err error
			switch operation {
			case "put":
				_, err = c.Put(ctx, "account:field", store.Change{ExpectedID: &id})
			case "rename":
				_, err = c.Rename(ctx, id, "account:field")
			case "delete":
				_, err = c.Delete(ctx, id)
			case "credential rename":
				_, err = c.RenameCredential(ctx, "account", "renamed", []string{id})
			case "credential delete":
				_, err = c.DeleteCredential(ctx, "account", []string{id})
			}
			if err == nil || !strings.Contains(err.Error(), "change may have been applied") {
				t.Fatalf("malformed mutation response: %v", err)
			}
		})
	}
}
