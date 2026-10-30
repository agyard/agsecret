package remote

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agyard/agsecret/internal/store"
	"github.com/agyard/agsecret/internal/totp"
)

const syntheticKey = "agk_0000000000000000000000000000000000000000000000000000000000000000"

func TestURLPolicy(t *testing.T) {
	for _, address := range []string{"https://secrets.example.com", "https://secrets.example.com:8443/", "http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080", "http://secrets.example.com", "http://192.168.0.1:8765"} {
		if err := ValidateURL(address); err != nil {
			t.Errorf("rejected %q: %v", address, err)
		}
	}
	for _, address := range []string{"http://127.0.0.1@elsewhere", "https://key@localhost", "https://host/api", "https://host?key=value", "https://host?", "https://host#fragment", "https://host#", "http://localhost:8765#", "file:///tmp/socket", "://host"} {
		if err := ValidateURL(address); err == nil {
			t.Errorf("accepted %q", address)
		}
	}
}

func testVault(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Create(filepath.Join(t.TempDir(), "secrets.db"), []byte("synthetic-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func testPut(t *testing.T, s *store.Store, name, kind, value string) store.Record {
	t.Helper()
	result, err := s.Put(name, store.Change{Type: &kind, Secret: []byte(value)})
	if err != nil {
		t.Fatal(err)
	}
	return result.Record
}

func testClient(t *testing.T, handler http.Handler, key string) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := NewClient(server.URL, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.http.CloseIdleConnections)
	return client
}

func TestServerClient(t *testing.T) {
	s := testVault(t)
	password := testPut(t, s, "pku_work:password", "password", "synthetic-password")
	const seed = "JBSWY3DPEHPK3PXP"
	code := testPut(t, s, "pku_work:otp", "totp", seed)
	plain := testPut(t, s, "pku_work:username", "plain", "alice")
	hidden := testPut(t, s, "pku_private:password", "password", "synthetic-password")
	key, err := s.CreateAPIKey("work", []string{"pku_*:*", "!pku_private:*"})
	if err != nil {
		t.Fatal(err)
	}
	client := testClient(t, NewHandler(s), key)
	ctx := context.Background()
	listed, err := client.List(ctx)
	if err != nil || len(listed) != 3 {
		t.Fatalf("list: %d fields, %v", len(listed), err)
	}
	for _, r := range listed {
		if r.Type != "plain" && len(r.Secret) != 0 {
			t.Fatal("metadata contains sensitive bytes")
		}
	}
	for _, ref := range []string{plain.Name, plain.ID} {
		r, err := client.Get(ctx, ref)
		if err != nil || string(r.Secret) != "alice" {
			t.Fatalf("plain lookup: %v", err)
		}
	}
	if _, err := client.Get(ctx, hidden.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("hidden field: %v", err)
	}
	before := time.Now()
	used, err := client.Use(ctx, []string{password.ID, code.ID, password.ID}, "exec")
	if err != nil || len(used) != 2 {
		t.Fatalf("use: %d fields, %v", len(used), err)
	}
	defer clearRecords(used)
	for _, r := range used {
		if r.UsedCount != 1 {
			t.Errorf("unexpected use count: %d", r.UsedCount)
		}
		if r.Type == "totp" {
			first, _ := totp.Generate(seed, before)
			last, _ := totp.Generate(seed, time.Now())
			if string(r.Secret) != first && string(r.Secret) != last {
				t.Error("TOTP use did not return a current code")
			}
		} else if string(r.Secret) != "synthetic-password" {
			t.Error("password use did not return its value")
		}
	}
	reported, err := client.Report(ctx, password.ID, "synthetic output")
	if err != nil || len(reported) != 1 || len(reported[0].Leaks) != 1 || len(reported[0].Secret) != 0 {
		t.Fatalf("report: %d fields, %v", len(reported), err)
	}
	r, err := s.Get(hidden.ID, false)
	if err != nil || len(r.Leaks) != 1 {
		t.Fatal("report did not update a hidden duplicate")
	}
	if _, err := client.Report(ctx, code.ID, "irrelevant"); !errors.Is(err, store.ErrReportType) {
		t.Fatalf("TOTP report: %v", err)
	}
	invalid := testClient(t, NewHandler(s), syntheticKey)
	if _, err := invalid.List(ctx); !errors.Is(err, store.ErrUnauthorized) {
		t.Fatalf("invalid API key: %v", err)
	}
}

func TestServerWireAndInput(t *testing.T) {
	s := testVault(t)
	const seed = "JBSWY3DPEHPK3PXP"
	code := testPut(t, s, "otp", "totp", seed)
	password := testPut(t, s, "password", "password", "synthetic-password")
	key, err := s.CreateAPIKey("all", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(s)
	for _, tc := range []struct {
		method, path, body string
		status             int
	}{
		{"GET", "/v1/fields", "", 200},
		{"GET", "/v1/field?ref=" + code.ID, "", 200},
		{"POST", "/v1/use", fmt.Sprintf(`{"ids":[%q],"action":"get"}`, code.ID), 200},
		{"POST", "/v1/use", fmt.Sprintf(`{"ids":[%q],"action":"unknown"}`, password.ID), 400},
		{"POST", "/v1/use", `{"ids":["password"],"action":"exec"}`, 400},
		{"POST", "/v1/use", `{"ids":[],"action":"exec"}`, 400},
		{"POST", "/v1/report", fmt.Sprintf(`{"id":%q,"reason":"ok","extra":true}`, password.ID), 400},
		{"POST", "/v1/report", fmt.Sprintf(`{"id":%q,"reason":%q}`, password.ID, strings.Repeat("x", maxRequestBytes)), 400},
		{"POST", "/v1/report", `{} {}`, 400},
	} {
		t.Run(tc.method+tc.path+fmt.Sprint(len(tc.body)), func(t *testing.T) {
			request := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			request.Header.Set("Authorization", "Bearer "+key)
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != tc.status {
				t.Fatalf("status %d, want %d", response.Code, tc.status)
			}
			for _, secret := range []string{seed, "synthetic-password", key} {
				if bytes.Contains(response.Body.Bytes(), []byte(secret)) {
					t.Fatal("response exposed a secret")
				}
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("missing cache control")
			}
		})
	}
	r, err := s.Get(password.ID, false)
	if err != nil || r.UsedCount != 0 || len(r.Leaks) != 0 {
		t.Fatal("invalid request mutated the vault")
	}
}

func TestClientRejectsRedirectsAndDoesNotReplayMutations(t *testing.T) {
	var redirected atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirected.Add(1)
	}))
	defer destination.Close()
	client := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}), syntheticKey)
	if _, err := client.List(context.Background()); err == nil || redirected.Load() != 0 {
		t.Fatalf("followed redirect: %v", err)
	}
	for _, action := range []string{"use", "report"} {
		t.Run(action, func(t *testing.T) {
			var attempts atomic.Int32
			client := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					_, _ = io.WriteString(w, "[]")
					return
				}
				attempts.Add(1)
				_, _ = io.Copy(io.Discard, r.Body)
				connection, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				_ = connection.Close()
			}), syntheticKey)
			if _, err := client.List(context.Background()); err != nil {
				t.Fatal(err)
			}
			var err error
			if action == "use" {
				_, err = client.Use(context.Background(), []string{"ags_0123456789abcdef"}, "exec")
			} else {
				_, err = client.Report(context.Background(), "ags_0123456789abcdef", "synthetic")
			}
			if err == nil || !strings.Contains(err.Error(), "may have been") || attempts.Load() != 1 {
				t.Fatalf("mutation attempts=%d, error=%v", attempts.Load(), err)
			}
		})
	}
}

func TestClientTLSAndUnknownEndpoint(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "[]")
	}))
	defer server.Close()
	client, err := NewClient(server.URL, syntheticKey)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.List(context.Background()); err == nil {
		t.Fatal("accepted an untrusted certificate")
	}
	transport := client.http.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.RootCAs = x509.NewCertPool()
	transport.TLSClientConfig.RootCAs.AddCert(server.Certificate())
	client.Close()
	client.http.Transport = transport
	if _, err := client.List(context.Background()); err != nil {
		t.Fatalf("trusted certificate: %v", err)
	}
	wrongService := testClient(t, http.NotFoundHandler(), syntheticKey)
	if _, err := wrongService.Get(context.Background(), "password"); err == nil || errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a missing API endpoint was mistaken for a missing field: %v", err)
	}
	for _, suffix := range []string{" {}", strings.Repeat(" ", 4096) + "{}"} {
		malformed := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"error":"not_found"}`+suffix)
		}), syntheticKey)
		if _, err := malformed.Get(context.Background(), "password"); err == nil || errors.Is(err, store.ErrNotFound) {
			t.Fatalf("malformed error was mistaken for a missing field: %v", err)
		}
	}
}

func TestClientValidatesFieldResponses(t *testing.T) {
	f := field{Name: "password", ID: "ags_0123456789abcdef", Type: "password", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	for _, tc := range []struct {
		name string
		edit func(*field)
	}{
		{"ID", func(f *field) { f.ID = "ags_bad" }},
		{"name", func(f *field) { f.Name = "invalid\nname" }},
		{"type", func(f *field) { f.Type = "unknown" }},
		{"secret metadata", func(f *field) { f.Value = "synthetic-password" }},
		{"counter", func(f *field) { f.UsedCount = -1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := f
			tc.edit(&changed)
			client := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode([]field{changed})
			}), syntheticKey)
			if _, err := client.List(context.Background()); err == nil {
				t.Fatal("accepted malformed field")
			}
		})
	}
	for _, fields := range [][]field{{}, {f, f}, {{Name: "other", ID: "ags_0000000000000000", Type: "plain", Value: "alice", CreatedAt: f.CreatedAt, UpdatedAt: f.UpdatedAt}}} {
		client := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(fields)
		}), syntheticKey)
		if _, err := client.Use(context.Background(), []string{f.ID}, "exec"); err == nil {
			t.Fatal("accepted mismatched use response")
		}
	}
	code := f
	code.Type, code.Value = "totp", "JBSWY3DPEHPK3PXP"
	if _, err := fromFields([]field{code}, true); err == nil {
		t.Fatal("accepted seed in place of a TOTP code")
	}
}
