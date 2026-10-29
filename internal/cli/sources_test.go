package cli

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/agyard/agsecret/internal/remote"
	"github.com/agyard/agsecret/internal/store"
)

func openTestVault(t *testing.T, c testCLI) *store.Store {
	t.Helper()
	s, err := store.Open(c.db, []byte("test-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// Open each test server vault only for its request. Production servers run in
// separate processes; this keeps the in-process multi-server fixture bounded.
func vaultHandler(c testCLI) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, err := store.Open(c.db, []byte("test-passphrase"))
		if err != nil {
			http.Error(w, "vault unavailable", http.StatusInternalServerError)
			return
		}
		defer s.Close()
		remote.NewHandler(s).ServeHTTP(w, r)
	})
}

func mountVault(t *testing.T, client testCLI, name string, host testCLI, rules ...string) (*httptest.Server, string) {
	t.Helper()
	args := []string{"key", "create", name}
	for _, rule := range rules {
		args = append(args, "--rule", rule)
	}
	key, _ := host.ok("", args...)
	server := httptest.NewServer(vaultHandler(host))
	t.Cleanup(server.Close)
	client.ok(key, "remote", "add", name, server.URL, "--key-stdin")
	return server, strings.TrimSpace(key)
}

func TestRemoteOverlayAndIdentity(t *testing.T) {
	local, first, second := newTestCLI(t), newTestCLI(t), newTestCLI(t)
	localID := local.put("pku:password", "local-password")["id"]
	firstID := first.put("pku:password", "first-password")["id"].(string)
	first.put("pku:user", "first-user", "--type", "plain")
	first.put("pku:otp", "JBSWY3DPEHPK3PXP", "--type", "totp")
	second.put("pku:user", "second-user", "--type", "plain")
	second.put("pku:url", "https://example.com", "--type", "plain")
	secondID := second.put("independent", "independent-value", "--type", "plain")["id"].(string)
	// Register in reverse order to prove names determine precedence.
	mountVault(t, local, "10_second", second, "*")
	server, _ := mountVault(t, local, "00_first", first, "*", "!*:otp")
	rows := local.json("", "ls").([]any)
	if len(rows) != 4 || rows[0].(map[string]any)["name"] != "independent" {
		t.Fatalf("merged fields: %v", rows)
	}
	if r := local.record("view", "pku:password"); r["id"] != localID || r["source"] != "local" {
		t.Fatalf("local precedence: %v", r)
	}
	if r := local.record("view", "pku:user"); r["value"] != "first-user" || r["source"] != "00_first" {
		t.Fatalf("remote precedence: %v", r)
	}
	if r := local.record("view", firstID); r["source"] != "00_first" {
		t.Fatalf("shadowed ID: %v", r)
	}
	if group := local.record("credential", "view", "pku"); len(group["fields"].([]any)) != 3 {
		t.Fatalf("field-level group merge: %v", group)
	}
	local.ok("", "report", firstID)
	if r := first.record("view", firstID); len(r["leaks"].([]any)) != 1 {
		t.Fatalf("report destination: %v", r)
	}
	if r := local.record("view", "pku:password"); len(r["leaks"].([]any)) != 0 {
		t.Fatal("remote report changed local field")
	}
	local.ok("", "delete", "pku:password")
	if r := local.record("view", "pku:password"); r["id"] != firstID {
		t.Fatalf("remote field did not reappear: %v", r)
	}
	server.Close()
	for _, args := range [][]string{{"ls", "--json"}, {"view", "pku:user", "--json"}, {"view", "ags_ffffffffffffffff", "--json"}} {
		if code, out, _ := local.call("", args...); code == 0 || out != "" {
			t.Fatalf("incomplete lookup succeeded: %v: %d %q", args, code, out)
		}
	}
	if out, _ := local.ok("", "get", secondID); out != "independent-value\n" {
		t.Fatalf("known ID blocked by unrelated outage: %q", out)
	}
	local.put("pku:user", "offline-local", "--type", "plain")
	if out, _ := local.ok("", "get", "pku:user"); out != "offline-local\n" {
		t.Fatalf("local field blocked by outage: %q", out)
	}
}

func TestRemoteExecUseRedactionAndTOTP(t *testing.T) {
	local, host := newTestCLI(t), newTestCLI(t)
	usedID := host.put("used", "used-remote-password", "--uses", "2")["id"].(string)
	host.put("unused", "unrelated-credential")
	localID := local.put("local", "local-password")["id"].(string)
	otpID := host.put("otp", "JBSWY3DPEHPK3PXP", "--type", "totp")["id"].(string)
	mountVault(t, local, "work", host, "*")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGSECRET_CLI_OUTPUT_HELPER", "1")
	t.Setenv("AGSECRET_CLI_OUTPUT_VALUE", usedID+"|local-password|unrelated-credential")
	out, _ := local.ok("", "exec", "--", executable, "-test.run=^TestCLIOutputHelper$", usedID, usedID)
	want := "[REDACTED:" + usedID + "]|[REDACTED:" + localID + "]|unrelated-credential\n"
	if out != want {
		t.Fatalf("remote redaction boundary: %q", out)
	}
	host.assertUsage(usedID, 2, 1)
	if code, out, _ := local.call("", "get", usedID); code != 2 || out != "" {
		t.Fatal("remote password get allowed")
	}
	host.assertUsage(usedID, 2, 1)
	t.Setenv("AGSECRET_CLI_OUTPUT_VALUE", otpID)
	code, _ := local.ok("", "get", otpID)
	if len(strings.TrimSpace(code)) != 6 {
		t.Fatalf("remote OTP: %q", code)
	}
	out, note := local.ok("", "exec", "--", executable, "-test.run=^TestCLIOutputHelper$")
	if len(strings.TrimSpace(out)) != 6 || strings.Contains(out+note, "REDACTED") {
		t.Fatalf("remote OTP was filtered: %q %q", out, note)
	}
	// Deleting a key takes effect for the already mounted client.
	host.ok("", "key", "delete", "work")
	if code, out, _ := local.call("", "view", usedID); code == 0 || out != "" {
		t.Fatal("deleted API key remained usable")
	}
}

func TestRemoteUseFailureConsumesEarlierSources(t *testing.T) {
	local, host := newTestCLI(t), newTestCLI(t)
	localID := local.put("local", "local-password", "--uses", "2")["id"].(string)
	remoteID := host.put("remote", "remote-password")["id"].(string)
	key, _ := host.ok("", "key", "create", "client", "--rule", "*")
	handler := vaultHandler(host)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/use" {
			requests.Add(1)
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	defer server.Close()
	local.ok(key, "remote", "add", "work", server.URL, "--key-stdin")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGSECRET_CLI_OUTPUT_HELPER", "1")
	t.Setenv("AGSECRET_CLI_OUTPUT_VALUE", "child-started")
	code, out, note := local.call("", "exec", "--", executable, "-test.run=^TestCLIOutputHelper$", localID, remoteID)
	if code != 125 || out != "" || !strings.Contains(note, "uses may have been consumed") || requests.Load() != 1 {
		t.Fatalf("partial failure: %d %q %q requests=%d", code, out, note, requests.Load())
	}
	local.assertUsage(localID, 2, 1)
}

func TestResolvedSourceStaysPinned(t *testing.T) {
	local, host := newTestCLI(t), newTestCLI(t)
	local.put("password", "original-password")
	host.put("password", "fallback-password")
	mountVault(t, local, "work", host, "*")
	a := openTestVault(t, local)
	mounts, err := a.Remotes()
	if err != nil {
		t.Fatal(err)
	}
	s := &sources{local: a, mounts: mounts, clients: map[string]*remote.Client{}}
	r, err := s.get(context.Background(), "password")
	if err != nil {
		t.Fatal(err)
	}
	local.put("password", "replacement-password")
	if _, err := s.use(context.Background(), []store.Record{r}, "exec"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("rotation changed resolved field: %v", err)
	}
	host.assertUsage("password", 0, 0)
}
