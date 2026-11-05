package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/agyard/agsecret/internal/remote"
	"github.com/agyard/agsecret/internal/store"
)

func TestRemoteCredentialRenameRegression(t *testing.T) {
	client, host := newTestCLI(t), newTestCLI(t)
	password := host.put("account:password", "synthetic-password", "--uses", "3")["id"].(string)
	user := host.put("account:username", "synthetic-user", "--type", "plain")["id"].(string)
	mountVault(t, client, "work", host, "*")
	if groups := client.json("", "credential", "ls").([]any); len(groups) != 1 {
		t.Fatalf("remote credential absent: %v", groups)
	}
	if code, out, note := client.call("", "credential", "rename", "account", "renamed"); code != 1 || out != "" || !strings.Contains(note, "does not allow editing") || strings.Contains(note, "not found") {
		t.Fatalf("read-only error: %d %q %q", code, out, note)
	}
	host.ok("", "key", "update", "work", "--allow-edit")
	info := client.record("remote", "info", "work")
	policy := info["key"].(map[string]any)
	if policy["allow_edit"] != true || policy["allow_create"] != false {
		t.Fatalf("capabilities: %v", info)
	}
	group := client.record("credential", "rename", "account", "renamed")
	if group["name"] != "renamed" || len(group["fields"].([]any)) != 2 || host.id("renamed:password") != password || host.id("renamed:username") != user {
		t.Fatalf("remote rename lost fields: %v", group)
	}
	host.assertUsage(password, 3, 0)
	if groups := client.json("", "credential", "ls", "--source", "local").([]any); len(groups) != 0 {
		t.Fatalf("rename wrote to client vault: %v", groups)
	}
	client.ok("", "rename", password, "renamed:pass")
	if host.id("renamed:pass") != password {
		t.Fatal("field rename rotated identity")
	}
	client.ok("", "delete", user)
	deleted := client.record("credential", "delete", "renamed")
	if deleted["fields"] != float64(1) {
		t.Fatalf("remote delete count: %v", deleted)
	}
	if groups := host.json("", "credential", "ls").([]any); len(groups) != 0 {
		t.Fatalf("remote group remained: %v", groups)
	}
}

func TestRemotePutPermissionMatrix(t *testing.T) {
	for _, edit := range []bool{false, true} {
		for _, create := range []bool{false, true} {
			t.Run(fmt.Sprintf("edit=%t/create=%t", edit, create), func(t *testing.T) {
				client, host := newTestCLI(t), newTestCLI(t)
				original := host.put("account:username", "synthetic-user", "--type", "plain")["id"].(string)
				mountVault(t, client, "work", host, "*")
				host.ok("", "key", "update", "work", fmt.Sprintf("--allow-edit=%t", edit), fmt.Sprintf("--allow-create=%t", create))
				code, out, note := client.call("synthetic-update", "put", "account:username", "--stdin", "--json")
				if edit && code != 0 || !edit && (code != 1 || out != "" || !strings.Contains(note, "does not allow editing")) {
					t.Fatalf("update: %d %q %q", code, out, note)
				}
				current := host.record("view", "account:username")
				if edit && (current["id"] == original || current["value"] != "synthetic-update") || !edit && current["id"] != original {
					t.Fatalf("update target: %v", current)
				}
				code, out, note = client.call("synthetic-new", "put", "account:new", "--stdin", "--source", "work", "--json")
				if create && code != 0 || !create && (code != 1 || out != "" || !strings.Contains(note, "does not allow creating")) {
					t.Fatalf("create: %d %q %q", code, out, note)
				}
				if create && host.id("account:new") == "" {
					t.Fatal("new field not stored remotely")
				}
				if groups := client.json("", "credential", "ls", "--source", "local").([]any); len(groups) != 0 {
					t.Fatalf("remote put fell back locally: %v", groups)
				}
			})
		}
	}
}

func TestSourceSelectionAndMixedCredentialRefusal(t *testing.T) {
	client, first, second := newTestCLI(t), newTestCLI(t), newTestCLI(t)
	localID := client.put("account:username", "synthetic-local", "--type", "plain")["id"].(string)
	firstID := first.put("account:password", "synthetic-first")["id"].(string)
	secondID := second.put("account:password", "synthetic-second")["id"].(string)
	second.put("account:otp", "JBSWY3DPEHPK3PXP", "--type", "totp")
	server, _ := mountVault(t, client, "00_first", first, "*")
	mountVault(t, client, "10_second", second, "*")
	first.ok("", "key", "update", "00_first", "--allow-edit", "--allow-create")
	second.ok("", "key", "update", "10_second", "--allow-edit", "--allow-create")
	for _, operation := range []string{"rename", "delete"} {
		args := []string{"credential", operation, "account"}
		if operation == "rename" {
			args = append(args, "renamed")
		}
		if code, out, note := client.call("", args...); code != 1 || out != "" || !strings.Contains(note, "multiple sources") {
			t.Fatalf("mixed group: %d %q %q", code, out, note)
		}
	}
	if client.id("account:username") != localID || first.id("account:password") != firstID || second.id("account:password") != secondID {
		t.Fatal("mixed refusal changed fields")
	}
	client.ok("", "credential", "rename", "account", "renamed", "--source", "10_second")
	if second.id("renamed:password") != secondID || first.id("account:password") != firstID || client.id("account:username") != localID {
		t.Fatal("explicit group selection changed another source")
	}
	client.put("account:password", "synthetic-shadow", "--source", "local")
	if first.id("account:password") != firstID {
		t.Fatal("local shadow overwrote the server")
	}
	if row := client.record("view", "account:password", "--source", "00_first"); row["id"] != firstID || row["source"] != "00_first" {
		t.Fatalf("explicit source did not bypass shadow: %v", row)
	}
	server.Close()
	if code, out, _ := client.call("synthetic-new", "put", "new-name", "--stdin"); code == 0 || out != "" {
		t.Fatal("unavailable source caused a silent local create")
	}
	client.put("new-name", "synthetic-local", "--source", "local")
	if row := client.record("view", "renamed:password", "--source", "10_second"); row["id"] != secondID {
		t.Fatal("explicit source was blocked by another source's outage")
	}
	if code, out, _ := client.call("synthetic", "put", "missing", "--stdin", "--source", "not-mounted"); code != 1 || out != "" {
		t.Fatal("unknown source created a local record")
	}
}

func TestRemotePutPinsSourceAndRejectsRotation(t *testing.T) {
	client, host := newTestCLI(t), newTestCLI(t)
	host.put("password", "synthetic-original")
	mountVault(t, client, "work", host, "*")
	host.ok("", "key", "update", "work", "--allow-edit", "--allow-create")
	o := &options{db: client.db, passFile: client.pass}
	err := o.withSources(func(s *sources) error {
		target, err := s.putTarget(context.Background(), "password")
		if err != nil {
			return err
		}
		defer clear(target.Secret)
		host.put("password", "synthetic-replacement")
		_, err = s.put(context.Background(), target, store.Change{Secret: []byte("synthetic-late")})
		return err
	})
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale update: %v", err)
	}
}

func TestRemoteWriteRefusesBeforeInputAndOldServerCompatibility(t *testing.T) {
	client, host := newTestCLI(t), newTestCLI(t)
	host.put("password", "synthetic-original")
	server, key := mountVault(t, client, "work", host, "*")
	input := &unusedKeyInput{}
	var out, note bytes.Buffer
	args := []string{"--db", client.db, "--pass-file", client.pass, "put", "password", "--stdin"}
	if code := Execute(args, input, &out, &note); code != 1 || input.read || !strings.Contains(note.String(), "does not allow editing") {
		t.Fatalf("read-only input read: %d %t %q", code, input.read, note.String())
	}
	server.Close()
	legacy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/capabilities" || r.URL.Path == "/v1/rename" || r.URL.Path == "/v1/credential/rename" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"unknown_endpoint"}`))
			return
		}
		vaultHandler(host).ServeHTTP(w, r)
	}))
	defer legacy.Close()
	client.ok("", "remote", "delete", "work")
	client.ok(key, "remote", "add", "work", legacy.URL, "--key-stdin")
	if client.id("password") == "" {
		t.Fatal("new client could not read a legacy server")
	}
	if code, out, note := client.call("", "rename", "password", "renamed"); code != 1 || out != "" || !strings.Contains(note, "upgrade the server") {
		t.Fatalf("legacy write error: %d %q %q", code, out, note)
	}
	// The low-level error stays distinguishable for other callers, too.
	c, err := remote.NewClient(legacy.URL, key)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Capabilities(context.Background()); !errors.Is(err, remote.ErrUnsupported) {
		t.Fatalf("legacy capability error: %v", err)
	}
}
