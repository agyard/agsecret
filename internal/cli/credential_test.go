package cli

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/agyard/agsecret/internal/store"
)

func TestCredentialWorkflow(t *testing.T) {
	c := newTestCLI(t)
	// A standalone secret and a credential may have the same name.
	standalone := c.put("account", "independent-password")["id"]
	password := c.put("account:password", "credential-password", "--uses", "2")["id"].(string)
	const seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	otp := c.put("account:otp", seed, "--type", "totp", "--uses", "1")["id"].(string)
	c.put("account:username", "student-user", "--type", "plain")
	c.put("account:note", "Line one\nLine two\x1b[31m", "--type", "plain")
	if r := c.record("view", "account"); r["id"] != standalone {
		t.Fatalf("standalone lookup resolved a group: %v", r)
	}
	group := c.record("credential", "view", "account")
	fields := group["fields"].([]any)
	if group["name"] != "account" || len(fields) != 4 {
		t.Fatalf("credential: %v", group)
	}
	for i, name := range []string{"account:note", "account:otp", "account:password", "account:username"} {
		field := fields[i].(map[string]any)
		if field["name"] != name {
			t.Fatalf("field order: %v", fields)
		}
		if field["type"] != "plain" && field["value"] != nil {
			t.Fatalf("credential revealed a protected value: %v", field)
		}
	}
	if fields[3].(map[string]any)["value"] != "student-user" {
		t.Fatalf("plain field hidden: %v", fields[3])
	}
	text, _ := c.ok("", "credential", "view", "account")
	if !strings.Contains(text, "student-user") || !strings.Contains(text, `Line one\nLine two\x1b[31m`) || strings.Contains(text, "credential-password") || strings.Contains(text, seed) || strings.ContainsRune(text, '\x1b') {
		t.Fatalf("credential display: %q", text)
	}
	c.assertUsage(password, 2, 0)
	c.assertUsage(otp, 1, 0)

	groups := c.json("", "credential", "ls").([]any)
	if len(groups) != 1 || groups[0].(map[string]any)["name"] != "account" || groups[0].(map[string]any)["fields"] != float64(4) {
		t.Fatalf("credential summary: %v", groups)
	}
	c.ok("", "get", password, "--dangerously-skip-check")
	c.ok("", "report", password, "--reason", "synthetic test report")
	group = c.record("credential", "rename", "account", "renamed")
	if group["name"] != "renamed" || len(group["fields"].([]any)) != 4 {
		t.Fatalf("renamed credential: %v", group)
	}
	r := c.record("view", password)
	if r["name"] != "renamed:password" || len(r["leaks"].([]any)) != 1 || c.id("renamed:otp") != otp {
		t.Fatalf("group rename lost field state: %v", r)
	}
	c.assertUsage(password, 2, 1)
	if c.id("account") != standalone {
		t.Fatal("group rename moved the independent secret")
	}
	if code, _, errText := c.call("", "credential", "view", "account"); code != 1 || !strings.Contains(errText, "not found") {
		t.Fatalf("old group remains: code=%d err=%q", code, errText)
	}
	deleted := c.record("credential", "rm", "renamed")
	if deleted["deleted"] != "renamed" || deleted["fields"] != float64(4) {
		t.Fatalf("group deletion: %v", deleted)
	}
	if groups := c.json("", "credential", "ls").([]any); len(groups) != 0 {
		t.Fatalf("empty credential remains: %v", groups)
	}
	if c.id("account") != standalone {
		t.Fatal("group deletion removed independent secret")
	}
}

func TestRenameMovesAndConflicts(t *testing.T) {
	c := newTestCLI(t)
	id := c.put("password", "test-password")["id"].(string)
	if r := c.record("rename", id, "account:password"); r["name"] != "account:password" || r["id"] != id {
		t.Fatalf("move into credential: %v", r)
	}
	c.ok("", "rename", "account:password", "account:pass")
	c.ok("", "rename", "account:pass", "other:pass")
	if groups := c.json("", "credential", "ls").([]any); len(groups) != 1 || groups[0].(map[string]any)["name"] != "other" {
		t.Fatalf("moving the last member left an empty credential: %v", groups)
	}
	c.put("destination:username", "someone", "--type", "plain")
	c.put("taken", "occupied")
	for _, args := range [][]string{
		{"rename", id, "taken"},
		{"credential", "rename", "other", "destination"},
		{"credential", "view", "missing"},
		{"credential", "rename", "missing", "new"},
		{"credential", "delete", "missing"},
	} {
		if code, out, errText := c.call("", args...); code != 1 || out != "" || errText == "" {
			t.Fatalf("%v: code=%d out=%q err=%q", args, code, out, errText)
		}
	}
	if c.id("other:pass") != id || c.id("destination:username") == "" {
		t.Fatal("failed rename changed a field")
	}
	if r := c.record("rename", id, "password"); r["name"] != "password" || r["id"] != id {
		t.Fatalf("move out of credential: %v", r)
	}
	if groups := c.json("", "credential", "ls").([]any); len(groups) != 1 || groups[0].(map[string]any)["name"] != "destination" {
		t.Fatalf("credential did not disappear: %v", groups)
	}
}

func TestCredentialHelpAndInvalidNames(t *testing.T) {
	for _, path := range [][]string{{"rename"}, {"credential"}, {"credential", "ls"}, {"credential", "view"}, {"credential", "rename"}, {"credential", "delete"}} {
		code, out, errText := run("", append([]string{"help"}, path...)...)
		flagCode, flagOut, flagErr := run("", append(append([]string(nil), path...), "--help")...)
		if code != 0 || flagCode != 0 || out != flagOut || errText != "" || flagErr != "" {
			t.Fatalf("help %v: code=%d/%d out=%q/%q err=%q/%q", path, code, flagCode, out, flagOut, errText, flagErr)
		}
	}
	for _, args := range [][]string{
		{"list"}, {"credential", "list"},
		{"rename", "one"}, {"rename", "one", ":field"},
		{"rename", "one", "group:"}, {"rename", "one", "group:nested:field"},
		{"rename", "one", "ags_0123456789abcdef"},
		{"credential", "view", "group:field"},
		{"credential", "rename", "old", "new:nested"},
		{"credential", "delete", "group:field"},
	} {
		if code, out, errText := run("", args...); code != 2 || out != "" || errText == "" {
			t.Fatalf("%v: code=%d out=%q err=%q", args, code, out, errText)
		}
	}
}

func TestLSGroupsAndSortsFields(t *testing.T) {
	c := newTestCLI(t)
	for _, name := range []string{"b:alpha", "z-root", "a:zulu", "a-:alpha", "a-root", "a:alpha"} {
		c.put(name, "value-"+name, "--type", "plain")
	}
	rows := c.json("", "ls").([]any)
	want := []string{"a-root", "z-root", "a:alpha", "a:zulu", "a-:alpha", "b:alpha"}
	if len(rows) != len(want) {
		t.Fatalf("ls rows: %v", rows)
	}
	for i, name := range want {
		if row := rows[i].(map[string]any); row["name"] != name || row["value"] != "value-"+name {
			t.Fatalf("ls row %d: %v, want %s", i, row, name)
		}
	}
	text, _ := c.ok("", "ls")
	var display []string
	for _, line := range strings.Split(strings.TrimSpace(text), "\n")[1:] {
		name := strings.Fields(line)[0]
		if strings.HasPrefix(line, "  ") {
			name = "  " + name
		}
		display = append(display, name)
	}
	wantDisplay := []string{"a-root", "z-root", "a:", "  alpha", "  zulu", "a-:", "  alpha", "b:", "  alpha"}
	if !slices.Equal(display, wantDisplay) {
		t.Fatalf("group display: %q, want %q", display, wantDisplay)
	}
	groups := c.json("", "credential", "ls").([]any)
	if len(groups) != 3 {
		t.Fatalf("credential summaries: %v", groups)
	}
	for i, name := range []string{"a", "a-", "b"} {
		if groups[i].(map[string]any)["name"] != name {
			t.Fatalf("credential order: %v", groups)
		}
	}
}

func TestPositionalValuesWarnOnlyForSensitiveTypes(t *testing.T) {
	c := newTestCLI(t)
	for _, tc := range []struct {
		kind, value string
	}{
		{"password", "positional-synthetic-password"},
		{"totp", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"},
		{"plain", "public-user"},
	} {
		out, errText := c.ok("", "put", tc.kind, tc.value, "--type", tc.kind)
		if tc.kind == "plain" {
			if errText != "" || c.record("view", tc.kind)["value"] != tc.value {
				t.Fatalf("plain positional put: out=%q err=%q", out, errText)
			}
		} else if !strings.Contains(errText, "shell history") || strings.Contains(out+errText, tc.value) {
			t.Fatalf("%s positional warning: out=%q err=%q", tc.kind, out, errText)
		}
	}
	if _, errText := c.ok("", "put", "plain", "updated-public-user"); errText != "" {
		t.Fatalf("existing plain value warned without --type: %q", errText)
	}
	if _, errText := c.ok("", "put", "password", "updated-synthetic-password"); !strings.Contains(errText, "shell history") || strings.Contains(errText, "updated-synthetic-password") {
		t.Fatalf("existing password lacked a safe warning: %q", errText)
	}
	if code, out, errText := c.call("stdin-value", "put", "plain", "positional-value", "--stdin"); code != 2 || out != "" || !strings.Contains(errText, "either VALUE or --stdin") {
		t.Fatalf("ambiguous value source: code=%d out=%q err=%q", code, out, errText)
	}
}

func TestPlainUseAndProtectionRejection(t *testing.T) {
	c := newTestCLI(t)
	const value = "visible-user"
	id := c.put("account:user", value, "--type", "plain")["id"].(string)
	for _, ref := range []string{"account:user", id} {
		if out, errText := c.ok("", "get", ref); out != value+"\n" || errText != "" {
			t.Fatalf("plain get: out=%q err=%q", out, errText)
		}
	}
	t.Setenv("AGSECRET_EXEC_HELPER", "1")
	t.Setenv("AGSECRET_EXEC_VALUE", id)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	out, errText := c.ok("", "exec", "--", executable, "-test.run=^TestExecHelperProcess$", "--", "both", id)
	if out != value+"|"+value+"\n" || errText != "other-secret" {
		t.Fatalf("plain exec filtered output: out=%q err=%q", out, errText)
	}
	o := &options{db: c.db, passFile: c.pass}
	var used int64
	if err := o.withStore(func(s *store.Store) error {
		r, err := s.Get(id, false)
		used = r.UsedCount
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if used != 0 {
		t.Fatalf("plain get/exec consumed %d uses", used)
	}
	for _, flags := range [][]string{{"--ttl", "0"}, {"--uses", "0"}, {"--access", "get,exec"}, {"--dangerously-skip-check=true"}, {"--dangerously-skip-check=false"}} {
		args := append([]string{"put", "account:user", value}, flags...)
		if code, out, errText := c.call("", args...); code != 1 || out != "" || !strings.Contains(errText, "plain values do not support") {
			t.Fatalf("plain protection %v: code=%d out=%q err=%q", flags, code, out, errText)
		}
	}
	r := c.record("view", id)
	for _, key := range []string{"access", "expires_at", "expired", "max_uses", "used_count", "leaks"} {
		if _, exists := r[key]; exists {
			t.Fatalf("plain metadata has ineffective protection %s: %v", key, r)
		}
	}
}
