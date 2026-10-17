package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type testCLI struct {
	t        *testing.T
	db, pass string
}

func newTestCLI(t *testing.T) testCLI {
	t.Helper()
	dir := t.TempDir()
	c := testCLI{t: t, db: filepath.Join(dir, "secrets.db"), pass: filepath.Join(dir, "pass")}
	if err := os.WriteFile(c.pass, []byte("test-passphrase\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c.ok("", "init")
	return c
}

func (c testCLI) call(input string, args ...string) (int, string, string) {
	c.t.Helper()
	var out, errOut bytes.Buffer
	all := append([]string{"--db", c.db, "--pass-file", c.pass}, args...)
	code := Execute(all, strings.NewReader(input), &out, &errOut)
	return code, out.String(), errOut.String()
}

func (c testCLI) ok(input string, args ...string) (string, string) {
	c.t.Helper()
	code, out, errOut := c.call(input, args...)
	if code != 0 {
		c.t.Fatalf("%v: code=%d out=%q err=%s", args, code, out, errOut)
	}
	return out, errOut
}

func (c testCLI) record(args ...string) map[string]any {
	c.t.Helper()
	return c.recordWithInput("", args...)
}

func (c testCLI) recordWithInput(input string, args ...string) map[string]any {
	c.t.Helper()
	out, _ := c.ok(input, append(args, "--json")...)
	var record map[string]any
	if err := json.Unmarshal([]byte(out), &record); err != nil {
		c.t.Fatalf("invalid JSON %q: %v", out, err)
	}
	return record
}

// put stores secret through stdin, which removes one final newline.
func (c testCLI) put(name, secret string, flags ...string) map[string]any {
	c.t.Helper()
	return c.recordWithInput(secret, append([]string{"put", name, "--secret-stdin"}, flags...)...)
}

func TestHelpEntrypoints(t *testing.T) {
	call := func(args ...string) (int, string, string) {
		var out, errOut bytes.Buffer
		code := Execute(args, strings.NewReader(""), &out, &errOut)
		return code, out.String(), errOut.String()
	}
	for _, command := range []string{"", "init", "put", "view", "get", "send", "exec", "report", "list", "ls", "delete", "rm", "doctor", "version"} {
		helpArgs, flagArgs := []string{"help"}, []string{"--help"}
		if command != "" {
			helpArgs = append(helpArgs, command)
			flagArgs = []string{command, "--help"}
		}
		code, out, errOut := call(helpArgs...)
		flagCode, flagOut, flagErr := call(flagArgs...)
		if code != 0 || flagCode != 0 || errOut != "" || flagErr != "" || out != flagOut || !strings.Contains(out, "--help") {
			t.Fatalf("help mismatch for %q: code=%d/%d out=%q/%q err=%q/%q", command, code, flagCode, out, flagOut, errOut, flagErr)
		}
	}
	if _, out, _ := call(); !strings.Contains(out, "agsecret exec -- curl") || !strings.Contains(out, "ask the user") {
		t.Fatalf("root help lacks the workflow guide: %q", out)
	}
	if code, out, _ := call("--version"); code != 0 || out != "agsecret dev\n" {
		t.Fatalf("version: code=%d out=%q", code, out)
	}
	if code, out, errOut := call("lst"); code != 2 || out != "" || !strings.Contains(errOut, "list") || strings.Count(errOut, "\n") != 1 {
		t.Fatalf("unknown command: code=%d out=%q err=%q", code, out, errOut)
	}
	for _, args := range [][]string{{"--agent"}, {"view"}, {"list", "extra"}, {"put", "a", "b"}, {"put", "a", "--secret-stdin", "--secret-file", "f"}, {"get", "a", "--json"}, {"send", "screen:0", "a"}} {
		if code, out, errOut := call(args...); code != 2 || out != "" || errOut == "" {
			t.Fatalf("usage error %v: code=%d out=%q err=%q", args, code, out, errOut)
		}
	}
}

func TestWorkflowAndOutputProtection(t *testing.T) {
	c := newTestCLI(t)
	stored := c.put("api", "secret-value\n")
	id, ok := stored["id"].(string)
	if !ok || len(id) != 20 || !strings.HasPrefix(id, "ags_") {
		t.Fatalf("invalid ID: %v", stored)
	}
	if stored["allow_get"] != true || stored["allow_exec"] != true {
		t.Fatalf("default policy: %v", stored)
	}
	view := c.record("view", id)
	if view["value"] != "[set]" || view["name"] != "api" {
		t.Fatalf("view: %v", view)
	}
	if _, ok := view["secret"]; ok {
		t.Fatal("view exposes secret")
	}
	if code, out, errText := c.call("", "get", id); code != 1 || out != "" || !strings.Contains(errText, "not printing password api") {
		t.Fatalf("get safety: code=%d out=%q err=%s", code, out, errText)
	}
	if out, errText := c.ok("", "get", id, "--dangerously-skip-check"); out != "secret-value\n" || errText != "" {
		t.Fatalf("get: out=%q err=%q", out, errText)
	}
	if code, _, errText := c.call("", "put", "api"); code != 2 || !strings.Contains(errText, "--secret-stdin") {
		t.Fatalf("put without a secret source: code=%d err=%q", code, errText)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGSECRET_CLI_OUTPUT_HELPER", "1")
	if out, errText := c.ok("", "exec", "--", executable, "-test.run=^TestCLIOutputHelper$", "--", id); out != "[REDACTED:"+id+"]\n" || !strings.Contains(errText, "hid the values of "+id+" in the output above; nothing leaked") {
		t.Fatalf("exec: out=%q err=%q", out, errText)
	}
	c.ok("", "report", id, "--reason", "unexpected output", "--context", "terminal log", "--attachment", "screen.png", "--attachment", "debug.log")
	if code, _, _ := c.call("", "report", "api"); code != 2 {
		t.Fatal("report accepted a name")
	}
	c.ok("", "report", id)
	leaked := c.record("view", "api")
	if _, ok := leaked["status"]; ok || leaked["allow_get"] != true || leaked["allow_exec"] != true {
		t.Fatalf("leaked record: %v", leaked)
	}
	leaks := leaked["leaks"].([]any)
	first := leaks[0].(map[string]any)
	if len(leaks) != 2 || first["reason"] != "unexpected output" || first["context"] != "terminal log" || len(first["attachments"].([]any)) != 2 {
		t.Fatalf("leak details: %v", leaks)
	}
	if _, err := time.Parse(time.RFC3339, first["reported_at"].(string)); err != nil {
		t.Fatal(err)
	}
	if text, _ := c.ok("", "list"); !strings.Contains(text, "leaked (2)") || !strings.Contains(text, "get,exec") {
		t.Fatalf("list text: %q", text)
	}
	if doctor := c.record("doctor"); len(doctor["leaked"].([]any)) != 1 {
		t.Fatalf("doctor: %v", doctor)
	}
	rotated := c.put(id, "new-secret-value")
	newID, ok := rotated["id"].(string)
	if !ok || newID == id || rotated["name"] != "api" || len(rotated["leaks"].([]any)) != 0 || rotated["allow_get"] != true || rotated["allow_exec"] != true {
		t.Fatalf("rotation: %v", rotated)
	}
	if code, _, errText := c.call("", "report", id); code != 1 || !strings.Contains(errText, "needs no report") {
		t.Fatalf("stale report: code=%d err=%q", code, errText)
	}
	c.put("api", "next-secret-value", "--allow-get=false")
	if code, _, errText := c.call("", "get", "api"); code != 1 || !strings.Contains(errText, "get is disabled for api") || !strings.Contains(errText, "only its owner can enable it") {
		t.Fatalf("disabled get: code=%d err=%q", code, errText)
	}
	deleted := c.record("rm", "api")
	if deleted["name"] != "api" {
		t.Fatalf("delete: %v", deleted)
	}
	if code, _, errText := c.call("", "view", "api"); code != 1 || !strings.Contains(errText, "secret api not found; run agsecret list") {
		t.Fatalf("deleted credential: code=%d err=%q", code, errText)
	}
	if code, _, errText := c.call("", "view", "ags_123"); code != 1 || !strings.Contains(errText, "not a valid ID") {
		t.Fatalf("malformed ID: code=%d err=%q", code, errText)
	}
}

func TestTOTPPutViewGetAndPreservedPolicies(t *testing.T) {
	c := newTestCLI(t)
	seed := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	// A revealing mask must not apply to a TOTP seed.
	c.put("otp", seed, "--type", "totp", "--mask", "prefix:4", "--ttl", "1h", "--allow-exec=false")
	out, errOut := c.ok("", "get", "otp")
	if code := strings.TrimSpace(out); len(code) != 6 || strings.Trim(code, "0123456789") != "" || errOut != "" {
		t.Fatalf("TOTP get: %q %q", out, errOut)
	}
	previous := c.record("view", "otp")
	if previous["value"] != "[set]" {
		t.Fatalf("TOTP view exposed part of the seed: %v", previous)
	}
	if text, _ := c.ok("", "view", "otp"); strings.Contains(text, seed[:4]) {
		t.Fatalf("TOTP text view exposed part of the seed: %q", text)
	}
	updated := c.put("otp", seed)
	for _, key := range []string{"id", "type", "mask", "expires_at", "allow_exec"} {
		if previous[key] != updated[key] {
			t.Fatalf("omitted %s changed: %v -> %v", key, previous[key], updated[key])
		}
	}
	if code, _, _ := c.call("not-a-seed!", "put", "invalid", "--secret-stdin", "--type", "totp"); code == 0 {
		t.Fatal("invalid TOTP seed accepted")
	}
	if code, _, _ := c.call("123456", "put", "invalid", "--secret-stdin", "--type", "otp"); code == 0 {
		t.Fatal("old otp type accepted")
	}
}

func TestReportSecretAndInit(t *testing.T) {
	c := newTestCLI(t)
	first := c.put("first", "same-secret")
	_, warning := c.ok("same-secret", "put", "second", "--secret-stdin")
	if !strings.Contains(warning, first["id"].(string)) || strings.Contains(warning, "same-secret") {
		t.Fatalf("duplicate warning: %q", warning)
	}
	out, _ := c.ok("same-secret", "report", "--secret-stdin", "--json", "--reason", "shared password")
	var reported []map[string]any
	if err := json.Unmarshal([]byte(out), &reported); err != nil {
		t.Fatal(err)
	}
	if len(reported) != 2 {
		t.Fatalf("matched %d records", len(reported))
	}
	if code, _, _ := c.call("unmatched", "report", "--secret-stdin"); code == 0 {
		t.Fatal("unmatched secret report succeeded")
	}
	if out, errText := c.ok("", "init"); !strings.Contains(out, c.db) || errText != "" {
		t.Fatalf("repeated init: out=%q err=%q", out, errText)
	}
	missing := filepath.Join(t.TempDir(), "missing.db")
	if code, _, errText := c.call("", "--db", missing, "list"); code != 1 || !strings.Contains(errText, "no vault at "+missing+"; run agsecret init") {
		t.Fatalf("missing vault: code=%d err=%q", code, errText)
	}
}

func TestTmuxTargetsAndTTL(t *testing.T) {
	c := newTestCLI(t)
	for _, target := range []string{"0", "screen:0", "tmux:", "tmux:0\n"} {
		if code, _, errText := c.call("", "send", target, "missing"); code != 2 || !strings.Contains(errText, "needs a tmux pane") {
			t.Fatalf("accepted target %q: code=%d err=%q", target, code, errText)
		}
	}
	for _, value := range []string{"0", "15m", "2h", "7d", "1.5w"} {
		if _, err := parseTTL(value); err != nil {
			t.Fatalf("ttl %q: %v", value, err)
		}
	}
	for _, value := range []string{"-1h", "1foow", "1xw", "99999999999999999d", "1h2d", "1m2w", "1h30m2d"} {
		if _, err := parseTTL(value); err == nil {
			t.Fatalf("accepted ttl %q", value)
		}
	}
}

func TestCLIOutputHelper(t *testing.T) {
	if os.Getenv("AGSECRET_CLI_OUTPUT_HELPER") != "1" {
		return
	}
	value := os.Args[len(os.Args)-1]
	if override := os.Getenv("AGSECRET_CLI_OUTPUT_VALUE"); override != "" {
		value = override
	}
	fmt.Fprintln(os.Stdout, value)
	os.Exit(0)
}

func TestExecNoteIsRedactedAndExitCodes(t *testing.T) {
	c := newTestCLI(t)
	// "nothing" also occurs in the redaction note itself.
	id := c.put("details", "nothing")["id"].(string)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGSECRET_CLI_OUTPUT_HELPER", "1")
	t.Setenv("AGSECRET_CLI_OUTPUT_VALUE", "nothing")
	code, out, errText := c.call("", "exec", "--", executable, "-test.run=^TestCLIOutputHelper$", "--", id)
	if code != 0 || out != "[REDACTED:"+id+"]\n" || strings.Contains(errText, "nothing") {
		t.Fatalf("note leaked a credential: code=%d out=%q err=%q", code, out, errText)
	}
	for _, tc := range []struct {
		args []string
		code int
		text string
	}{
		{[]string{"exec", "--", filepath.Join(t.TempDir(), "missing")}, 127, "cannot run"},
		{[]string{"exec", "--", t.TempDir()}, 126, "cannot run"},
		{[]string{"exec", "--", "echo", "ags_0123456789abcdef"}, 125, "secret ags_0123456789abcdef not found"},
		{[]string{"exec", "--", "echo", "ags_0123456789abcde"}, 125, "not a valid ID"},
		{[]string{"exec", "--", "sh", "-c", "echo " + id}, 125, "environment variable"},
		{[]string{"exec", "--", id}, 125, "command name cannot contain"},
		{[]string{"exec", "--json", "--", "echo"}, 2, "no JSON output"},
	} {
		code, out, errText := c.call("", tc.args...)
		if code != tc.code || out != "" || !strings.Contains(errText, tc.text) {
			t.Fatalf("%v: code=%d out=%q err=%q", tc.args, code, out, errText)
		}
	}
}

func TestMetadataEscapesTerminalControls(t *testing.T) {
	c := newTestCLI(t)
	mask := "fixed:\x1b]52;c;c2VjcmV0\a\t\u202evalue"
	id := c.put("display", "secret-value", "--mask", mask)["id"].(string)
	c.ok("", "report", id, "--reason", "reason\x1b[2J", "--context", "context\b\u009b2J", "--attachment", "log\x1b]0;title\a")
	out, _ := c.ok("", "view", "display")
	if strings.ContainsAny(out, "\x1b\a\r\b\u009b\u202e") || !strings.Contains(out, `\x1b`) {
		t.Fatalf("terminal control in view output: %q", out)
	}
	value := c.record("view", "display")["value"]
	if value != strings.TrimPrefix(mask, "fixed:") {
		t.Fatalf("JSON changed the value: %q", value)
	}
	for input, want := range map[string]string{
		"ordinary \u4e2d\u6587": "ordinary \u4e2d\u6587",
		"\x00\r\n\t\b\x1b\x7f":  `\0\r\n\t\b\x1b\x7f`,
		"\u009b\u202e\u2028":    `\u009b\u202e\u2028`,
	} {
		if got := safeText(input); got != want {
			t.Fatalf("safeText(%q)=%q, want %q", input, got, want)
		}
	}
}
