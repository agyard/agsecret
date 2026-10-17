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

	"github.com/agyard/agsecret/internal/store"
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
	code := Execute(c.t.Context(), all, strings.NewReader(input), &out, &errOut)
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
	args = append(args, "--json")
	out, _ := c.ok("", args...)
	var record map[string]any
	if err := json.Unmarshal([]byte(out), &record); err != nil {
		c.t.Fatalf("invalid JSON %q: %v", out, err)
	}
	return record
}

func TestHelpEntrypoints(t *testing.T) {
	call := func(args ...string) (int, string, string) {
		var out, errOut bytes.Buffer
		code := Execute(t.Context(), args, strings.NewReader(""), &out, &errOut)
		return code, out.String(), errOut.String()
	}

	for _, command := range []string{"", "init", "put", "view", "get", "send", "exec", "report", "list", "ls", "delete", "rm", "doctor", "version", "help"} {
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
	if code, out, errOut := call("help", "--agent"); code != 0 || errOut != "" ||
		!strings.Contains(out, "Agent workflow") || strings.Contains(out, "Available Commands:") {
		t.Fatalf("agent help: code=%d out=%q err=%q", code, out, errOut)
	}
	for _, args := range [][]string{{"--agent"}, {"view", "--agent"}, {"help", "agent"}, {"help", "missing-command"}} {
		if code, out, errOut := call(args...); code == 0 || out != "" || errOut == "" {
			t.Fatalf("invalid help %v: code=%d out=%q err=%q", args, code, out, errOut)
		}
	}
	if code, out, errOut := call("help", "--agent", "view"); code != 2 || out != "" ||
		!strings.Contains(errOut, "--agent cannot be combined with COMMAND") {
		t.Fatalf("agent help with command: code=%d out=%q err=%q", code, out, errOut)
	}
}

func TestWorkflowAndOutputProtection(t *testing.T) {
	c := newTestCLI(t)
	stored := c.record("put", "api", "secret-value")
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
		t.Fatal("default view exposes secret")
	}
	if got := c.record("view", "api", "--dangerously-show-secret")["secret"]; got != "secret-value" {
		t.Fatalf("secret: %v", got)
	}
	if code, out, errText := c.call("", "get", id); code != 2 || out != "" || !strings.Contains(errText, "refused to print secret directly to captured stdout") {
		t.Fatalf("get safety: code=%d out=%q err=%s", code, out, errText)
	}
	if out, errText := c.ok("", "get", id, "--dangerously-skip-check"); out != "secret-value\n" || errText != "" {
		t.Fatalf("get: out=%q err=%q", out, errText)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGSECRET_CLI_OUTPUT_HELPER", "1")
	if out, errText := c.ok("", "exec", "--", executable, "-test.run=^TestCLIOutputHelper$", "--", id); out != "[REDACTED:"+id+"]\n" || !strings.Contains(errText, "redacted secret output") {
		t.Fatalf("exec: out=%q err=%q", out, errText)
	}
	c.ok("", "report", id, "--reason", "unexpected output", "--context", "terminal log", "--attachment", "screen.png", "--attachment", "debug.log")
	c.ok("", "report", "api")
	leaked := c.record("view", "api")
	if leaked["status"] != "leaked (2 times)" || leaked["allow_get"] != true || leaked["allow_exec"] != true {
		t.Fatalf("leaked record: %v", leaked)
	}
	leaks := leaked["leaks"].([]any)
	first := leaks[0].(map[string]any)
	if first["reason"] != "unexpected output" || first["context"] != "terminal log" || len(first["attachments"].([]any)) != 2 {
		t.Fatalf("leak details: %v", first)
	}
	if _, err := time.Parse(time.RFC3339Nano, first["reported_at"].(string)); err != nil {
		t.Fatal(err)
	}
	doctor := c.record("doctor")
	if doctor["leaked_credentials"] != float64(1) {
		t.Fatalf("doctor: %v", doctor)
	}
	rotated := c.record("put", id, "new-secret-value")
	newID, ok := rotated["id"].(string)
	if !ok || newID == id || rotated["name"] != "api" || rotated["status"] != "active" || len(rotated["leaks"].([]any)) != 0 || rotated["allow_get"] != true || rotated["allow_exec"] != true {
		t.Fatalf("rotation: %v", rotated)
	}
	c.ok("", "put", "api", "next-secret-value", "--allow-get", "--allow-exec")
	latest := c.record("view", "api")["id"].(string)
	if out, _ := c.ok("", "get", latest, "--dangerously-skip-check"); out != "next-secret-value\n" {
		t.Fatalf("rotation value: %q", out)
	}
	c.ok("", "rm", latest)
	if code, _, _ := c.call("", "view", "api"); code == 0 {
		t.Fatal("deleted credential still available")
	}
	for _, removed := range []string{"tokenize", "redact"} {
		if code, _, _ := c.call("", removed, "api"); code == 0 {
			t.Fatalf("removed command %q still available", removed)
		}
	}
}

func TestTOTPPutViewGetAndPreservedPolicies(t *testing.T) {
	c := newTestCLI(t)
	seed := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	c.ok("", "put", "otp", seed, "--type", "totp", "--mask", "fixed:configured", "--ttl", "1h", "--allow-exec=false")
	value, errOut := c.ok("", "get", "otp")
	if len(strings.TrimSpace(value)) != 6 || errOut != "" {
		t.Fatalf("TOTP get: %q %q", value, errOut)
	}
	view := c.record("view", "otp", "--dangerously-show-secret")
	if _, exists := view["secret"]; exists || len(view["current_otp"].(string)) != 6 {
		t.Fatalf("TOTP view: %v", view)
	}
	previous := c.record("view", "otp")
	updated := c.record("put", "otp", seed)
	for _, key := range []string{"id", "type", "mask", "expires_at", "allow_exec"} {
		if previous[key] != updated[key] {
			t.Fatalf("omitted %s changed: %v -> %v", key, previous[key], updated[key])
		}
	}
	if code, _, _ := c.call("", "put", "invalid", "not-a-seed!", "--type", "totp"); code == 0 {
		t.Fatal("invalid TOTP seed accepted")
	}
	if code, _, _ := c.call("", "put", "invalid", "123456", "--type", "otp"); code == 0 {
		t.Fatal("old otp type accepted")
	}
}

func TestReportSecretAndLecture(t *testing.T) {
	c := newTestCLI(t)
	first := c.record("put", "first", "same-secret")
	_, warning := c.ok("", "put", "second", "same-secret")
	if !strings.Contains(warning, first["id"].(string)) {
		t.Fatalf("shared passphrase warning missing first ID: %q", warning)
	}
	out, _ := c.ok("same-secret", "report", "--secret-stdin", "--json", "--reason", "shared password")
	var reported []map[string]any
	if err := json.Unmarshal([]byte(out), &reported); err != nil {
		t.Fatal(err)
	}
	if len(reported) != 2 {
		t.Fatalf("matched %d records", len(reported))
	}
	if _, errText := c.ok("", "list"); !strings.Contains(errText, "agsecret help --agent") {
		t.Fatalf("first lecture missing: %q", errText)
	}
	if _, errText := c.ok("", "view", "first"); errText != "" {
		t.Fatalf("lecture repeated: %q", errText)
	}
	s, err := store.Open(c.db, []byte("test-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetMeta("lecture_shown_at", time.Now().UTC().Add(-13*time.Hour).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, errText := c.ok("", "doctor"); !strings.Contains(errText, "agsecret help --agent") {
		t.Fatalf("expired lecture missing: %q", errText)
	}
	if code, _, _ := c.call("unmatched", "report", "--secret-stdin"); code == 0 {
		t.Fatal("unmatched secret report succeeded")
	}
}

func TestTmuxTargetsAndTTL(t *testing.T) {
	for _, value := range []string{"tmux:0", "tmux:dev:0.1", "tmux:%1"} {
		got, err := parseTmuxTarget(value)
		if err != nil || got != strings.TrimPrefix(value, "tmux:") {
			t.Fatalf("%q: %q %v", value, got, err)
		}
	}
	for _, value := range []string{"", "0", "screen:0", "tmux:", "tmux:0\n"} {
		if _, err := parseTmuxTarget(value); err == nil {
			t.Fatalf("accepted %q", value)
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

func TestExecWrapperDiagnosticsAreRedacted(t *testing.T) {
	c := newTestCLI(t)
	stored := c.record("put", "details", "details")
	id := stored["id"].(string)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGSECRET_CLI_OUTPUT_HELPER", "1")
	t.Setenv("AGSECRET_CLI_OUTPUT_VALUE", "details")
	code, out, errText := c.call("", "exec", "--", executable, "-test.run=^TestCLIOutputHelper$", "--", id)
	if code != 0 || out != "[REDACTED:"+id+"]\n" || strings.Contains(errText, "details") {
		t.Fatalf("footer leaked diagnostic value: code=%d out=%q err=%q", code, out, errText)
	}
	code, out, errText = c.call("", "exec", "--", "/missing/details/helper", id)
	if code == 0 || out != "" || strings.Contains(errText, "details") {
		t.Fatalf("start diagnostic leaked executable value: code=%d out=%q err=%q", code, out, errText)
	}
	if !strings.Contains(errText, "[REDACTED:"+id+"]") {
		t.Fatalf("sanitized diagnostic marker missing: %q", errText)
	}
}

func TestMetadataEscapesTerminalControls(t *testing.T) {
	c := newTestCLI(t)
	mask := "fixed:\x1b]52;c;c2VjcmV0\a\t\u202evalue"
	c.ok("", "put", "display", "secret-value", "--mask", mask)
	c.ok("", "report", "display", "--reason", "reason\x1b[2J", "--context", "context\b\u009b2J", "--attachment", "log\x1b]0;title\a")
	for _, command := range [][]string{{"view", "display"}, {"list"}} {
		out, _ := c.ok("", command...)
		if strings.ContainsAny(out, "\x1b\a\r\b\u009b\u202e") {
			t.Fatalf("terminal control in %v output: %q", command, out)
		}
		if !strings.Contains(out, `\x1b`) {
			t.Fatalf("escaped value missing from %v: %q", command, out)
		}
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
