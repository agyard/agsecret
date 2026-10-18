package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

func run(input string, args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := Execute(args, strings.NewReader(input), &out, &errOut)
	return code, out.String(), errOut.String()
}

func (c testCLI) call(input string, args ...string) (int, string, string) {
	c.t.Helper()
	return run(input, append([]string{"--db", c.db, "--pass-file", c.pass}, args...)...)
}

func (c testCLI) ok(input string, args ...string) (string, string) {
	c.t.Helper()
	code, out, errOut := c.call(input, args...)
	if code != 0 {
		c.t.Fatalf("%v: code=%d out=%q err=%s", args, code, out, errOut)
	}
	return out, errOut
}

func (c testCLI) json(input string, args ...string) any {
	c.t.Helper()
	out, _ := c.ok(input, append(args, "--json")...)
	var v any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		c.t.Fatalf("invalid JSON %q: %v", out, err)
	}
	return v
}

func (c testCLI) record(args ...string) map[string]any {
	c.t.Helper()
	return c.json("", args...).(map[string]any)
}

// put stores value through stdin, which drops one final newline.
func (c testCLI) put(name, value string, flags ...string) map[string]any {
	c.t.Helper()
	return c.json(value, append([]string{"put", name, "--stdin"}, flags...)...).(map[string]any)
}

func (c testCLI) id(name string) string {
	c.t.Helper()
	return c.record("view", name)["id"].(string)
}

func TestHelpAndUsageErrors(t *testing.T) {
	for _, command := range []string{"", "init", "put", "list", "view", "get", "exec", "send", "report", "delete"} {
		helpArgs, flagArgs := []string{"help"}, []string{"--help"}
		if command != "" {
			helpArgs, flagArgs = []string{"help", command}, []string{command, "--help"}
		}
		code, out, errOut := run("", helpArgs...)
		flagCode, flagOut, _ := run("", flagArgs...)
		if code != 0 || flagCode != 0 || errOut != "" || out != flagOut || !strings.Contains(out, "Usage:") {
			t.Fatalf("help for %q: code=%d/%d out=%q/%q err=%q", command, code, flagCode, out, flagOut, errOut)
		}
	}
	if _, out, _ := run(""); !strings.Contains(out, "agsecret init") || !strings.Contains(out, "ask the user") {
		t.Fatalf("root help lacks the guide: %q", out)
	}
	if code, out, _ := run("", "--version"); code != 0 || out != "agsecret dev\n" {
		t.Fatalf("version: code=%d out=%q", code, out)
	}
	for args, want := range map[string]string{
		"lst":                            `unknown command "lst"; did you mean "list"?`,
		"show x":                         `did you mean "view"?`,
		"run echo":                       `did you mean "exec"?`,
		"help nonsense":                  `no help for "nonsense"`,
		"view":                           "usage: agsecret view NAME|ID",
		"list extra":                     "usage: agsecret list",
		"exec":                           "usage: agsecret exec -- COMMAND [ARG...]",
		"get x --json":                   "unknown flag: --json",
		"send tmux:0 x --no-enter false": "write boolean flags as --flag=false",
		"send screen:0 x":                "send needs a tmux pane",
		"put x --ttl 1y":                 `invalid --ttl "1y"`,
		"put x --access all":             `invalid --access "all"`,
		"report name":                    "report takes the exposed ID, not a name",
	} {
		code, out, errOut := run("", strings.Fields(args)...)
		if code != 2 || out != "" || !strings.Contains(errOut, want) || strings.Count(errOut, "\n") != 1 {
			t.Fatalf("%s: code=%d out=%q err=%q", args, code, out, errOut)
		}
	}
}

func TestWorkflow(t *testing.T) {
	c := newTestCLI(t)
	stored := c.put("api", "secret-value\n")
	id := stored["id"].(string)
	if len(id) != 20 || stored["access"] != "get,exec" || stored["type"] != "password" {
		t.Fatalf("put: %v", stored)
	}
	if view := c.record("view", id); view["name"] != "api" || view["value"] != nil {
		t.Fatalf("view: %v", view)
	}
	if code, out, errText := c.call("", "get", id); code != 2 || out != "" || !strings.Contains(errText, "get does not print passwords by default") {
		t.Fatalf("get: code=%d out=%q err=%s", code, out, errText)
	}
	if code, out, errText := c.call("replacement", "put", id, "--stdin"); code != 2 || out != "" || !strings.Contains(errText, "put takes a name, not an ID") {
		t.Fatalf("put by ID: code=%d out=%q err=%q", code, out, errText)
	}
	if out, errText := c.ok("", "get", id, "--dangerously-skip-check"); out != "secret-value\n" || errText != "" {
		t.Fatalf("revealed get: out=%q err=%q", out, errText)
	}
	if code, _, errText := c.call("", "put", "api"); code != 1 || !strings.Contains(errText, "--stdin") {
		t.Fatalf("put without a value: code=%d err=%q", code, errText)
	}

	// Narrowing needs no value and keeps the ID; loosening needs the value.
	if r := c.json("", "put", "api", "--access", "exec").(map[string]any); r["id"] != id || r["access"] != "exec" {
		t.Fatalf("option change: %v", r)
	}
	if code, _, errText := c.call("", "get", "api", "--dangerously-skip-check"); code != 1 || !strings.Contains(errText, "get is turned off for api") || strings.Contains(errText, "--access") {
		t.Fatalf("disabled get: code=%d err=%q", code, errText)
	}
	c.ok("", "put", "api", "--ttl", "1ns")
	if code, _, errText := c.call("", "exec", "--", "echo", id); code != 125 || !strings.Contains(errText, "has expired; renewing it is up to the user") {
		t.Fatalf("expired exec: code=%d err=%q", code, errText)
	}
	for _, args := range [][]string{{"--ttl", "0"}, {"--access", "get,exec"}} {
		if code, _, errText := c.call("", append([]string{"put", "api"}, args...)...); code != 1 || !strings.Contains(errText, "put needs the value of api to widen") {
			t.Fatalf("loosening %v without the value: code=%d err=%q", args, code, errText)
		}
	}
	c.ok("", "put", "api", "--ttl", "0", "--dangerously-skip-check")
	c.ok("secret-value", "put", "api", "--stdin", "--access", "get,exec")
	if r := c.record("view", "api"); r["id"] != id || r["access"] != "get,exec" || r["expires_at"] != nil {
		t.Fatalf("loosened with the value: %v", r)
	}

	if out, _ := c.ok("", "report", id, "--reason", "printed by a debug endpoint"); out != "Reported a leak of api ("+id+")\n" {
		t.Fatalf("report: %q", out)
	}
	if text, _ := c.ok("", "list"); !strings.Contains(text, "leaked (1)") || !strings.Contains(text, "get,exec") {
		t.Fatalf("list: %q", text)
	}
	if text, _ := c.ok("", "view", "api"); !strings.Contains(text, "Leaked:") || !strings.Contains(text, "printed by a debug endpoint") {
		t.Fatalf("view leaks: %q", text)
	}

	out, _ := c.ok("new-secret-value", "put", "api", "--stdin")
	newID := c.id("api")
	if newID == id || out != "Updated api; its new ID is "+newID+", and "+id+" no longer works\n" {
		t.Fatalf("replacement: %q", out)
	}
	if r := c.record("view", newID); len(r["leaks"].([]any)) != 0 || r["access"] != "get,exec" {
		t.Fatalf("replacement kept reports or lost options: %v", r)
	}
	for _, args := range [][]string{{"get", id}, {"view", id}, {"delete", id}, {"exec", "--", "echo", id}} {
		if code, _, errText := c.call("", args...); code == 0 || !strings.Contains(errText, "not found") {
			t.Fatalf("old ID accepted by %v: %q", args, errText)
		}
	}
	if code, _, errText := c.call("", "report", id); code != 1 || !strings.Contains(errText, "needs no report") {
		t.Fatalf("stale report: code=%d err=%q", code, errText)
	}

	if deleted := c.record("rm", "api"); deleted["name"] != "api" {
		t.Fatalf("delete: %v", deleted)
	}
	if code, _, errText := c.call("", "view", "api"); code != 1 || !strings.Contains(errText, "secret api not found; run agsecret list") {
		t.Fatalf("deleted secret: code=%d err=%q", code, errText)
	}
	if out, _ := c.ok("", "list"); !strings.HasPrefix(out, "No secrets yet") {
		t.Fatalf("empty list: %q", out)
	}
	if code, _, errText := c.call("", "view", "ags_123"); code != 1 || !strings.Contains(errText, "not a valid ID") {
		t.Fatalf("malformed ID: code=%d err=%q", code, errText)
	}
}

func TestPasswordGetRefusesFilesAndPipes(t *testing.T) {
	c := newTestCLI(t)
	id := c.put("private", "synthetic-output-value", "--uses", "1")["id"].(string)
	file, err := os.CreateTemp(t.TempDir(), "output")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	for _, output := range []*os.File{file, w} {
		var diagnostic bytes.Buffer
		code := Execute([]string{"--db", c.db, "--pass-file", c.pass, "get", id}, strings.NewReader(""), output, &diagnostic)
		if code != 2 || !strings.Contains(diagnostic.String(), "use agsecret exec or send") {
			t.Fatalf("password get: code=%d err=%q", code, diagnostic.String())
		}
	}
	if info, err := file.Stat(); err != nil || info.Size() != 0 {
		t.Fatalf("get wrote to a file: %v", err)
	}
	w.Close()
	if b, err := io.ReadAll(r); err != nil || len(b) != 0 {
		t.Fatalf("get wrote to a pipe: bytes=%d err=%v", len(b), err)
	}
	c.assertUsage(id, 1, 0)
}

func TestDuplicatesReportsAndTOTP(t *testing.T) {
	c := newTestCLI(t)
	first := c.put("first", "same-secret")["id"].(string)
	_, note := c.ok("same-secret", "put", "second", "--stdin", "--access", "none")
	if !strings.Contains(note, "also stored as first") || strings.Contains(note, "same-secret") {
		t.Fatalf("duplicate note: %q", note)
	}
	reported := c.json("", "report", first).([]any)
	if len(reported) != 2 {
		t.Fatalf("report reached %d secrets", len(reported))
	}
	for _, v := range reported {
		if r := v.(map[string]any); len(r["leaks"].([]any)) != 1 || r["name"] == "second" && r["access"] != "none" {
			t.Fatalf("report changed access or missed a copy: %v", r)
		}
	}

	seed := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	otp := c.put("otp", seed, "--type", "totp", "--ttl", "1h", "--access", "get")
	out, errOut := c.ok("", "get", "otp")
	if code := strings.TrimSpace(out); len(code) != 6 || strings.Trim(code, "0123456789") != "" || errOut != "" {
		t.Fatalf("TOTP get: %q %q", out, errOut)
	}
	if r := c.put("otp", seed); r["id"] != otp["id"] || r["expires_at"] != otp["expires_at"] || r["access"] != "get" || r["type"] != "totp" {
		t.Fatalf("same value changed options: %v -> %v", otp, r)
	}
	if code, out, errText := c.call("", "report", otp["id"].(string)); code == 0 || out != "" || strings.Contains(errText, seed) {
		t.Fatalf("TOTP report: code=%d err=%q", code, errText)
	}
	for _, args := range [][]string{{"--type", "totp"}, {"--type", "pass"}} {
		if code, _, _ := c.call("not-a-seed!", append([]string{"put", "bad", "--stdin"}, args...)...); code == 0 {
			t.Fatalf("accepted %v", args)
		}
	}
}

func TestVaultSetup(t *testing.T) {
	c := newTestCLI(t)
	if out, errText := c.ok("", "init"); !strings.Contains(out, "Vault already exists: "+c.db) || errText != "" {
		t.Fatalf("repeated init: out=%q err=%q", out, errText)
	}
	missing := filepath.Join(t.TempDir(), "missing.db")
	for _, args := range [][]string{{"list"}, {"put", "x"}} {
		if code, _, errText := c.call("value", append([]string{"--db", missing}, args...)...); code != 1 || !strings.Contains(errText, "no vault at "+missing+"; run agsecret init") {
			t.Fatalf("missing vault %v: code=%d err=%q", args, code, errText)
		}
	}
	if err := os.WriteFile(c.pass, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if code, _, errText := c.call("", "list"); code != 1 || !strings.Contains(errText, "pass file "+c.pass+": the value is empty") {
		t.Fatalf("empty pass file: code=%d err=%q", code, errText)
	}
}

func TestTTL(t *testing.T) {
	for _, value := range []string{"0", "15m", "2h", "7d", "1.5w"} {
		if _, err := parseTTL(value); err != nil {
			t.Fatalf("ttl %q: %v", value, err)
		}
	}
	for _, value := range []string{"", "-1h", "1foow", "1xw", "99999999999999999d", "1h2d", "1m2w", "1h30m2d", "never"} {
		if _, err := parseTTL(value); err == nil {
			t.Fatalf("accepted ttl %q", value)
		}
	}
}

func TestOversizedStdinIsRejected(t *testing.T) {
	c := newTestCLI(t)
	prefix := strings.Repeat("a", 1<<20)
	before := c.put("boundary", prefix)["id"]
	code, out, errOut := c.call(prefix+"\ntrailing-data", "put", "boundary", "--stdin")
	if code == 0 || out != "" || !strings.Contains(errOut, "larger than 1 MiB") || c.id("boundary") != before {
		t.Fatalf("oversized input: code=%d err=%q", code, errOut)
	}
}

func TestCLIOutputHelper(t *testing.T) {
	if os.Getenv("AGSECRET_CLI_OUTPUT_HELPER") != "1" {
		return
	}
	fmt.Fprintln(os.Stdout, os.Getenv("AGSECRET_CLI_OUTPUT_VALUE"))
	os.Exit(0)
}

func TestExecNoteIsRedactedAndExitCodes(t *testing.T) {
	c := newTestCLI(t)
	// "leak" also occurs in the redaction note itself.
	id := c.put("details", "leak")["id"].(string)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGSECRET_CLI_OUTPUT_HELPER", "1")
	t.Setenv("AGSECRET_CLI_OUTPUT_VALUE", "leak")
	code, out, errText := c.call("", "exec", "--", executable, "-test.run=^TestCLIOutputHelper$", id)
	if code != 0 || out != "[REDACTED:"+id+"]\n" || strings.Contains(errText, "leak") || !strings.Contains(errText, "redacted "+id) {
		t.Fatalf("note leaked a secret: code=%d out=%q err=%q", code, out, errText)
	}
	// IDs are ordinary argument substitutions, including for browser and CLI
	// tools that take several positional arguments.
	t.Setenv("AGSECRET_CLI_OUTPUT_VALUE", "fill e1 leak")
	code, out, errText = c.call("", "exec", "--", executable, "-test.run=^TestCLIOutputHelper$", "fill", "e1", id)
	if code != 0 || out != "fill e1 [REDACTED:"+id+"]\n" || strings.Contains(errText, "leak") {
		t.Fatalf("multi-argument ID expansion: code=%d out=%q err=%q", code, out, errText)
	}
	if _, errText := c.ok("", "exec", "--", "true"); !strings.Contains(errText, "no secret IDs found") {
		t.Fatalf("no-ID note: %q", errText)
	}
	for _, tc := range []struct {
		args []string
		code int
		text string
	}{
		{[]string{"exec", "--", filepath.Join(t.TempDir(), "missing")}, 127, "command not found"},
		{[]string{"exec", "--", "curl -s x"}, 127, "separate words"},
		{[]string{"exec", "--", t.TempDir()}, 126, "cannot run"},
		{[]string{"exec", "--", "echo", id + "0"}, 125, "not a valid ID"},
		{[]string{"exec", "--", "echo", strings.ToUpper(id)}, 125, "not a valid ID"},
		{[]string{"exec", "--", "env", "sh", "-c", "echo " + id}, 125, "environment variable instead"},
		{[]string{"exec", "--", id}, 125, "command name cannot contain"},
	} {
		code, out, errText := c.call("", tc.args...)
		if code != tc.code || out != "" || !strings.Contains(errText, tc.text) {
			t.Fatalf("%v: code=%d out=%q err=%q", tc.args, code, out, errText)
		}
	}
	t.Setenv("STALE", "ags_0123456789abcdef")
	if code, _, errText := c.call("", "exec", "--", "true"); code != 125 || !strings.Contains(errText, "in environment variable STALE") {
		t.Fatalf("stale environment ID: code=%d err=%q", code, errText)
	}
}

func TestMetadataEscapesTerminalControls(t *testing.T) {
	c := newTestCLI(t)
	id := c.put("display", "secret-value")["id"].(string)
	c.ok("", "report", id, "--reason", "reason\x1b[2J\u202e")
	out, _ := c.ok("", "view", "display")
	if strings.ContainsAny(out, "\x1b\u202e") || !strings.Contains(out, `\x1b`) {
		t.Fatalf("terminal control in view output: %q", out)
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
