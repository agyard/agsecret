package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestExecModeArguments(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"exec"}, "usage:"},
		{[]string{"exec", "--"}, "usage:"},
		{[]string{"exec", "-c"}, "flag needs an argument"},
		{[]string{"exec", "-c", ""}, "use either -c SCRIPT or -- COMMAND"},
		{[]string{"exec", "--command="}, "use either -c SCRIPT or -- COMMAND"},
		{[]string{"exec", "-c", "echo ok", "echo", "extra"}, "use either -c SCRIPT or -- COMMAND"},
		{[]string{"exec", "--command", "echo ok", "--", "echo", "extra"}, "use either -c SCRIPT or -- COMMAND"},
		{[]string{"exec", "--allow-code", "-c", "echo ok"}, "unknown flag: --allow-code"},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			code, out, errText := run("", tc.args...)
			if code != 2 || out != "" || !strings.Contains(errText, tc.want) {
				t.Fatalf("code=%d out=%q err=%q", code, out, errText)
			}
		})
	}
}

func TestExecReceivesSeparateArguments(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX executable script and echo")
	}
	c := newTestCLI(t)
	secret := "literal value 'quoted' ; $HOME $(printf unexpected)"
	id := c.put("browser", secret)["id"].(string)
	marker := "[REDACTED:" + id + "]"
	if out, errText := c.ok("", "exec", "--", "echo", id); out != marker+"\n" || strings.Contains(errText, secret) {
		t.Fatalf("echo: out=%q err=%q", out, errText)
	}

	dir := t.TempDir()
	browser := filepath.Join(dir, "agent-browser")
	argsFile := filepath.Join(dir, "arguments")
	// The fake browser records the actual positional arguments it received,
	// then prints the value to exercise the output filter as well.
	script := "#!/bin/sh\nprintf '%s\\000' \"$@\" > \"$AGSECRET_EXEC_ARGS\"\nprintf '%s\\n' \"$3\"\n"
	if err := os.WriteFile(browser, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGSECRET_EXEC_ARGS", argsFile)
	out, errText := c.ok("", "exec", "--", browser, "fill", "e1", id)
	if out != marker+"\n" || strings.Contains(errText, secret) {
		t.Fatalf("browser: out=%q err=%q", out, errText)
	}
	b, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Split(string(bytes.TrimSuffix(b, []byte{0})), "\x00"); !slices.Equal(got, []string{"fill", "e1", secret}) {
		t.Fatalf("browser received %q", got)
	}
}

func TestExecShellEnvironmentPreservesLiteralValue(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("tests POSIX shell expansion")
	}
	c := newTestCLI(t)
	probe := filepath.Join(t.TempDir(), "must-not-exist")
	secret := "literal \" ' ; $(touch \"" + probe + "\") `touch \"" + probe + "\"`\nnext line"
	id := c.put("shell", secret)["id"].(string)
	t.Setenv("TOKEN", id)
	for _, flag := range []string{"-c", "--command"} {
		out, errText := c.ok("", "exec", flag, `printf '%s' "$TOKEN"`)
		if out != "[REDACTED:"+id+"]" || strings.Contains(errText, secret) {
			t.Fatalf("%s: out=%q err=%q", flag, out, errText)
		}
		if _, err := os.Stat(probe); !os.IsNotExist(err) {
			t.Fatalf("%s interpreted the value as shell code: %v", flag, err)
		}
	}
}

func TestExecRefusesCodeIDsAndImplicitShell(t *testing.T) {
	c := newTestCLI(t)
	id := c.put("code", "synthetic-secret")["id"].(string)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"exec", "-c", "echo " + id}, "secret would be read as code"},
		{[]string{"exec", "--command", "echo " + id}, "secret would be read as code"},
		{[]string{"exec", "--", "bash", "-c", "echo " + id}, "secret would be read as code"},
		{[]string{"exec", "--", "echo " + id}, "pass the command and each argument as separate words"},
		{[]string{"exec", "--", id}, "command name cannot contain a secret ID"},
	} {
		code, out, errText := c.call("", tc.args...)
		if code != 125 || out != "" || !strings.Contains(errText, tc.want) || strings.Contains(errText, "synthetic-secret") {
			t.Fatalf("%v: code=%d out=%q err=%q", tc.args, code, out, errText)
		}
	}
	if code, out, errText := c.call("", "exec", "--", "echo ordinary-text"); code != 127 || out != "" || !strings.Contains(errText, "separate words") {
		t.Fatalf("implicit shell: code=%d out=%q err=%q", code, out, errText)
	}
}
