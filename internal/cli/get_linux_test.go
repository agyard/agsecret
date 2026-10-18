//go:build linux

package cli

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Run the actual CLI with real process file descriptors so /proc sees the
// same shell and pipe relationships as it does for an installed binary.
func TestGetProcessHelper(t *testing.T) {
	if os.Getenv("AGSECRET_TEST_GET_HELPER") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			args := append([]string{"--db", os.Getenv("AGSECRET_TEST_GET_DB"), "--pass-file", os.Getenv("AGSECRET_TEST_GET_PASS")}, os.Args[i+1:]...)
			os.Exit(Execute(args, os.Stdin, os.Stdout, os.Stderr))
		}
	}
	os.Exit(127)
}

func TestGetShellContexts(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh is needed for shell context checks")
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	c := newTestCLI(t)
	const value = "synthetic-get-context-value"
	id := c.put("context-test", value)["id"].(string)
	const get = `"$AGSECRET_TEST_GET_BINARY" -test.run='^TestGetProcessHelper$' -- get "$AGSECRET_TEST_GET_ID"`
	for _, tc := range []struct {
		name, script string
		allowed      bool
	}{
		{"direct capture", get + `; status=$?; exit "$status"`, false},
		{"stderr capture", get + ` >&2; status=$?; exit "$status"`, false},
		{"command substitution", `value=$(` + get + `); status=$?; [ "$status" -eq 0 ] || exit "$status"; [ "$value" = "$AGSECRET_TEST_GET_VALUE" ] || exit 21; printf 'accepted\n'`, true},
		{"inner pipeline", get + ` | { IFS= read -r value; [ "$value" = "$AGSECRET_TEST_GET_VALUE" ] || exit 21; printf 'accepted\n'; }`, true},
		{"file redirect", get + ` > "$AGSECRET_TEST_GET_FILE"; status=$?; exit "$status"`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			capture := filepath.Join(t.TempDir(), "capture")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "/bin/sh", "-c", tc.script)
			cmd.WaitDelay = time.Second
			cmd.Env = append(os.Environ(),
				"AGSECRET_TEST_GET_HELPER=1", "AGSECRET_TEST_GET_BINARY="+binary,
				"AGSECRET_TEST_GET_DB="+c.db, "AGSECRET_TEST_GET_PASS="+c.pass,
				"AGSECRET_TEST_GET_ID="+id, "AGSECRET_TEST_GET_VALUE="+value,
				"AGSECRET_TEST_GET_FILE="+capture)
			var out, errOut bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &errOut
			err := cmd.Run()
			if ctx.Err() != nil {
				t.Fatalf("shell context check timed out: %v", ctx.Err())
			}
			if tc.allowed {
				if err != nil || out.String() != "accepted\n" || errOut.Len() != 0 {
					t.Fatalf("indirect get failed: err=%v out=%q stderr=%q", err, out.String(), errOut.String())
				}
			} else if cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 2 || out.Len() != 0 || !strings.Contains(errOut.String(), "refused to print a password directly") {
				t.Fatalf("direct get was not refused: err=%v out=%q stderr=%q", err, out.String(), errOut.String())
			}
			if strings.Contains(out.String()+errOut.String(), value) {
				t.Fatal("the shell exposed the synthetic password")
			}
			if tc.name == "file redirect" {
				data, err := os.ReadFile(capture)
				if err != nil || len(data) != 0 {
					t.Fatalf("file redirect was not refused: bytes=%d err=%v", len(data), err)
				}
			}
		})
	}
}

func TestParseParentPID(t *testing.T) {
	for _, stat := range []string{"123 (worker) S 42 0", "123 (a worker (nested) name)) S 42 0"} {
		if pid, err := parseParentPID(stat); err != nil || pid != 42 {
			t.Fatalf("parse %q: pid=%d err=%v", stat, pid, err)
		}
	}
	for _, stat := range []string{"", "123 worker S 42", "123 (worker)", "123 (worker) S", "123 (worker) S nope", "123 (worker) S -1"} {
		if _, err := parseParentPID(stat); err == nil {
			t.Fatalf("accepted malformed process stat: %q", stat)
		}
	}
}

func TestIsShellCommand(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want bool
	}{
		{[]string{"/bin/sh", "-c", "echo test"}, true},
		{[]string{"-bash", "-lc", "echo test"}, true},
		{[]string{"bash", "--norc", "-o", "errexit", "-c", "echo test"}, true},
		{[]string{"bash", "+o", "errexit", "-O", "extglob", "-c", "echo test"}, true},
		{[]string{"busybox", "sh", "-c", "echo test"}, true},
		{[]string{"fish", "--command=echo test"}, true},
		{[]string{"bash", "--rcfile", "config", "-c", "echo test"}, true},
		{[]string{"bash", "--rcfile", "-c", "script"}, false},
		{[]string{"bash", "-o", "noclobber"}, false},
		{[]string{"sh", "script", "-c"}, false},
		{[]string{"sh", "--", "-c"}, false},
		{[]string{"sh", "-i"}, false},
		{[]string{"python", "-c", "print('test')"}, false},
		{nil, false},
	} {
		if got := isShellCommand(tc.args); got != tc.want {
			t.Errorf("isShellCommand(%q)=%v, want %v", tc.args, got, tc.want)
		}
	}
}
