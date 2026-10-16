//go:build linux

package cli

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestGetShellCaptureAndIndirectPipes(t *testing.T) {
	c := newTestCLI(t)
	c.ok("", "put", "api", "synthetic-get-secret")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	invoke := `"$AGSECRET_TEST_EXE" -test.run=^TestGetRealDescriptorHelper$ -- --db "$AGSECRET_TEST_DB" --pass-file "$AGSECRET_TEST_PASS" get api`
	cases := []struct {
		name, script, stdout string
		code                 int
	}{
		{"direct stdout", invoke + `; status=$?; exit "$status"`, "", 2},
		{"direct stderr", invoke + ` >&2; status=$?; exit "$status"`, "", 2},
		{"command substitution", `value=$(` + invoke + `); status=$?; [ "$status" = 0 ] || exit "$status"; [ "$value" = 'synthetic-get-secret' ] || exit 99; printf 'consumed\n'`, "consumed\n", 0},
		{"inner pipeline", invoke + ` | { IFS= read -r value; [ "$value" = 'synthetic-get-secret' ] || exit 99; printf 'consumed\n'; }`, "consumed\n", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "sh", "-c", tc.script)
			cmd.Env = append(os.Environ(), "AGSECRET_TEST_GET_HELPER=1", "AGSECRET_TEST_EXE="+exe, "AGSECRET_TEST_DB="+c.db, "AGSECRET_TEST_PASS="+c.pass)
			var out, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &stderr
			err := cmd.Run()
			code := 0
			if err != nil {
				if e, ok := err.(*exec.ExitError); ok {
					code = e.ExitCode()
				} else {
					t.Fatal(err)
				}
			}
			if code != tc.code || out.String() != tc.stdout {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
			}
			if tc.code == 2 && !strings.Contains(stderr.String(), capturedOutputRefusal) {
				t.Fatalf("missing refusal: %q", stderr.String())
			}
			if tc.code == 0 && stderr.Len() != 0 {
				t.Fatalf("successful get emitted notice: %q", stderr.String())
			}
		})
	}
}

func TestGetRealDescriptorHelper(t *testing.T) {
	if os.Getenv("AGSECRET_TEST_GET_HELPER") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Exit(Execute(t.Context(), os.Args[i+1:], os.Stdin, os.Stdout, os.Stderr))
		}
	}
	os.Exit(99)
}
