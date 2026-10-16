package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOversizedStdinCannotBecomeTruncatedSecret(t *testing.T) {
	c := newTestCLI(t)
	const maximum = 1 << 20
	prefix := strings.Repeat("a", maximum)
	c.ok(prefix, "put", "boundary", "--secret-stdin")
	before := c.record("view", "boundary")
	oversized := prefix + "\ntrailing-data-must-not-be-ignored"
	for _, args := range [][]string{
		{"put", "boundary", "--secret-stdin"},
		{"report", "--secret-stdin"},
	} {
		code, out, errOut := c.call(oversized, args...)
		if code == 0 || out != "" || !strings.Contains(errOut, "exceeds 1 MiB") {
			t.Fatalf("oversized input was not rejected: %v code=%d out bytes=%d err=%q", args, code, len(out), errOut)
		}
	}
	after := c.record("view", "boundary")
	if before["id"] != after["id"] || len(after["leaks"].([]any)) != 0 {
		t.Fatal("rejected input changed the credential or created a false report")
	}
}

func TestFileAndStdinUseTheSameInputRules(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	for _, raw := range []string{"synthetic-password", "synthetic-password\n", "synthetic-password\r\n", "first\nsecond\n", "", "\x00", strings.Repeat("z", (1<<20)+1)} {
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		stdin, stdinErr := readSecret(nil, true, "", strings.NewReader(raw))
		file, fileErr := readPassFile(path)
		if (stdinErr == nil) != (fileErr == nil) || !bytes.Equal(stdin, file) {
			t.Fatalf("file and stdin differ for %d bytes: %v / %v", len(raw), stdinErr, fileErr)
		}
		clear(stdin)
		clear(file)
	}
}
