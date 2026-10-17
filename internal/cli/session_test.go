package cli

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestInitGeneratesPrivateDefaultPassFile(t *testing.T) {
	data := t.TempDir()
	t.Setenv("XDG_DATA_HOME", data)
	t.Setenv("AGSECRET_DB", "")
	t.Setenv("AGSECRET_PASS_FILE", "")
	var out, stderr bytes.Buffer
	code := Execute([]string{"init"}, strings.NewReader(""), &out, &stderr)
	if code != 0 {
		t.Fatalf("init exit=%d: %s", code, stderr.String())
	}
	pass := filepath.Join(data, "agsecret", "session.pass")
	raw, err := os.ReadFile(pass)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(decoded) != 32 {
		t.Fatal("pass file must be 32 random bytes as hex")
	}
	if st, err := os.Stat(pass); err != nil || runtime.GOOS != "windows" && st.Mode().Perm() != 0600 {
		t.Fatal("pass file permissions", err)
	}
	if strings.Contains(out.String()+stderr.String(), strings.TrimSpace(string(raw))) {
		t.Fatal("init disclosed passphrase")
	}
	if code := Execute([]string{"doctor", "--json"}, strings.NewReader(""), &out, &stderr); code != 0 {
		t.Fatalf("doctor: %s", stderr.String())
	}
	out.Reset()
	stderr.Reset()
	if code := Execute([]string{"init"}, strings.NewReader(""), &out, &stderr); code != 0 {
		t.Fatalf("repeated init: %s", stderr.String())
	}
	after, _ := os.ReadFile(pass)
	if !bytes.Equal(raw, after) {
		t.Fatal("init overwrote passphrase")
	}
}

func TestInitExternalPassFileNeverFallsBack(t *testing.T) {
	data := t.TempDir()
	t.Setenv("XDG_DATA_HOME", data)
	t.Setenv("AGSECRET_DB", "")
	t.Setenv("AGSECRET_PASS_FILE", "")
	var out, stderr bytes.Buffer
	missing := filepath.Join(data, "missing.pass")
	if code := Execute([]string{"--pass-file", missing, "init"}, strings.NewReader(""), &out, &stderr); code == 0 {
		t.Fatal("missing external pass file accepted")
	}
	if _, err := os.Stat(filepath.Join(data, "agsecret", "session.pass")); !os.IsNotExist(err) {
		t.Fatal("unexpected generated default pass file")
	}
}
