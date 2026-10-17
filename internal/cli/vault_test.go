package cli

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestInitCreatesPrivatePassFileBesideVault(t *testing.T) {
	data := t.TempDir()
	t.Setenv("XDG_DATA_HOME", data)
	t.Setenv("AGSECRET_DB", "")
	t.Setenv("AGSECRET_PASS_FILE", "")
	code, out, errOut := run("", "init")
	if code != 0 {
		t.Fatalf("init exit=%d: %s", code, errOut)
	}
	pass := filepath.Join(data, "agsecret", "secrets.pass")
	raw, err := os.ReadFile(pass)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := hex.DecodeString(strings.TrimSpace(string(raw))); err != nil || len(decoded) != 32 {
		t.Fatal("pass file must hold 32 random bytes as hex")
	}
	if st, err := os.Stat(pass); err != nil || runtime.GOOS != "windows" && st.Mode().Perm() != 0600 {
		t.Fatal("pass file permissions", err)
	}
	if strings.Contains(out+errOut, strings.TrimSpace(string(raw))) {
		t.Fatal("init printed the passphrase")
	}
	if code, _, errOut := run("", "init"); code != 0 {
		t.Fatalf("repeated init: %s", errOut)
	}
	if after, _ := os.ReadFile(pass); string(after) != string(raw) {
		t.Fatal("init replaced the pass file")
	}

	// A vault elsewhere gets its own pass file beside it.
	other := filepath.Join(t.TempDir(), "work", "team.db")
	if code, _, errOut := run("", "--db", other, "init"); code != 0 {
		t.Fatalf("init --db: %s", errOut)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(other), "team.pass")); err != nil {
		t.Fatal("pass file not beside the vault", err)
	}
}

func TestInitNeverInventsAChosenPassFile(t *testing.T) {
	data := t.TempDir()
	t.Setenv("XDG_DATA_HOME", data)
	t.Setenv("AGSECRET_DB", "")
	t.Setenv("AGSECRET_PASS_FILE", "")
	missing := filepath.Join(data, "missing.pass")
	if code, _, _ := run("", "--pass-file", missing, "init"); code == 0 {
		t.Fatal("missing chosen pass file accepted")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("init created a pass file the user chose")
	}
}
