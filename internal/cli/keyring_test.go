package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agyard/agsecret/internal/store"
)

type fakeKeyring struct {
	values         map[string][]byte
	getErr, setErr error
	gets, sets     int
}

func (r *fakeKeyring) Get(id string) ([]byte, error) {
	r.gets++
	if r.getErr != nil {
		return nil, r.getErr
	}
	return bytes.Clone(r.values[id]), nil
}

func (r *fakeKeyring) Set(id string, pass []byte) error {
	r.sets++
	if r.setErr != nil {
		return r.setErr
	}
	r.values[id] = bytes.Clone(pass)
	return nil
}

func keyringFixture(t *testing.T) (*options, *fakeKeyring, string) {
	t.Helper()
	dir := t.TempDir()
	r := &fakeKeyring{values: map[string][]byte{}}
	o := &options{db: filepath.Join(dir, "vault.db"), passFile: filepath.Join(dir, "vault.pass"),
		defaultPass: true, keyringMode: "auto", keyring: r, in: strings.NewReader(""), errOut: &bytes.Buffer{}}
	if err := os.WriteFile(o.passFile, []byte("synthetic-unlock-pass"), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := store.Create(o.db, []byte("synthetic-unlock-pass"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	id, err := store.UnlockID(o.db)
	if err != nil {
		t.Fatal(err)
	}
	return o, r, id
}

func checkOpen(o *options) error {
	return o.withStore(func(*store.Store) error { return nil })
}

func TestKeyringCachesOnlyVerifiedFileUnlockAndPrefersItAfterMove(t *testing.T) {
	o, ring, id := keyringFixture(t)
	if err := checkOpen(o); err != nil {
		t.Fatal(err)
	}
	if o.unlockSource != "passfile" || !o.keyringCached || ring.sets != 1 {
		t.Fatal("file unlock was not cached")
	}
	// Moving the database and descriptor preserves the ID, without a pass file.
	old := o.db
	o.db = filepath.Join(t.TempDir(), "moved.db")
	for _, suffix := range []string{"", ".unlock"} {
		if err := os.Rename(old+suffix, o.db+suffix); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(o.passFile); err != nil {
		t.Fatal(err)
	}
	if err := checkOpen(o); err != nil {
		t.Fatal(err)
	}
	if o.unlockSource != "keyring" || ring.sets != 1 || !bytes.Equal(ring.values[id], []byte("synthetic-unlock-pass")) {
		t.Fatal("keyring did not retain priority after moving the vault")
	}
}

func TestKeyringUnavailableStaleOrEmptyFallsBackWithoutDisclosure(t *testing.T) {
	for _, mode := range []string{"unavailable", "stale", "empty", "set-fails"} {
		t.Run(mode, func(t *testing.T) {
			o, ring, id := keyringFixture(t)
			switch mode {
			case "unavailable":
				ring.getErr = errors.New("synthetic-secret-provider-error")
			case "stale":
				ring.values[id] = []byte("wrong-unlock-pass")
			case "set-fails":
				ring.setErr = errors.New("synthetic-secret-provider-error")
			}
			if err := checkOpen(o); err != nil {
				t.Fatal("file fallback failed")
			}
			if o.unlockSource != "passfile" || o.errOut.(*bytes.Buffer).Len() != 0 {
				t.Fatal("fallback leaked provider output")
			}
			if mode != "set-fails" && !bytes.Equal(ring.values[id], []byte("synthetic-unlock-pass")) {
				t.Fatal("cache was not refreshed")
			}
			if raw, err := os.ReadFile(o.passFile); err != nil || string(raw) != "synthetic-unlock-pass" {
				t.Fatal("fallback file changed")
			}
		})
	}
}

func TestKeyringNeverCachesAnInvalidPassFileAndOffSkipsBackend(t *testing.T) {
	o, ring, _ := keyringFixture(t)
	if err := os.WriteFile(o.passFile, []byte("wrong-passphrase"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkOpen(o); err == nil || ring.sets != 0 {
		t.Fatal("invalid file unlock was cached")
	}
	o.keyringMode = "off"
	ring.gets = 0
	_ = checkOpen(o)
	if ring.gets != 0 || ring.sets != 0 {
		t.Fatal("off contacted the keyring")
	}
}

func TestKeyringConfigurationPrecedence(t *testing.T) {
	t.Setenv("AGSECRET_KEYRING", "auto")
	o := &options{keyringMode: "off"}
	if err := o.resolve(); err != nil || o.keyringMode != "off" {
		t.Fatal("flag must override environment")
	}
	o = &options{}
	if err := o.resolve(); err != nil || o.keyringMode != "auto" {
		t.Fatal("environment not respected")
	}
	t.Setenv("AGSECRET_KEYRING", "invalid")
	if err := (&options{}).resolve(); err == nil {
		t.Fatal("invalid backend mode accepted")
	}
}
