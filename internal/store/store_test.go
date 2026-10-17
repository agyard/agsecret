package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Create(filepath.Join(t.TempDir(), "secrets.db"), []byte("test passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}

func TestEncryptedStoreRoundTripAndWrongPassphrase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.db")
	pass := []byte("test passphrase")
	s, err := Create(path, pass)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Put(Record{Name: "api", Type: "pass", Mask: "fixed:[set]", Secret: []byte("super-secret"), AllowGet: true, AllowExec: true}, nil); err != nil {
		t.Fatal(err)
	}
	r, err := s.GetByNameOrID("api", false)
	if err != nil || !ValidID(r.ID) {
		t.Fatalf("invalid generated ID %q: %v", r.ID, err)
	}
	id := r.ID
	if len(r.Secret) != 0 {
		t.Fatal("metadata contains secret")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("super-secret")) || bytes.HasPrefix(raw, []byte("SQLite format 3")) {
		t.Fatal("database contains plaintext SQLite or secret bytes")
	}
	if _, err := Open(path, []byte("wrong")); err == nil {
		t.Fatal("wrong passphrase was accepted")
	}
	s, err = Open(path, pass)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r, err = s.GetByNameOrID(id, true)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(r.Secret)
	if string(r.Secret) != "super-secret" || !r.AllowGet || r.Name != "api" || r.ID != id {
		t.Fatal("record round trip changed fields")
	}
	descriptor, err := os.ReadFile(path + ".unlock")
	if err != nil {
		t.Fatal(err)
	}
	var u unlockDescriptor
	if err := json.Unmarshal(descriptor, &u); err != nil || u.Version != 2 {
		t.Fatal("new descriptor does not use KDF version 2")
	}
}

func TestLegacyUnlockDescriptorRemainsReadable(t *testing.T) {
	pass := []byte("legacy passphrase")
	key := bytes.Repeat([]byte{17}, 32)
	defer clear(key)
	u := unlockDescriptor{Version: 1, Salt: bytes.Repeat([]byte{23}, 16), Nonce: bytes.Repeat([]byte{42}, chacha20poly1305.NonceSizeX)}
	derived := argon2.IDKey(pass, u.Salt, 3, 64*1024, 4, 32)
	aead, err := chacha20poly1305.NewX(derived)
	clear(derived)
	if err != nil {
		t.Fatal(err)
	}
	u.Wrapped = aead.Seal(nil, u.Nonce, key, []byte("agsecret-store-v1"))
	descriptor, err := json.Marshal(u)
	if err != nil {
		t.Fatal(err)
	}
	unwrapped, err := unwrapPassphrase(pass, descriptor)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(unwrapped)
	if !bytes.Equal(unwrapped, key) {
		t.Fatal("legacy unlock descriptor no longer opens its database key")
	}
}

func TestIDsAndLookup(t *testing.T) {
	s := newTestStore(t)
	ids := map[string]bool{}
	for _, name := range []string{"api", "mail", "database"} {
		if _, err := s.Put(Record{Name: name, Secret: []byte("test-value")}, nil); err != nil {
			t.Fatal(err)
		}
		r, err := s.GetByNameOrID(name, false)
		if err != nil || !ValidID(r.ID) || ids[r.ID] {
			t.Fatalf("invalid or repeated ID %q, err %v", r.ID, err)
		}
		ids[r.ID] = true
		byID, err := s.GetByNameOrID(r.ID, false)
		if err != nil || byID.Name != name {
			t.Fatal("ID lookup failed")
		}
		if _, err := s.Put(Record{Name: r.ID, Secret: []byte("rotated-value")}, nil); err != nil {
			t.Fatal(err)
		}
		rotated, err := s.GetByNameOrID(name, false)
		if err != nil || rotated.ID == r.ID {
			t.Fatal("secret rotation did not replace identity")
		}
		if _, err := s.GetByNameOrID(r.ID, false); !errors.Is(err, ErrNotFound) {
			t.Fatal("old ID still resolves after secret rotation")
		}
	}
	if _, err := s.Put(Record{Name: "ags_ffffffffffffffff", Secret: []byte("bad")}, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("new ID used as a name: %v", err)
	}
	if _, err := s.Put(Record{Name: "ags_reserved", Secret: []byte("bad")}, nil); err == nil {
		t.Fatal("reserved name allowed")
	}
	for _, bad := range []string{"ags_123", "ags_0123456789abcdeF", "agsecret://v1/api", "{{agsecret:api}}"} {
		if ValidID(bad) {
			t.Errorf("invalid ID %q accepted", bad)
		}
	}
	r, err := s.GetByNameOrID("api", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(r.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetByNameOrID("api", false); !errors.Is(err, ErrNotFound) {
		t.Fatal("delete by ID did not delete credential")
	}
}

func TestStoreExpiryAndTOTPValidation(t *testing.T) {
	s := newTestStore(t)
	expires := time.Now().UTC().Add(-time.Second)
	if _, err := s.Put(Record{Name: "old", Type: "totp", Secret: []byte("JBSWY3DPEHPK3PXP"), ExpiresAt: &expires}, nil); err != nil {
		t.Fatal(err)
	}
	r, err := s.GetByNameOrID("old", false)
	if err != nil || !r.Expired(time.Now().UTC()) {
		t.Fatalf("expiry not preserved: %v", err)
	}
	if _, err := s.ReportLeak("old", Leak{}); err == nil {
		t.Fatal("TOTP leak report was accepted")
	}
	if _, err := s.ReportSecret([]byte("JBSWY3DPEHPK3PXP"), Leak{}); err == nil {
		t.Fatalf("TOTP seed matched report: %v", err)
	}
	for _, r := range []Record{{Name: "invalid", Type: "totp", Secret: []byte("not-a-valid-seed!")}, {Name: "legacy", Type: "otp", Secret: []byte("123456")}} {
		if _, err := s.Put(r, nil); err == nil {
			t.Fatal("invalid credential accepted")
		}
	}
}

func TestLeakHistoryAndAtomicRotationOptions(t *testing.T) {
	s := newTestStore(t)
	expires := time.Now().UTC().Add(time.Hour)
	if _, err := s.Put(Record{Name: "api", Type: "pass", Secret: []byte("original"), Mask: "fixed:configured", ExpiresAt: &expires, AllowGet: true, AllowExec: true}, nil); err != nil {
		t.Fatal(err)
	}
	r, err := s.GetByNameOrID("api", false)
	if err != nil {
		t.Fatal(err)
	}
	first := Leak{ReportedAt: time.Now().UTC(), Reason: "log exposure", Context: "command output", Attachments: []string{"shot.png", "run.log"}}
	reports, err := s.ReportLeak(r.ID, first)
	if err != nil || len(reports) != 1 || len(reports[0].Leaks) != 1 {
		t.Fatalf("first report: %v", err)
	}
	reports, err = s.ReportLeak("api", Leak{})
	if err != nil || len(reports) != 1 || len(reports[0].Leaks) != 2 || !reports[0].AllowGet || !reports[0].AllowExec {
		t.Fatalf("append or policy mutation failed: %v", err)
	}
	r = reports[0]
	if r.Leaks[0].Context != first.Context || len(r.Leaks[0].Attachments) != 2 || r.Leaks[1].Reason != "reported by agent" {
		t.Fatal("leak metadata changed")
	}
	if _, err := s.Put(Record{Name: r.ID, Secret: []byte("original"), AllowGet: false}, map[string]bool{"allow-get": true}); err != nil {
		t.Fatal(err)
	}
	policyOnly, err := s.GetByNameOrID("api", false)
	if err != nil || policyOnly.ID != r.ID || len(policyOnly.Leaks) != 2 {
		t.Fatal("policy-only put unexpectedly changed ID or cleared leaks")
	}
	r = policyOnly
	oldID := r.ID
	if _, err := s.Put(Record{Name: r.ID, Secret: []byte("rotated"), AllowGet: true, AllowExec: true}, map[string]bool{}); err != nil {
		t.Fatal(err)
	}
	rotated, err := s.GetByNameOrID("api", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(rotated.Leaks) != 0 || rotated.ID == oldID || rotated.AllowGet || !rotated.AllowExec || rotated.Mask != "fixed:configured" || rotated.ExpiresAt == nil || !rotated.ExpiresAt.Equal(expires.Truncate(time.Second)) {
		t.Fatal("rotation failed to clear history, replace ID, or preserve omitted options")
	}
	if _, err := s.Put(Record{Name: rotated.ID, Secret: []byte("rotated-again"), AllowGet: true}, map[string]bool{"allow-get": true, "ttl": true}); err != nil {
		t.Fatal(err)
	}
	r, err = s.GetByNameOrID("api", false)
	if err != nil || !r.AllowGet || !r.AllowExec || r.ExpiresAt != nil {
		t.Fatal("explicit policy override not applied")
	}
}

func TestReportSecretMatchesAllExactValues(t *testing.T) {
	s := newTestStore(t)
	for _, name := range []string{"one", "two"} {
		if _, err := s.Put(Record{Name: name, Secret: []byte("shared-secret")}, nil); err != nil {
			t.Fatal(err)
		}
	}
	records, err := s.ReportSecret([]byte("shared-secret"), Leak{Context: "found in stdout"})
	if err != nil || len(records) != 2 {
		t.Fatalf("match failed: %v", err)
	}
	for _, r := range records {
		if len(r.Leaks) != 1 || len(r.Secret) != 0 {
			t.Fatal("invalid report result")
		}
	}
	if _, err := s.ReportSecret([]byte("shared"), Leak{}); err == nil {
		t.Fatal("partial secret matched")
	}
}

func TestMigrateLegacySchema(t *testing.T) {
	s := newTestStore(t)
	const oldSchema = `DROP TABLE secrets;
CREATE TABLE secrets(name TEXT PRIMARY KEY NOT NULL,type TEXT NOT NULL,secret BLOB NOT NULL,mask TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,expires_at TEXT,allow_get INTEGER NOT NULL DEFAULT 0,allow_tokenize INTEGER NOT NULL DEFAULT 1,allow_redact INTEGER NOT NULL DEFAULT 1,allow_exec INTEGER NOT NULL DEFAULT 1);
PRAGMA user_version=1;`
	if _, err := s.DB.Exec(oldSchema); err != nil {
		t.Fatal(err)
	}
	now := encodeTime(time.Now())
	if _, err := s.DB.Exec("INSERT INTO secrets(name,type,secret,mask,created_at,updated_at,allow_get,allow_exec) VALUES('legacy','otp',?,'fixed:[set]',?,?,0,1)", []byte("123456"), now, now); err != nil {
		t.Fatal(err)
	}
	if err := checkSchema(s.DB); err != nil {
		t.Fatal(err)
	}
	r, err := s.GetByNameOrID("legacy", true)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(r.Secret)
	if !ValidID(r.ID) || r.Type != "pass" || string(r.Secret) != "123456" || r.AllowGet || !r.AllowExec || len(r.Leaks) != 0 {
		t.Fatal("migration did not preserve legacy credential")
	}
}

func TestCreatePreservesExistingParentPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permissions")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0750); err != nil {
		t.Fatal(err)
	}
	s, err := Create(filepath.Join(dir, "secrets.db"), []byte("pass"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm() != 0750 {
		t.Fatalf("parent permissions changed: %v", err)
	}
	for _, suffix := range []string{"", ".unlock"} {
		info, err := os.Stat(s.Path + suffix)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("store file permissions: %v", err)
		}
	}
	if _, err := Create(s.Path, []byte("pass")); !errors.Is(err, os.ErrExist) {
		t.Fatal("existing database accepted")
	}
	if _, err := s.List(); err != nil {
		t.Fatal("duplicate creation damaged database")
	}
}

func TestUnlockDescriptorReadLimit(t *testing.T) {
	name := filepath.Join(t.TempDir(), "test.unlock")
	if err := os.WriteFile(name, bytes.Repeat([]byte{'x'}, maxUnlockDescriptorBytes+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readUnlockDescriptor(name); err == nil || !strings.Contains(err.Error(), "4096-byte limit") {
		t.Fatalf("oversized descriptor accepted: %v", err)
	}
	want := []byte(`{"version":2}`)
	if err := os.WriteFile(name, want, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readUnlockDescriptor(name)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("small descriptor read failed: %v", err)
	}
}

// These helpers are real OS processes using independent SQLite/WASM runtimes.
// Each is started with a deadline and is always waited, including failure paths.
func runStoreHelpers(t *testing.T, path string, modes ...string) {
	t.Helper()
	if len(modes) > 4 {
		t.Fatal("at most four subprocesses are allowed")
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	dir := t.TempDir()
	release := filepath.Join(dir, "release")
	type helper struct {
		output bytes.Buffer
		ready  string
		done   chan error
	}
	helpers := make([]*helper, 0, len(modes))
	defer func() {
		cancel()
		for _, h := range helpers {
			if h.done != nil {
				<-h.done
			}
		}
	}()
	for i, mode := range modes {
		h := &helper{ready: filepath.Join(dir, fmt.Sprintf("ready-%d", i)), done: make(chan error, 1)}
		cmd := exec.CommandContext(ctx, binary, "-test.run=^TestStoreSubprocess$", "-test.timeout=18s")
		cmd.Env = append(os.Environ(), "AGSECRET_STORE_HELPER_MODE="+mode, "AGSECRET_STORE_HELPER_DB="+path,
			"AGSECRET_STORE_HELPER_READY="+h.ready, "AGSECRET_STORE_HELPER_RELEASE="+release)
		cmd.Stdout, cmd.Stderr = &h.output, &h.output
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		helpers = append(helpers, h)
		go func() { h.done <- cmd.Wait() }()
	}
	for _, h := range helpers {
		if err := waitForTestFile(ctx, h.ready); err != nil {
			t.Fatalf("subprocess did not reach the concurrency barrier: %v", err)
		}
	}
	if err := os.WriteFile(release, []byte("go"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, h := range helpers {
		err := <-h.done
		h.done = nil
		if err != nil {
			t.Fatalf("store subprocess failed: %v\n%s", err, h.output.String())
		}
	}
}

func waitForTestFile(ctx context.Context, path string) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func TestStoreSubprocess(t *testing.T) {
	mode := os.Getenv("AGSECRET_STORE_HELPER_MODE")
	if mode == "" {
		t.Skip("subprocess helper")
	}
	s, err := Open(os.Getenv("AGSECRET_STORE_HELPER_DB"), []byte("test passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// Both put helpers deliberately read the same old policy before the barrier.
	// Put must retain the other writer's subsequent policy update.
	r, err := s.GetByNameOrID("api", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("AGSECRET_STORE_HELPER_READY"), []byte("ready"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	if err := waitForTestFile(ctx, os.Getenv("AGSECRET_STORE_HELPER_RELEASE")); err != nil {
		t.Fatal(err)
	}
	switch mode {
	case "report":
		for range 6 {
			if _, err := s.ReportLeak(r.ID, Leak{Reason: "separate process"}); err != nil {
				t.Fatal(err)
			}
		}
	case "put-get":
		r.Name, r.Secret, r.AllowGet = "api", []byte("rotated-get"), false
		if _, err := s.Put(r, map[string]bool{"allow-get": true}); err != nil {
			t.Fatal(err)
		}
	case "put-exec":
		r.Name, r.Secret, r.AllowExec = "api", []byte("rotated-exec"), false
		if _, err := s.Put(r, map[string]bool{"allow-exec": true}); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unknown helper mode %q", mode)
	}
}

func TestCrossProcessReports(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.Put(Record{Name: "api", Secret: []byte("secret-value"), AllowGet: true, AllowExec: true}, nil); err != nil {
		t.Fatal(err)
	}
	runStoreHelpers(t, s.Path, "report", "report")
	r, err := s.GetByNameOrID("api", false)
	if err != nil || len(r.Leaks) != 12 {
		t.Fatalf("cross-process reports lost: count %d, err %v", len(r.Leaks), err)
	}
}

func TestConcurrentPutPreservesDifferentPolicyUpdates(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.Put(Record{Name: "api", Secret: []byte("original"), AllowGet: true, AllowExec: true}, nil); err != nil {
		t.Fatal(err)
	}
	before, err := s.GetByNameOrID("api", false)
	if err != nil {
		t.Fatal(err)
	}
	runStoreHelpers(t, s.Path, "put-get", "put-exec")
	after, err := s.GetByNameOrID("api", false)
	if err != nil {
		t.Fatal(err)
	}
	if after.AllowGet || after.AllowExec || before.ID == after.ID {
		t.Fatal("concurrent put lost an independent policy update or failed to replace the ID")
	}
}
