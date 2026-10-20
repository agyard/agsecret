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
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

const testPass = "test passphrase"

func newTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secrets.db")
	s, err := Create(path, []byte(testPass))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s, path
}

func ptr[T any](v T) *T { return &v }

// put creates or replaces a password with the given value.
func put(t *testing.T, s *Store, ref, value string) PutResult {
	t.Helper()
	r, err := s.Put(ref, Change{Secret: []byte(value)})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestEncryptedRoundTripAndWrongPassphrase(t *testing.T) {
	s, path := newTestStore(t)
	id := put(t, s, "api", "super-secret").Record.ID
	if r, err := s.Get("api", false); err != nil || r.ID != id || len(r.Secret) != 0 {
		t.Fatalf("metadata read: %v %v", r, err)
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
	s, err = Open(path, []byte(testPass))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r, err := s.Get(id, true)
	if err != nil || string(r.Secret) != "super-secret" || r.Type != "password" || !r.AllowGet || !r.AllowExec {
		t.Fatalf("round trip: %+v %v", r, err)
	}
	var u unlockDescriptor
	if b, err := os.ReadFile(path + ".unlock"); err != nil || json.Unmarshal(b, &u) != nil || u.Version != 1 {
		t.Fatal("unexpected .unlock format")
	}
}

func TestOpenRejectsUnsupportedFormatsWithoutChangingThem(t *testing.T) {
	s, path := newTestStore(t)
	id := put(t, s, "api", "synthetic-value").Record.ID
	for _, version := range []int{0, SchemaVersion + 1} {
		if _, err := s.db.Exec(fmt.Sprintf("PRAGMA user_version=%d", version)); err != nil {
			t.Fatal(err)
		}
		opened, err := Open(path, []byte(testPass))
		if err == nil {
			opened.Close()
			t.Fatalf("accepted unsupported format %d", version)
		}
		if !strings.Contains(err.Error(), fmt.Sprintf("format version %d", version)) {
			t.Fatalf("unexpected format error: %v", err)
		}
		var actual int
		if err := s.db.QueryRow("PRAGMA user_version").Scan(&actual); err != nil || actual != version {
			t.Fatalf("rejected open changed version: got %d, want %d, err=%v", actual, version, err)
		}
		r, err := s.Get(id, true)
		if err != nil || r.Name != "api" || string(r.Secret) != "synthetic-value" {
			t.Fatalf("rejected open changed a record: %v", err)
		}
		clear(r.Secret)
	}
}

func TestIDsChangeWithTheValue(t *testing.T) {
	s, _ := newTestStore(t)
	first := put(t, s, "api", "first-value")
	if !first.Created || !ValidID(first.Record.ID) {
		t.Fatalf("create: %+v", first)
	}
	if _, err := s.Report(first.Record.ID, "exposed"); err != nil {
		t.Fatal(err)
	}
	same, err := s.Put("api", Change{AllowGet: ptr(false)})
	if err != nil || same.Record.ID != first.Record.ID || same.PreviousID != "" || len(same.Record.Leaks) != 1 || same.Record.AllowGet || !same.Record.AllowExec {
		t.Fatalf("option change lost identity, reports or options: %+v %v", same, err)
	}
	replaced := put(t, s, "api", "second-value")
	if replaced.PreviousID != first.Record.ID || replaced.Record.ID == first.Record.ID || len(replaced.Record.Leaks) != 0 || replaced.Record.AllowGet {
		t.Fatalf("replacement: %+v", replaced)
	}
	for _, ref := range []string{first.Record.ID, "ags_ffffffffffffffff"} {
		if _, err := s.Get(ref, false); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s resolves: %v", ref, err)
		}
		if _, err := s.Report(ref, "late"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("stale report on %s: %v", ref, err)
		}
		if _, err := s.Put(ref, Change{Secret: []byte("x")}); err == nil || !strings.Contains(err.Error(), "put requires a field name") {
			t.Fatalf("put by unknown ID %s: %v", ref, err)
		}
	}
	if _, err := s.Put("new", Change{AllowGet: ptr(false)}); err == nil || !strings.Contains(err.Error(), "needs a value") {
		t.Fatalf("option change on a missing secret: %v", err)
	}
	for _, bad := range []string{"ags_reserved", "AGS_0123456789abcdef", "with space", ""} {
		if _, err := s.Put(bad, Change{Secret: []byte("x")}); err == nil {
			t.Fatalf("name %q accepted", bad)
		}
	}
	if err := s.Delete(replaced.Record.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("api", false); !errors.Is(err, ErrNotFound) {
		t.Fatal("delete did not delete")
	}
}

func TestLooseningNeedsTheValue(t *testing.T) {
	s, _ := newTestStore(t)
	soon := time.Now().Add(time.Hour)
	later := soon.Add(time.Hour)
	if _, err := s.Put("api", Change{Secret: []byte("value"), ExpiresAt: ptr(&soon), AllowGet: ptr(false)}); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]Change{
		"allow get":     {AllowGet: ptr(true)},
		"later expiry":  {ExpiresAt: ptr(&later)},
		"never expires": {ExpiresAt: ptr[*time.Time](nil)},
	} {
		if _, err := s.Put("api", c); !errors.Is(err, ErrNeedsValue) {
			t.Fatalf("%s without the value: %v", name, err)
		}
		c.SkipCheck = true
		if _, err := s.Put("api", c); err != nil {
			t.Fatalf("%s with SkipCheck: %v", name, err)
		}
		if _, err := s.Put("api", Change{ExpiresAt: ptr(&soon), AllowGet: ptr(false)}); err != nil {
			t.Fatalf("narrowing again: %v", err)
		}
	}
	for name, c := range map[string]Change{
		"deny exec":        {AllowExec: ptr(false)},
		"earlier expiry":   {ExpiresAt: ptr(&soon)},
		"allow with value": {Secret: []byte("value"), AllowGet: ptr(true), AllowExec: ptr(true)},
	} {
		if _, err := s.Put("api", c); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestTypesExpiryAndTOTP(t *testing.T) {
	s, _ := newTestStore(t)
	past := time.Now().Add(-time.Second)
	r, err := s.Put("otp", Change{Secret: []byte("JBSWY3DPEHPK3PXP"), Type: ptr("totp"), ExpiresAt: ptr(&past)})
	if err != nil || !r.Record.Expired(time.Now()) || !r.Record.ExpiresAt.Equal(past.Truncate(time.Second)) {
		t.Fatalf("expiry: %+v %v", r, err)
	}
	if _, err := s.Report("otp", "x"); err == nil {
		t.Fatal("TOTP report accepted")
	}
	for _, kind := range []string{"pass", "otp"} {
		if _, err := s.Put("bad", Change{Secret: []byte("123456"), Type: ptr(kind)}); err == nil {
			t.Fatalf("type %q accepted", kind)
		}
	}
	if _, err := s.Put("bad", Change{Secret: []byte("not-a-seed!"), Type: ptr("totp")}); err == nil {
		t.Fatal("invalid TOTP seed accepted")
	}
}

func TestReportsReachEveryCopy(t *testing.T) {
	s, _ := newTestStore(t)
	a := put(t, s, "primary", "shared-value")
	past := time.Now().Add(-time.Hour)
	b, err := s.Put("retired", Change{Secret: []byte("shared-value"), ExpiresAt: ptr(&past), AllowExec: ptr(false)})
	if err != nil || !slices.Equal(b.Duplicates, []string{"primary"}) {
		t.Fatalf("duplicate names: %+v %v", b, err)
	}
	put(t, s, "other", "unrelated")
	for i, ref := range []string{a.Record.ID, "retired"} {
		records, err := s.Report(ref, "exposed")
		if err != nil || len(records) != 2 {
			t.Fatalf("report via %s: %v %v", ref, records, err)
		}
		for _, r := range records {
			if len(r.Leaks) != i+1 || r.Leaks[i].Reason != "exposed" {
				t.Fatalf("reports: %+v", r)
			}
			if r.Name == "retired" && r.AllowExec {
				t.Fatal("report changed access")
			}
		}
	}
	if r, _ := s.Get("other", false); len(r.Leaks) != 0 {
		t.Fatal("unrelated secret reported")
	}
	put(t, s, "primary", "rotated")
	if r, _ := s.Get("retired", false); len(r.Leaks) != 2 {
		t.Fatal("replacing one password cleared another's reports")
	}
}

func TestCreateIsExclusiveAndPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permissions")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "secrets.db")
	s, err := Create(path, []byte("pass"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0750 {
		t.Fatalf("parent permissions changed: %v", err)
	}
	for _, suffix := range []string{"", ".unlock"} {
		if info, err := os.Stat(path + suffix); err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("file permissions: %v", err)
		}
	}
	if _, err := Create(path, []byte("pass")); !errors.Is(err, os.ErrExist) {
		t.Fatal("existing database accepted")
	}
	if _, err := s.List(false); err != nil {
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
}

func TestConcurrentDuplicatePutsSeeEachOther(t *testing.T) {
	first, path := newTestStore(t)
	second, err := Open(path, []byte(testPass))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	var wg sync.WaitGroup
	results := make([]PutResult, 2)
	errs := make([]error, 2)
	for i, s := range []*Store{first, second} {
		wg.Go(func() {
			results[i], errs[i] = s.Put([]string{"first", "second"}[i], Change{Secret: []byte("shared-value")})
		})
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		t.Fatal(err)
	}
	if n := len(results[0].Duplicates) + len(results[1].Duplicates); n != 1 {
		t.Fatalf("concurrent puts saw %d duplicates, want 1", n)
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
	s, err := Open(os.Getenv("AGSECRET_STORE_HELPER_DB"), []byte(testPass))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
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
			if _, err := s.Report("api", "separate process"); err != nil {
				t.Fatal(err)
			}
		}
	// Both writers change one option each on the same secret at once; neither
	// may undo the other's change.
	case "deny-get":
		_, err = s.Put("api", Change{AllowGet: ptr(false)})
	case "deny-exec":
		_, err = s.Put("api", Change{AllowExec: ptr(false)})
	default:
		t.Fatalf("unknown helper mode %q", mode)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestCrossProcessWritesDoNotLoseUpdates(t *testing.T) {
	s, path := newTestStore(t)
	put(t, s, "api", "secret-value")
	runStoreHelpers(t, path, "report", "report", "deny-get", "deny-exec")
	r, err := s.Get("api", false)
	if err != nil || len(r.Leaks) != 12 || r.AllowGet || r.AllowExec {
		t.Fatalf("lost cross-process update: reports=%d get=%v exec=%v err=%v", len(r.Leaks), r.AllowGet, r.AllowExec, err)
	}
}

func TestUsageLimitsAndAtomicConsumption(t *testing.T) {
	s, _ := newTestStore(t)
	max := int64(2)
	created, err := s.Put("api", Change{Secret: []byte("value"), MaxUses: &max})
	if err != nil {
		t.Fatal(err)
	}
	if created.Record.MaxUses != 2 || created.Record.UsedCount != 0 {
		t.Fatalf("initial usage state: %+v", created.Record)
	}
	for i, ref := range []string{created.Record.ID, "api"} {
		r, err := s.Consume(ref, "get")
		if err != nil || r.UsedCount != int64(i+1) || string(r.Secret) != "value" {
			t.Fatalf("consume %d: %+v %v", i+1, r, err)
		}
		clear(r.Secret)
	}
	if _, err := s.Consume(created.Record.ID, "get"); !errors.Is(err, ErrNoUses) {
		t.Fatalf("third use: %v", err)
	}
	r, err := s.Get(created.Record.ID, false)
	if err != nil || r.UsedCount != 2 {
		t.Fatalf("failed consume changed state: %+v %v", r, err)
	}

	// A finite limit can be narrowed without the value, but widening it needs
	// the value (or the explicit caller-side bypass).
	narrow := int64(1)
	if _, err := s.Put("api", Change{MaxUses: &narrow}); err != nil {
		t.Fatalf("narrowing limit: %v", err)
	}
	widen := int64(3)
	if _, err := s.Put("api", Change{MaxUses: &widen}); !errors.Is(err, ErrNeedsValue) {
		t.Fatalf("widening limit without value: %v", err)
	}
	updated, err := s.Put("api", Change{Secret: []byte("value"), MaxUses: &widen})
	if err != nil || updated.Record.ID != created.Record.ID || updated.Record.UsedCount != 2 || updated.Record.MaxUses != 3 {
		t.Fatalf("widening with same value: %+v %v", updated, err)
	}
	rotated := put(t, s, "api", "new-value")
	if rotated.Record.ID == created.Record.ID || rotated.Record.UsedCount != 0 || rotated.Record.MaxUses != 3 {
		t.Fatalf("rotation usage state: %+v", rotated.Record)
	}

	// A failed batch leaves every counter untouched, and repeated refs count
	// only once.
	one := int64(1)
	first := put(t, s, "first", "one")
	if _, err := s.Put("first", Change{MaxUses: &one}); err != nil {
		t.Fatal(err)
	}
	second := put(t, s, "second", "two")
	if _, err := s.Put("second", Change{MaxUses: &one}); err != nil {
		t.Fatal(err)
	}
	used, err := s.ConsumeMany([]string{first.Record.ID, "first"}, "exec")
	if err != nil || len(used) != 1 || used[0].UsedCount != 1 {
		t.Fatalf("duplicate refs consumed more than once: %+v %v", used, err)
	}
	clear(used[0].Secret)
	if _, err := s.ConsumeMany([]string{first.Record.ID, second.Record.ID}, "exec"); !errors.Is(err, ErrNoUses) {
		t.Fatalf("failed batch: %v", err)
	}
	secondState, err := s.Get(second.Record.ID, false)
	if err != nil || secondState.UsedCount != 0 {
		t.Fatalf("failed batch changed second counter: %+v %v", secondState, err)
	}
}

func TestConsumeChecksDoNotSpendUses(t *testing.T) {
	s, _ := newTestStore(t)
	put(t, s, "available", "value")
	past := time.Now().Add(-time.Minute)
	for _, tc := range []struct {
		name, action string
		change       Change
		want         error
	}{
		{"expired", "get", Change{ExpiresAt: ptr(&past)}, ErrExpired},
		{"deny-get", "get", Change{AllowGet: ptr(false)}, ErrNotAllowed},
		{"deny-exec", "exec", Change{AllowExec: ptr(false)}, ErrNotAllowed},
		{"deny-send", "send", Change{AllowExec: ptr(false)}, ErrNotAllowed},
	} {
		tc.change.Secret = []byte("value")
		if _, err := s.Put(tc.name, tc.change); err != nil {
			t.Fatal(err)
		}
		if _, err := s.ConsumeMany([]string{"available", tc.name}, tc.action); !errors.Is(err, tc.want) {
			t.Fatalf("%s: %v", tc.name, err)
		}
	}
	r, err := s.Get("available", false)
	if err != nil || r.UsedCount != 0 {
		t.Fatalf("refused batches consumed uses: %+v %v", r, err)
	}
	r, err = s.Consume("available", "exec")
	defer clear(r.Secret)
	if err != nil || r.MaxUses != 0 || r.UsedCount != 1 {
		t.Fatalf("unlimited credential usage: %+v %v", r, err)
	}
}

func TestUsageLimitConcurrentConsumption(t *testing.T) {
	first, path := newTestStore(t)
	max := int64(5)
	created := put(t, first, "api", "value")
	if _, err := first.Put("api", Change{MaxUses: &max}); err != nil {
		t.Fatal(err)
	}
	second, err := Open(path, []byte(testPass))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	stores := []*Store{first, second}
	var wg sync.WaitGroup
	results := make(chan error, 12)
	for i := 0; i < 12; i++ {
		store := stores[i%len(stores)]
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := store.Consume(created.Record.ID, "send")
			if err == nil {
				clear(r.Secret)
			}
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	var success, exhausted int64
	for err := range results {
		switch {
		case err == nil:
			success++
		case errors.Is(err, ErrNoUses):
			exhausted++
		default:
			t.Fatalf("concurrent consume: %v", err)
		}
	}
	if success != max || exhausted != 12-max {
		t.Fatalf("success=%d exhausted=%d", success, exhausted)
	}
	r, err := first.Get(created.Record.ID, false)
	if err != nil || r.UsedCount != max {
		t.Fatalf("final usage count: %+v %v", r, err)
	}
}
