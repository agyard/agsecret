package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func testAPIKey(t *testing.T, s *Store, name string, rules ...string) string {
	t.Helper()
	token, err := s.CreateAPIKey(name, rules)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestRules(t *testing.T) {
	for _, tc := range []struct {
		pattern, name string
		want          bool
	}{
		{"*", "pku/a:password", true},
		{"pku_*:*", "pku_work:password", true},
		{"pku_*:*", "pku_work", false},
		{"*", "standalone", true},
		{"*:*", "standalone", false},
		{"pku?*", "pku/a:otp", true},
		{"pku?:otp", "pkux:otp", true},
		{"pku?:otp", "pkuxx:otp", false},
		{"pku_[ab]:*", "pku_b:otp", true},
		{"pku_[^a]:*", "pku_b:otp", true},
		{"pku_[^a]:*", "pku_a:otp", false},
		{"pku[.-0]a:*", "pku/a:otp", true},
		{"pku[/]a:*", "pku/a:otp", true},
		{"pku[.-0]a:*", "pku:a:otp", false},
		{`pku\/:*`, "pku/:otp", true},
		{"pku*:otp", "PKU_a:otp", false},
		{"a*b*c", "axbyc", true},
		{"a*b*c", "axbycz", false},
		{"a**?c", "ab/c", true},
	} {
		got, err := matchRule(tc.pattern, tc.name)
		if err != nil || got != tc.want {
			t.Errorf("match %q %q = %v, %v; want %v", tc.pattern, tc.name, got, err, tc.want)
		}
	}
	rules := []string{"pku_*:*", "!pku_*:otp", "pku_shared:otp"}
	if err := ValidateRules(rules); err != nil {
		t.Fatal(err)
	}
	for name, allowed := range map[string]bool{
		"pku_work:password": true,
		"pku_work:otp":      false,
		"pku_shared:otp":    true,
		"other:password":    false,
	} {
		if got := rulesAllow(rules, name); got != allowed {
			t.Errorf("rules for %s = %v, want %v", name, got, allowed)
		}
	}
	for _, rules := range [][]string{nil, {}, {"!excluded"}, {""}, {"!"}, {"["}, {"*", "![x"}, {"*", "a\\"}, {"nul\x00"}, {"new\nline"}, {"tab\t"}} {
		if err := ValidateRules(rules); err == nil {
			t.Errorf("accepted invalid rules %q", rules)
		}
	}
}

func TestServerConfig(t *testing.T) {
	s, _ := newTestStore(t)
	if keys, err := s.APIKeys(); err != nil || len(keys) != 0 {
		t.Fatalf("empty API keys: %v %v", keys, err)
	}
	if remotes, err := s.Remotes(); err != nil || len(remotes) != 0 {
		t.Fatalf("empty remotes: %v %v", remotes, err)
	}
	if _, err := s.APIList("agk_" + strings.Repeat("1", 64)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("unconfigured server authorized: %v", err)
	}
	for _, table := range []string{"api_keys", "remotes"} {
		if exists, err := hasTable(s.db, table); err != nil || exists {
			t.Fatalf("read created %s: %v", table, err)
		}
	}
	token := testAPIKey(t, s, "agent", "*", "!*:otp")
	if !ValidAPIKey(token) {
		t.Fatal("created an invalid API key")
	}
	var digest []byte
	if err := s.db.QueryRow("SELECT digest FROM api_keys WHERE name='agent'").Scan(&digest); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte(token))
	if !bytes.Equal(digest, want[:]) || bytes.Equal(digest, []byte(token)) {
		t.Fatal("API key was not stored as its SHA-256 digest")
	}
	if _, err := s.CreateAPIKey("agent", []string{"*"}); err == nil {
		t.Fatal("duplicate API key name accepted")
	}
	keys, err := s.APIKeys()
	if err != nil || len(keys) != 1 || keys[0].Name != "agent" || !slices.Equal(keys[0].Rules, []string{"*", "!*:otp"}) {
		t.Fatalf("API keys: %v %v", keys, err)
	}
	for _, bad := range []string{"", "agk_short", "AGK_" + strings.Repeat("1", 64), "agk_" + strings.Repeat("A", 64)} {
		if ValidAPIKey(bad) {
			t.Errorf("accepted token %q", bad)
		}
	}
	for _, name := range []string{"10_home", "00_work"} {
		if err := s.AddRemote(name, "https://example.com/", token); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"local", "UPPER", "", "with space", "a/b"} {
		if err := s.AddRemote(name, "https://example.com", token); err == nil {
			t.Fatalf("accepted remote name %q", name)
		}
	}
	for _, address := range []string{"relative", "ftp://example.com", "https://user@example.com", "https://example.com/path", "https://example.com?key=x", "https://example.com#", "https://example.com?"} {
		if err := s.AddRemote("invalid", address, token); err == nil {
			t.Errorf("accepted URL %q", address)
		}
	}
	if err := s.AddRemote("00_work", "https://other.example", token); err == nil {
		t.Fatal("duplicate remote accepted")
	}
	remotes, err := s.Remotes()
	if err != nil || len(remotes) != 2 || remotes[0].Name != "00_work" || remotes[1].Name != "10_home" || remotes[0].Key != token || remotes[0].URL != "https://example.com" {
		t.Fatalf("remotes: %v %v", remotes, err)
	}
	encoded, _ := json.Marshal(remotes)
	if bytes.Contains(encoded, []byte(token)) {
		t.Fatal("remote metadata JSON includes its API key")
	}
	if err := s.DeleteRemote("00_work"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteRemote("00_work"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing remote: %v", err)
	}
	if err := s.DeleteAPIKey("agent"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.APIList(token); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("deleted key still authorized: %v", err)
	}
}

func TestAPIDynamicScopeAndMetadata(t *testing.T) {
	s, _ := newTestStore(t)
	a := put(t, s, "pku_work:password", "first-password").Record
	b := put(t, s, "private:password", "other-password").Record
	if _, err := s.Put("pku_work:username", Change{Secret: []byte("alice"), Type: ptr("plain")}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put("pku_work:otp", Change{Secret: []byte("JBSWY3DPEHPK3PXP"), Type: ptr("totp")}); err != nil {
		t.Fatal(err)
	}
	token := testAPIKey(t, s, "agent", "pku_*:*")
	for _, ref := range []string{a.Name, a.ID, "pku_work:otp"} {
		r, err := s.APIGet(token, ref)
		if err != nil || len(r.Secret) != 0 || r.UsedCount != 0 {
			t.Fatalf("sensitive metadata %s: %+v %v", ref, r, err)
		}
	}
	if r, err := s.APIGet(token, "pku_work:username"); err != nil || string(r.Secret) != "alice" {
		t.Fatalf("plain metadata: %+v %v", r, err)
	}
	for _, ref := range []string{b.Name, b.ID, "ags_0000000000000000"} {
		if _, err := s.APIGet(token, ref); !errors.Is(err, ErrNotFound) {
			t.Fatalf("unauthorized/missing ref %s: %v", ref, err)
		}
	}
	put(t, s, "pku_new:password", "new-value")
	records, err := s.APIList(token)
	if err != nil || len(records) != 4 {
		t.Fatalf("dynamic list: %+v %v", records, err)
	}
	for _, r := range records {
		if r.Type != "plain" && r.Secret != nil {
			t.Fatal("list exposed a sensitive value")
		}
	}
	if _, err := s.Rename(a.ID, "private:renamed"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.APIGet(token, a.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("renamed ID retained old scope: %v", err)
	}
	if _, err := s.APIConsume(token, []string{a.ID}, "exec"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("renamed ID consumed outside scope: %v", err)
	}
	rotated := put(t, s, "pku_new:password", "rotated-password").Record
	if _, err := s.APIGet(token, rotated.ID); err != nil {
		t.Fatalf("rotation lost name authorization: %v", err)
	}
}

func TestAPIConsumeAtomicAndShared(t *testing.T) {
	s, _ := newTestStore(t)
	a, err := s.Put("work:password", Change{Secret: []byte("synthetic"), MaxUses: ptr(int64(2))})
	if err != nil {
		t.Fatal(err)
	}
	b := put(t, s, "private:password", "other").Record
	plain, err := s.Put("work:username", Change{Secret: []byte("alice"), Type: ptr("plain")})
	if err != nil {
		t.Fatal(err)
	}
	token := testAPIKey(t, s, "agent", "work:*")
	if _, err := s.APIConsume(token, []string{a.Record.ID, b.ID}, "exec"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("out-of-scope batch: %v", err)
	}
	if r, _ := s.Get(a.Record.ID, false); r.UsedCount != 0 {
		t.Fatal("failed batch consumed an allowed record")
	}
	if _, err := s.APIConsume(token, []string{a.Record.Name}, "exec"); err == nil {
		t.Fatal("consume accepted a name")
	}
	for _, action := range []string{"get", "exec", "send"} {
		if _, err := s.APIConsume("invalid", []string{a.Record.ID}, action); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("invalid key for %s: %v", action, err)
		}
	}
	records, err := s.APIConsume(token, []string{a.Record.ID, a.Record.ID, plain.Record.ID}, "exec")
	if err != nil || len(records) != 2 || records[0].UsedCount != 1 || string(records[0].Secret) != "synthetic" || records[1].UsedCount != 0 {
		t.Fatalf("consume: %+v %v", records, err)
	}
	clearRecords(records)
	r, err := s.Consume(a.Record.ID, "get")
	if err != nil || r.UsedCount != 2 {
		t.Fatalf("shared local use: %+v %v", r, err)
	}
	clear(r.Secret)
	if _, err := s.APIConsume(token, []string{a.Record.ID}, "send"); !errors.Is(err, ErrNoUses) {
		t.Fatalf("shared counter exhausted: %v", err)
	}
	past := time.Now().Add(-time.Hour)
	expired, err := s.Put("work:expired", Change{Secret: []byte("expired"), ExpiresAt: ptr(&past)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.APIConsume(token, []string{expired.Record.ID}, "exec"); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired use: %v", err)
	}
	denied, err := s.Put("work:denied", Change{Secret: []byte("denied"), AllowGet: ptr(false), AllowExec: ptr(false)})
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"get", "exec", "send"} {
		if _, err := s.APIConsume(token, []string{denied.Record.ID}, action); !errors.Is(err, ErrNotAllowed) {
			t.Fatalf("access for %s: %v", action, err)
		}
	}
}

func TestAPIConcurrentUses(t *testing.T) {
	s, path := newTestStore(t)
	other, err := Open(path, []byte(testPass))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	r, err := s.Put("password", Change{Secret: []byte("synthetic"), MaxUses: ptr(int64(1))})
	if err != nil {
		t.Fatal(err)
	}
	token := testAPIKey(t, s, "agent", "*")
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, vault := range []*Store{s, other} {
		wg.Go(func() {
			records, err := vault.APIConsume(token, []string{r.Record.ID}, "exec")
			clearRecords(records)
			results <- err
		})
	}
	wg.Wait()
	close(results)
	success, exhausted := 0, 0
	for err := range results {
		switch {
		case err == nil:
			success++
		case errors.Is(err, ErrNoUses):
			exhausted++
		default:
			t.Fatal(err)
		}
	}
	if success != 1 || exhausted != 1 {
		t.Fatalf("successful=%d, exhausted=%d", success, exhausted)
	}
}

func TestAPIReportFanoutAndScope(t *testing.T) {
	s, _ := newTestStore(t)
	a := put(t, s, "visible:password", "shared-password").Record
	b := put(t, s, "hidden:password", "shared-password").Record
	c := put(t, s, "visible:copy", "shared-password").Record
	plain, err := s.Put("visible:username", Change{Secret: []byte("alice"), Type: ptr("plain")})
	if err != nil {
		t.Fatal(err)
	}
	token := testAPIKey(t, s, "agent", "visible:*")
	for _, ref := range []string{b.ID, "ags_0000000000000000"} {
		if _, err := s.APIReport(token, ref, "exposed"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("unauthorized/missing report: %v", err)
		}
	}
	if _, err := s.APIReport(token, plain.Record.ID, "exposed"); !errors.Is(err, ErrReportType) {
		t.Fatalf("plain report: %v", err)
	}
	if _, err := s.APIReport(token, a.Name, "exposed"); err == nil {
		t.Fatal("report accepted a name")
	}
	records, err := s.APIReport(token, a.ID, "exposed")
	if err != nil || len(records) != 2 || records[0].ID != c.ID || records[1].ID != a.ID {
		t.Fatalf("scoped report response: %+v %v", records, err)
	}
	for _, id := range []string{a.ID, b.ID, c.ID} {
		r, err := s.Get(id, false)
		if err != nil || len(r.Leaks) != 1 || r.Leaks[0].Reason != "exposed" {
			t.Fatalf("fanout %s: %+v %v", id, r, err)
		}
	}
	if err := s.DeleteAPIKey("agent"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.APIReport(token, a.ID, "again"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("deleted key reported: %v", err)
	}
}
