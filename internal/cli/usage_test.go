package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func (c testCLI) assertUsage(ref string, maxUses, used int64) {
	c.t.Helper()
	r := c.record("view", ref)
	if r["max_uses"] != float64(maxUses) || r["used_count"] != float64(used) {
		c.t.Fatalf("usage of %s: max=%v used=%v, want %d/%d", ref, r["max_uses"], r["used_count"], maxUses, used)
	}
}

func TestUsageSharedByGetAndExec(t *testing.T) {
	c := newTestCLI(t)
	id := c.put("limited", "limited-password", "--uses", "2")["id"].(string)
	c.ok("", "get", id, "--dangerously-skip-check")
	c.assertUsage(id, 2, 1)

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGSECRET_EXEC_HELPER", "1")
	t.Setenv("AGSECRET_EXEC_VALUE", id)
	// The same ID appears twice in argv and once in the environment.
	out, _ := c.ok("", "exec", "--", executable, "-test.run=^TestExecHelperProcess$", "--", "both", id, id)
	if want := "[REDACTED:" + id + "]|[REDACTED:" + id + "]\n"; out != want {
		t.Fatalf("expanded output: %q, want %q", out, want)
	}
	c.assertUsage(id, 2, 2)
	if code, out, errText := c.call("", "get", id, "--dangerously-skip-check"); code != 1 || out != "" || !strings.Contains(errText, "no uses left") {
		t.Fatalf("exhausted get: code=%d out=%q err=%q", code, out, errText)
	}
	c.assertUsage(id, 2, 2)
	rows := c.json("", "list").([]any)
	if len(rows) != 1 || rows[0].(map[string]any)["used_count"] != float64(2) {
		t.Fatalf("list usage: %v", rows)
	}
	if out, _ := c.ok("", "view", id); !strings.Contains(out, "exhausted") || !strings.Contains(out, "2/2") {
		t.Fatalf("exhausted view: %q", out)
	}
}

func TestUsageExecPreflightAndDownstreamFailures(t *testing.T) {
	c := newTestCLI(t)
	id := c.put("limited", "limited-password", "--uses", "2")["id"].(string)
	disabled := c.put("disabled", "disabled-password", "--uses", "2", "--access", "none")["id"].(string)
	expired := c.put("expired", "expired-password", "--uses", "2", "--ttl", "1ns")["id"].(string)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGSECRET_EXEC_HELPER", "1")
	args := []string{"exec", "--", executable, "-test.run=^TestExecHelperProcess$", "--", "silent", id}
	for _, tc := range []struct {
		args []string
		code int
	}{
		{[]string{"get", id}, 2},
		{[]string{"exec", "-c", "echo " + id}, 125},
		{append(append([]string(nil), args...), "ags_ffffffffffffffff"), 125},
		{append(append([]string(nil), args...), disabled), 125},
		{append(append([]string(nil), args...), expired), 125},
	} {
		if code, out, errText := c.call("", tc.args...); code != tc.code || out != "" || errText == "" {
			t.Fatalf("preflight %v: code=%d out=%q err=%q", tc.args, code, out, errText)
		}
		c.assertUsage(id, 2, 0)
	}
	c.assertUsage(disabled, 2, 0)
	c.assertUsage(expired, 2, 0)

	if code, _, errText := c.call("", "exec", "--", executable, "-test.run=^TestExecHelperProcess$", "--", "exit", id); code != 7 {
		t.Fatalf("child failure: code=%d err=%q", code, errText)
	}
	c.assertUsage(id, 2, 1)
	if code, _, errText := c.call("", "exec", "--", filepath.Join(t.TempDir(), "missing"), id); code != 127 {
		t.Fatalf("start failure: code=%d err=%q", code, errText)
	}
	c.assertUsage(id, 2, 2)
}

func TestUsageLimitUpdatesAndRotation(t *testing.T) {
	c := newTestCLI(t)
	id := c.put("limited", "first-password", "--uses", "2")["id"].(string)
	c.ok("", "get", id, "--dangerously-skip-check")
	if r := c.put("limited", "first-password"); r["id"] != id {
		t.Fatalf("same value changed ID: %v", r)
	}
	c.assertUsage(id, 2, 1)
	c.ok("", "put", "limited", "--uses", "1")
	c.assertUsage(id, 1, 1)
	for _, limit := range []string{"2", "0"} {
		if code, _, errText := c.call("", "put", "limited", "--uses", limit); code != 1 || !strings.Contains(errText, "put needs the value") {
			t.Fatalf("widen to %s without value: code=%d err=%q", limit, code, errText)
		}
		c.assertUsage(id, 1, 1)
	}
	if r := c.put("limited", "first-password", "--uses", "3"); r["id"] != id {
		t.Fatalf("limit change changed ID: %v", r)
	}
	c.assertUsage(id, 3, 1)
	newID := c.put("limited", "replacement-password")["id"].(string)
	if newID == id {
		t.Fatal("replacement kept the old ID")
	}
	c.assertUsage(newID, 3, 0)
	if code, _, errText := c.call("", "put", "limited", "--uses", "-1"); code != 2 || !strings.Contains(errText, "zero or greater") {
		t.Fatalf("negative limit: code=%d err=%q", code, errText)
	}
	c.assertUsage(newID, 3, 0)
}

func TestUsageTOTPAndUnlimited(t *testing.T) {
	c := newTestCLI(t)
	const seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	id := c.put("otp", seed, "--type", "totp", "--uses", "1")["id"].(string)
	out, _ := c.ok("", "get", id)
	if code := strings.TrimSpace(out); len(code) != 6 || strings.Trim(code, "0123456789") != "" {
		t.Fatalf("TOTP get: %q", out)
	}
	c.assertUsage(id, 1, 1)
	if code, out, errText := c.call("", "get", id); code != 1 || out != "" || !strings.Contains(errText, "no uses left") {
		t.Fatalf("exhausted TOTP: code=%d out=%q err=%q", code, out, errText)
	}
	if r := c.put("otp", seed, "--uses", "0"); r["id"] != id {
		t.Fatalf("unlimited changed ID: %v", r)
	}
	for range 2 {
		c.ok("", "get", id)
	}
	c.assertUsage(id, 0, 3)
}
