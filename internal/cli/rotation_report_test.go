package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestReportFansOutWithoutPolicyChangeAndPutRefreshesID(t *testing.T) {
	c := newTestCLI(t)
	a := c.put("api", "shared-password")
	id := a["id"].(string)
	output, warning := c.ok("shared-password", "put", "backup", "--secret-stdin", "--json", "--allow-exec=false")
	var b map[string]any
	if err := json.Unmarshal([]byte(output), &b); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(warning, id) || strings.Contains(warning, "shared-password") {
		t.Fatal("duplicate warning must contain ID but no secret", warning)
	}
	c.put("otp", "shared-password", "--type", "pass") // all pass duplicates are intentional
	output, _ = c.ok("", "report", id, "--reason", "unexpected output", "--json")
	var reported []map[string]any
	if err := json.Unmarshal([]byte(output), &reported); err != nil || len(reported) != 3 {
		t.Fatal("ID report must return every affected record as an array", err, output)
	}
	for _, r := range reported {
		if len(r["leaks"].([]any)) != 1 || r["allow_get"] != true {
			t.Fatal("report changed policy or missed history")
		}
		if r["id"] == b["id"] && r["allow_exec"] != false {
			t.Fatal("report changed disabled permission")
		}
	}
	same := c.put(id, "shared-password", "--mask", "fixed:configured")
	if same["id"] != id || len(same["leaks"].([]any)) != 1 {
		t.Fatal("same-value put lost history or ID")
	}
	rotated := c.put(id, "replacement-password")
	if rotated["id"] == id || len(rotated["leaks"].([]any)) != 0 {
		t.Fatal("rotation result stale")
	}
	for _, command := range []string{"get", "view", "report", "delete"} {
		if code, _, _ := c.call("", command, id); code == 0 {
			t.Fatalf("old ID accepted by %s", command)
		}
	}
	if code, _, _ := c.call("", "exec", "--", "echo", id); code == 0 {
		t.Fatal("exec accepted an old token")
	}
	current := c.record("view", rotated["id"].(string))
	if len(current["leaks"].([]any)) != 0 {
		t.Fatal("late report marked replacement")
	}
	other := c.record("view", b["id"].(string))
	if len(other["leaks"].([]any)) != 1 {
		t.Fatal("rotation cleared unrelated matching record")
	}
}

func TestTOTPReportsRejectedAndNoStoredSeedDisclosed(t *testing.T) {
	c := newTestCLI(t)
	const seed = "JBSWY3DPEHPK3PXP"
	r := c.put("login", seed, "--type", "totp")
	for _, ref := range []string{"login", r["id"].(string)} {
		if code, out, _ := c.call("", "report", ref, "--json"); code == 0 || out != "" {
			t.Fatal("TOTP report accepted")
		}
	}
	if code, out, errText := c.call(seed, "report", "--secret-stdin", "--json"); code == 0 || strings.Contains(out+errText, seed) {
		t.Fatal("TOTP seed was reportable or disclosed")
	}
}
