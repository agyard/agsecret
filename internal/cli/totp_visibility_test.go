package cli

import (
	"strings"
	"testing"
)

func TestTOTPViewKeepsSeedOpaque(t *testing.T) {
	c := newTestCLI(t)
	seed := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	c.ok("", "put", "otp", seed, "--type", "totp", "--mask", "prefix:4")

	defaultView := c.record("view", "otp")
	if defaultView["value"] != "[set]" {
		t.Fatalf("TOTP default view must stay opaque: %v", defaultView)
	}
	if _, ok := defaultView["secret"]; ok {
		t.Fatalf("default TOTP view exposed a seed: %v", defaultView)
	}

	dangerView := c.record("view", "otp", "--dangerously-show-secret")
	if _, ok := dangerView["secret"]; ok {
		t.Fatalf("dangerous TOTP view exposed a seed: %v", dangerView)
	}
	code, ok := dangerView["current_otp"].(string)
	if !ok || len(code) != 6 || strings.Trim(code, "0123456789") != "" {
		t.Fatalf("dangerous TOTP view did not expose a current code: %v", dangerView)
	}
	if dangerView["value"] != "[set]" {
		t.Fatalf("dangerous TOTP view must keep value opaque: %v", dangerView)
	}

	text, errText := c.ok("", "view", "otp", "--dangerously-show-secret")
	if strings.Contains(text, seed) || strings.Contains(text, "Secret:") {
		t.Fatalf("text TOTP view exposed the seed: %q", text)
	}
	if !strings.Contains(text, "CurrentOTP: ") || errText != "" {
		t.Fatalf("text TOTP view missing current code or emitted noise: out=%q err=%q", text, errText)
	}
}

func TestTOTPGetPrintsOnlyCurrentCode(t *testing.T) {
	c := newTestCLI(t)
	seed := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	c.ok("", "put", "otp", seed, "--type", "totp")

	// Short-lived TOTP codes may use the normal command path; no seed is
	// ever sent to the command output.
	out, errText := c.ok("", "get", "otp")
	code := strings.TrimSpace(out)
	if len(code) != 6 || strings.Trim(code, "0123456789") != "" {
		t.Fatalf("TOTP get returned an invalid code: %q", out)
	}
	if strings.Contains(out, seed) || errText != "" {
		t.Fatalf("TOTP get leaked seed or warning: out=%q err=%q", out, errText)
	}
}
