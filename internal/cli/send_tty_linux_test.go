//go:build linux

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func testPTY(t *testing.T) (int, string) {
	t.Helper()
	master, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Skipf("PTYs unavailable: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(master) })
	if err := unix.IoctlSetPointerInt(master, unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	number, err := unix.IoctlGetInt(master, unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	return master, fmt.Sprintf("/dev/pts/%d", number)
}

func setPTYEcho(t *testing.T, master int, enabled bool) {
	t.Helper()
	state, err := unix.IoctlGetTermios(master, unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if enabled {
		state.Lflag |= unix.ECHO
	} else {
		state.Lflag &^= unix.ECHO
	}
	if err := unix.IoctlSetTermios(master, unix.TCSETS, state); err != nil {
		t.Fatal(err)
	}
}

func TestTargetTTYDetectsEcho(t *testing.T) {
	master, path := testPTY(t)
	for _, enabled := range []bool{true, false} {
		setPTYEcho(t, master, enabled)
		got, err := targetEchoEnabled(path)
		if err != nil {
			t.Fatal(err)
		}
		if got != enabled {
			t.Fatalf("echo=%v, want %v", got, enabled)
		}
	}
	if _, err := targetEchoEnabled(t.TempDir() + "/not-a-tty"); err == nil {
		t.Fatal("accepted a non-TTY path")
	}
}

func TestSendChecksEchoAndUsesLiteralTmuxArguments(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh is needed for the private tmux stub")
	}
	master, ttyPath := testPTY(t)
	c := newTestCLI(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "send.log")
	stub := `#!/bin/sh
case "$1" in
  display-message)
    [ "$#" -eq 5 ] && [ "$2" = '-p' ] && [ "$3" = '-t' ] && [ "$4" = 'dev:0.1' ] && [ "$5" = '#{pane_tty}' ] || exit 32
    printf '%s\n' "$AGSECRET_TEST_TMUX_TTY"
    ;;
  send-keys)
    printf '%s\n' "$@" >> "$AGSECRET_TEST_TMUX_LOG"
    ;;
  *) exit 33 ;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "tmux"), []byte(stub), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("AGSECRET_TEST_TMUX_TTY", ttyPath)
	t.Setenv("AGSECRET_TEST_TMUX_LOG", logPath)
	secret := "-pa ss;word"
	c.ok(secret, "put", "send-test", "--secret-stdin")
	stored := c.record("view", "send-test")
	id := stored["id"].(string)
	readLog := func() string {
		t.Helper()
		b, err := os.ReadFile(logPath)
		if os.IsNotExist(err) {
			return ""
		}
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	resetLog := func() {
		t.Helper()
		if err := os.Remove(logPath); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	assertNoSend := func() {
		t.Helper()
		if got := readLog(); got != "" {
			t.Fatalf("tmux sent a rejected credential: %q", got)
		}
	}
	literal := "send-keys\n-t\ndev:0.1\n-l\n--\n" + secret + "\n"
	enter := "send-keys\n-t\ndev:0.1\nEnter\n"
	setPTYEcho(t, master, true)
	if code, out, errText := c.call("", "send", "tmux:dev:0.1", id); code == 0 || out != "" || !strings.Contains(errText, "TTY has ECHO enabled") {
		t.Fatalf("echo check: code=%d out=%q err=%q", code, out, errText)
	}
	assertNoSend()
	if out, errText := c.ok("", "send", "tmux:dev:0.1", id, "--force-echo", "--enter=false"); out != "" || errText != "" {
		t.Fatalf("send should be quiet: out=%q err=%q", out, errText)
	}
	if got := readLog(); got != literal {
		t.Fatalf("literal send: %q, want %q", got, literal)
	}
	resetLog()
	setPTYEcho(t, master, false)
	c.ok("", "send", "tmux:dev:0.1", "send-test")
	if got := readLog(); got != literal+enter {
		t.Fatalf("send with Enter: %q, want %q", got, literal+enter)
	}
	resetLog()
	c.ok("", "put", "send-test", "--allow-exec=false", "--", secret)
	if code, _, errText := c.call("", "send", "tmux:dev:0.1", id, "--force-echo"); code == 0 || !strings.Contains(errText, "send is disabled") {
		t.Fatalf("policy check: code=%d err=%q", code, errText)
	}
	assertNoSend()
	c.ok("", "put", "expired", "expired-password", "--ttl", "1ns")
	if code, _, errText := c.call("", "send", "tmux:dev:0.1", "expired"); code == 0 || !strings.Contains(errText, "has expired") {
		t.Fatalf("expiry check: code=%d err=%q", code, errText)
	}
	assertNoSend()
	seed := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	c.ok(seed, "put", "send-otp", "--secret-stdin", "--type", "totp")
	c.ok("", "send", "tmux:dev:0.1", "send-otp", "--enter=false")
	got := readLog()
	prefix := "send-keys\n-t\ndev:0.1\n-l\n--\n"
	if !strings.HasPrefix(got, prefix) || !strings.HasSuffix(got, "\n") {
		t.Fatalf("TOTP send arguments: %q", got)
	}
	code := strings.TrimSuffix(strings.TrimPrefix(got, prefix), "\n")
	if len(code) != 6 || strings.Trim(code, "0123456789") != "" || strings.Contains(got, seed) {
		t.Fatalf("TOTP send did not use a six-digit code: %q", got)
	}
}

func TestSendRejectsControlCharactersBeforeCallingTmux(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh is needed for the private tmux stub")
	}
	c := newTestCLI(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "tmux.log")
	stub := `#!/bin/sh
printf '%s\n' called >> "$AGSECRET_TEST_TMUX_LOG"
exit 42
`
	if err := os.WriteFile(filepath.Join(dir, "tmux"), []byte(stub), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("AGSECRET_TEST_TMUX_LOG", logPath)
	for _, tc := range []struct {
		name, control string
	}{
		{"lf", "\n"},
		{"cr", "\r"},
		{"tab", "\t"},
		{"interrupt", "\x03"},
		{"escape", "\x1b"},
		{"backspace", "\x08"},
		{"delete", "\x7f"},
		{"c1", "\u0085"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secret := "prefix" + tc.control + "suffix"
			name := "unsafe-" + tc.name
			c.ok("", "put", name, secret)
			for _, flags := range [][]string{nil, {"--force-echo"}, {"--force-echo", "--enter=false"}} {
				args := append([]string{"send", "tmux:dev:0.1", name}, flags...)
				code, out, errText := c.call("", args...)
				if code == 0 || out != "" || !strings.Contains(errText, "terminal control characters") || !strings.Contains(errText, "use agsecret exec") {
					t.Fatalf("unsafe send: flags=%v code=%d out=%q err=%q", flags, code, out, errText)
				}
				if strings.Contains(out+errText, secret) {
					t.Fatal("rejection disclosed the credential")
				}
				if _, err := os.Stat(logPath); !os.IsNotExist(err) {
					t.Fatalf("unsafe value reached tmux: %v", err)
				}
			}
		})
	}
}
