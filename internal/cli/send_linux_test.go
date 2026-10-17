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

func setPTYMode(t *testing.T, master int, echo, canonical bool) {
	t.Helper()
	state, err := unix.IoctlGetTermios(master, unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	state.Lflag &^= unix.ECHO | unix.ICANON
	if echo {
		state.Lflag |= unix.ECHO
	}
	if canonical {
		state.Lflag |= unix.ICANON
	}
	if err := unix.IoctlSetTermios(master, unix.TCSETS, state); err != nil {
		t.Fatal(err)
	}
}

func TestPasswordPromptNeedsNoEchoAndLineInput(t *testing.T) {
	master, path := testPTY(t)
	for _, tc := range []struct{ echo, canonical, prompt bool }{
		{true, true, false},   // ordinary cooked terminal
		{false, false, false}, // shell line editor or REPL
		{false, true, true},   // getpass-style password prompt
	} {
		setPTYMode(t, master, tc.echo, tc.canonical)
		got, err := atPasswordPrompt(path)
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.prompt {
			t.Fatalf("echo=%v canonical=%v: prompt=%v", tc.echo, tc.canonical, got)
		}
	}
	if _, err := atPasswordPrompt(t.TempDir() + "/not-a-tty"); err == nil {
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
    [ "$#" -eq 3 ] && exit 0  # target check
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
	id := c.put("send-test", secret)["id"].(string)
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
			t.Fatalf("tmux typed a refused secret: %q", got)
		}
	}
	literal := "send-keys\n-t\ndev:0.1\n-l\n--\n" + secret + "\n"
	enter := "send-keys\n-t\ndev:0.1\nEnter\n"
	setPTYMode(t, master, false, false)
	if code, out, errText := c.call("", "send", "tmux:dev:0.1", id); code == 0 || out != "" || !strings.Contains(errText, "not waiting at a password prompt") {
		t.Fatalf("echo check: code=%d out=%q err=%q", code, out, errText)
	}
	assertNoSend()
	if out, errText := c.ok("", "send", "tmux:dev:0.1", id, "--dangerously-skip-check", "--no-enter"); out != "" || errText != "" {
		t.Fatalf("send should be quiet: out=%q err=%q", out, errText)
	}
	if got := readLog(); got != literal {
		t.Fatalf("literal send: %q, want %q", got, literal)
	}
	resetLog()
	setPTYMode(t, master, false, true)
	c.ok("", "send", "tmux:dev:0.1", "send-test")
	if got := readLog(); got != literal+enter {
		t.Fatalf("send with Enter: %q, want %q", got, literal+enter)
	}
	resetLog()
	c.put("send-test", secret, "--access", "get")
	if code, _, errText := c.call("", "send", "tmux:dev:0.1", id, "--dangerously-skip-check"); code == 0 || !strings.Contains(errText, "send is turned off") {
		t.Fatalf("policy check: code=%d err=%q", code, errText)
	}
	assertNoSend()
	c.put("expired", "expired-password", "--ttl", "1ns")
	if code, _, errText := c.call("", "send", "tmux:dev:0.1", "expired"); code == 0 || !strings.Contains(errText, "has expired") {
		t.Fatalf("expiry check: code=%d err=%q", code, errText)
	}
	assertNoSend()
	seed := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	c.put("send-otp", seed, "--type", "totp")
	c.ok("", "send", "tmux:dev:0.1", "send-otp", "--no-enter")
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
			// put drops one final newline, so control characters go inside.
			secret := "prefix" + tc.control + "suffix"
			name := "unsafe-" + tc.name
			c.put(name, secret)
			for _, flags := range [][]string{nil, {"--dangerously-skip-check"}, {"--dangerously-skip-check", "--no-enter"}} {
				args := append([]string{"send", "tmux:dev:0.1", name}, flags...)
				code, out, errText := c.call("", args...)
				if code == 0 || out != "" || !strings.Contains(errText, "contains control characters") || !strings.Contains(errText, "use agsecret exec") {
					t.Fatalf("unsafe send: flags=%v code=%d out=%q err=%q", flags, code, out, errText)
				}
				if strings.Contains(out+errText, secret) {
					t.Fatal("rejection disclosed the secret")
				}
				if _, err := os.Stat(logPath); !os.IsNotExist(err) {
					t.Fatalf("unsafe value reached tmux: %v", err)
				}
			}
		})
	}
}

// In an agent's pseudo-terminal, anything written to the terminal reaches
// the agent unfiltered, so the command must not hold the terminal at all.
func TestExecCommandCannotWriteToTheTerminal(t *testing.T) {
	master, ttyPath := testPTY(t)
	tty, err := os.OpenFile(ttyPath, os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer tty.Close()
	c := newTestCLI(t)
	id := c.put("api", "terminal-secret")["id"].(string)
	t.Setenv("T", id)
	var out, errOut strings.Builder
	script := `import os
for open_fd in (lambda: 0, lambda: os.open("/dev/tty", os.O_WRONLY)):
    try:
        os.write(open_fd(), os.environ["T"].encode())
    except OSError:
        pass`
	code := Execute([]string{"--db", c.db, "--pass-file", c.pass, "exec", "--", "python3", "-I", "-c", script}, tty, &out, &errOut)
	if code != 0 {
		t.Skipf("python3 unavailable: %d %s", code, errOut.String())
	}
	if err := unix.SetNonblock(master, true); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, _ := unix.Read(master, buf)
	if strings.Contains(string(buf[:max(n, 0)]), "terminal-secret") {
		t.Fatal("the command wrote the secret to the terminal")
	}
}
