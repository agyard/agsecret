//go:build linux

package cli

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestPutTerminalHelper(t *testing.T) {
	if os.Getenv("AGSECRET_PUT_TERMINAL_HELPER") != "1" {
		return
	}
	args := os.Args[slices.Index(os.Args, "--")+1:]
	os.Exit(Execute(args, os.Stdin, os.Stdout, os.Stderr))
}

func TestPutTerminalInput(t *testing.T) {
	c := newTestCLI(t)
	seed := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	c.put("kept-plain", "old-user", "--type", "plain")
	c.put("kept-totp", seed, "--type", "totp")
	c.put("to-password", "old-user", "--type", "plain")
	c.put("to-plain", "old-password")
	c.put("limited", "limited-password", "--access", "none")
	master, path := testPTY(t)
	terminal, err := os.OpenFile(path, os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer terminal.Close()
	if err := unix.SetNonblock(master, true); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	// All cases reuse one terminal, so a plain prompt followed by a password
	// prompt must change echo correctly and leave no mode changes behind.
	for _, tc := range []struct {
		name, kind, value string
		flags             []string
		raw               bool
		errorText         string
		concurrentType    string
	}{
		{name: "new-plain", kind: "plain", value: "visible-user", flags: []string{"--type", "plain"}},
		{name: "new-password", kind: "password", value: "hidden-password"},
		{name: "kept-plain", kind: "plain", value: "replacement-user"},
		{name: "kept-totp", kind: "totp", value: seed},
		{name: "to-password", kind: "password", value: "converted-password", flags: []string{"--type", "password"}},
		{name: "to-plain", kind: "plain", value: "converted-user", flags: []string{"--type", "plain"}},
		{name: "stdin-plain", kind: "plain", value: "stdin-user", flags: []string{"--type", "plain", "--stdin"}, raw: true},
		{name: "stdin-password", kind: "password", value: "stdin-password-value", flags: []string{"--stdin"}},
		{name: "limited", kind: "password", value: "limited-password", flags: []string{"--access", "exec"}},
		{name: "concurrent-password", kind: "password", value: "hidden-concurrent-password", concurrentType: "plain"},
		{name: "concurrent-plain", kind: "plain", value: "visible-concurrent-user", flags: []string{"--type", "plain"}, concurrentType: "password"},
		{name: "invalid-type", flags: []string{"--type", "typo"}, errorText: "type"},
		{name: "plain-policy", flags: []string{"--type", "plain", "--uses", "1"}, errorText: "plain"},
		{name: "kept-plain", flags: []string{"--ttl", "1h"}, errorText: "plain"},
	} {
		t.Run(tc.name+"/"+strings.Join(tc.flags, " "), func(t *testing.T) {
			setPTYMode(t, master, !tc.raw, !tc.raw)
			before, err := unix.IoctlGetTermios(master, unix.TCGETS)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			args := []string{"-test.run=^TestPutTerminalHelper$", "--", "--db", c.db, "--pass-file", c.pass, "put", tc.name}
			cmd := exec.CommandContext(ctx, executable, append(args, tc.flags...)...)
			cmd.Env = append(os.Environ(), "AGSECRET_PUT_TERMINAL_HELPER=1")
			cmd.Stdin, cmd.Stdout, cmd.Stderr = terminal, terminal, terminal
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			waited := false
			defer func() {
				cancel()
				if !waited {
					_ = cmd.Wait()
				}
			}()

			var output strings.Builder
			readOutput := func(timeout int) bool {
				t.Helper()
				fds := []unix.PollFd{{Fd: int32(master), Events: unix.POLLIN}}
				n, err := unix.Poll(fds, timeout)
				if errors.Is(err, unix.EINTR) {
					return true
				}
				if err != nil {
					t.Fatal(err)
				}
				if n == 0 {
					return false
				}
				var b [4096]byte
				n, err = unix.Read(master, b[:])
				if errors.Is(err, unix.EAGAIN) {
					return false
				}
				if err != nil {
					t.Fatal(err)
				}
				output.Write(b[:n])
				if output.Len() > 64*1024 {
					t.Fatal("unexpectedly large terminal output")
				}
				return n > 0
			}

			if tc.errorText == "" {
				label := tc.kind + "; hidden"
				if tc.kind == "plain" {
					label = "plain; visible, not secret"
				} else if tc.kind == "totp" {
					label = "totp seed; hidden"
				}
				prompt := tc.name + " [" + label + "]: "
				for !strings.Contains(output.String(), prompt) && ctx.Err() == nil {
					readOutput(20)
				}
				if !strings.Contains(output.String(), prompt) {
					t.Fatalf("missing prompt %q: %q", prompt, output.String())
				}
				if tc.concurrentType != "" {
					c.put(tc.name, "concurrent-value", "--type", tc.concurrentType)
				}
				// Echo must be set before displaying the prompt, so immediate
				// input cannot inherit the wrong mode.
				state, err := unix.IoctlGetTermios(master, unix.TCGETS)
				if err != nil {
					t.Fatal(err)
				}
				if (state.Lflag&unix.ECHO != 0) != (tc.kind == "plain") || state.Lflag&unix.ICANON == 0 {
					t.Fatalf("wrong input mode for %s: flags=%#x", tc.kind, state.Lflag)
				}
				if _, err := unix.Write(master, []byte(tc.value+"\n")); err != nil {
					t.Fatal(err)
				}
			}
			err = cmd.Wait()
			waited = true
			for readOutput(0) {
			}
			if ctx.Err() != nil {
				t.Fatalf("put did not finish without further input: %q", output.String())
			}
			if tc.errorText != "" {
				if err == nil || !strings.Contains(output.String(), tc.errorText) || strings.Contains(output.String(), "]: ") {
					t.Fatalf("expected rejection before prompting: err=%v output=%q", err, output.String())
				}
			} else {
				if err != nil {
					t.Fatalf("put failed: %v output=%q", err, output.String())
				}
				if strings.Contains(output.String(), tc.value) != (tc.kind == "plain") {
					t.Fatalf("unexpected echo for %s: %q", tc.kind, output.String())
				}
				if r := c.record("view", tc.name); r["type"] != tc.kind {
					t.Fatalf("stored type: %v", r)
				}
			}
			after, err := unix.IoctlGetTermios(master, unix.TCGETS)
			if err != nil {
				t.Fatal(err)
			}
			if after.Lflag != before.Lflag || after.Iflag != before.Iflag {
				t.Fatalf("terminal mode not restored: before=%#v after=%#v", before, after)
			}
		})
	}
}
