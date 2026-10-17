//go:build linux || darwin || dragonfly || freebsd || netbsd || openbsd

package cli

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// atPasswordPrompt reports whether a terminal has echo off and canonical line
// input on, as getpass-style prompts do. Shells and REPLs also turn echo off,
// but they read raw keys and echo them themselves.
func atPasswordPrompt(path string) (bool, error) {
	if !strings.HasPrefix(path, "/dev/") {
		return false, fmt.Errorf("tmux reported %q as the pane's terminal", path)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOCTTY, 0)
	if err != nil {
		return false, fmt.Errorf("cannot open the pane's terminal: %w", err)
	}
	defer f.Close()
	state, err := unix.IoctlGetTermios(int(f.Fd()), ioctlGetTermios)
	if err != nil {
		return false, fmt.Errorf("cannot inspect the pane's terminal: %w", err)
	}
	return state.Lflag&unix.ECHO == 0 && state.Lflag&unix.ICANON != 0, nil
}
