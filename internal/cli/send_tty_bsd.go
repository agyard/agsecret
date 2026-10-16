//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

func targetEchoEnabled(path string) (bool, error) {
	if !strings.HasPrefix(path, "/dev/") {
		return false, errors.New("tmux pane did not return a device TTY path")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOCTTY, 0)
	if err != nil {
		return false, fmt.Errorf("cannot open target pane TTY: %w", err)
	}
	defer f.Close()
	state, err := unix.IoctlGetTermios(int(f.Fd()), unix.TIOCGETA)
	if err != nil {
		return false, fmt.Errorf("cannot inspect target pane TTY: %w", err)
	}
	return state.Lflag&unix.ECHO != 0, nil
}
