//go:build !linux && !darwin && !dragonfly && !freebsd && !netbsd && !openbsd && !windows

package cli

import (
	"os"

	"golang.org/x/term"
)

func readTerminal(f *os.File, echo bool, prompt func() error) ([]byte, error) {
	if err := prompt(); err != nil {
		return nil, err
	}
	if echo {
		return readTerminalLine(f)
	}
	return term.ReadPassword(int(f.Fd()))
}
