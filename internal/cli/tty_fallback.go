//go:build !linux && !darwin && !dragonfly && !freebsd && !netbsd && !openbsd && !windows

package cli

import (
	"os"

	"golang.org/x/term"
)

func readTerminal(f *os.File, echo bool, read func() ([]byte, error)) ([]byte, error) {
	if !echo {
		state, err := term.MakeRaw(int(f.Fd()))
		if err != nil {
			return nil, err
		}
		defer term.Restore(int(f.Fd()), state)
	}
	return read()
}
