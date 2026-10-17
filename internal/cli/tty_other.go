//go:build !linux && !darwin && !dragonfly && !freebsd && !netbsd && !openbsd

package cli

import (
	"errors"
	"os"
	"os/exec"

	"golang.org/x/term"
)

func atPasswordPrompt(string) (bool, error) {
	return false, errors.New("send works only on Linux, macOS and BSD")
}

func detach(*exec.Cmd) {}

func signalGroup(p *os.Process, sig os.Signal) error { return p.Signal(sig) }

func readHidden(f *os.File) ([]byte, error) { return term.ReadPassword(int(f.Fd())) }
