//go:build !linux && !darwin && !dragonfly && !freebsd && !netbsd && !openbsd

package cli

import "errors"

func targetEchoEnabled(string) (bool, error) {
	return false, errors.New("send tmux requires a platform with supported TTY echo inspection")
}
