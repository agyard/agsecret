//go:build !linux && !darwin && !dragonfly && !freebsd && !netbsd && !openbsd

package cli

import "errors"

func atPasswordPrompt(string) (bool, error) {
	return false, errors.New("send works only on Linux, macOS and BSD")
}
