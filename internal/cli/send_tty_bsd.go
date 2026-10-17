//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package cli

import "golang.org/x/sys/unix"

const ioctlGetTermios = unix.TIOCGETA
