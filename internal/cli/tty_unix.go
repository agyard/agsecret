//go:build linux || darwin || dragonfly || freebsd || netbsd || openbsd

package cli

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// detach starts c in a new session without a controlling terminal, so the
// command cannot write to the terminal behind the output filter, for example
// through a password prompt on /dev/tty. In an agent's pseudo-terminal, such
// writes would reach the agent.
func detach(c *exec.Cmd) { c.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }

// signalGroup sends sig to the command and everything it started, as a
// terminal would for its foreground job.
func signalGroup(p *os.Process, sig os.Signal) error {
	return syscall.Kill(-p.Pid, sig.(syscall.Signal))
}

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

// readHidden reads a line with echo off. Unlike term.ReadPassword, it treats
// Ctrl-D on an empty line as the end of input instead of ignoring it.
func readHidden(f *os.File) ([]byte, error) {
	fd := int(f.Fd())
	old, err := unix.IoctlGetTermios(fd, ioctlGetTermios)
	if err != nil {
		return nil, err
	}
	quiet := *old
	quiet.Lflag = quiet.Lflag&^unix.ECHO | unix.ICANON | unix.ISIG
	quiet.Iflag |= unix.ICRNL
	if err := unix.IoctlSetTermios(fd, ioctlSetTermios, &quiet); err != nil {
		return nil, err
	}
	restore := func() { _ = unix.IoctlSetTermios(fd, ioctlSetTermios, old) }
	defer restore()
	// Turn echo back on before Ctrl-C ends the process.
	signals, done := make(chan os.Signal, 1), make(chan struct{})
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(signals)
	defer close(done)
	go func() {
		select {
		case sig := <-signals:
			restore()
			os.Exit(128 + int(sig.(syscall.Signal)))
		case <-done:
		}
	}()
	var line []byte
	b := make([]byte, 1)
	for {
		n, err := f.Read(b)
		if n == 1 && b[0] == '\n' || err == io.EOF && len(line) > 0 {
			return line, nil
		}
		line = append(line, b[:n]...)
		if err != nil {
			clear(line)
			return nil, err
		}
	}
}
