package cli

import (
	"os"
	"os/signal"

	"golang.org/x/sys/windows"
)

func readTerminal(f *os.File, echo bool, read func() ([]byte, error)) ([]byte, error) {
	handle := windows.Handle(f.Fd())
	var old uint32
	if err := windows.GetConsoleMode(handle, &old); err != nil {
		return nil, err
	}
	mode := old &^ (windows.ENABLE_ECHO_INPUT | windows.ENABLE_VIRTUAL_TERMINAL_INPUT)
	mode |= windows.ENABLE_LINE_INPUT | windows.ENABLE_PROCESSED_INPUT
	if echo {
		mode |= windows.ENABLE_ECHO_INPUT
	} else {
		mode &^= windows.ENABLE_LINE_INPUT | windows.ENABLE_PROCESSED_INPUT
	}
	if err := windows.SetConsoleMode(handle, mode); err != nil {
		return nil, err
	}
	restore := func() { _ = windows.SetConsoleMode(handle, old) }
	defer restore()
	signals, done := make(chan os.Signal, 1), make(chan struct{})
	signal.Notify(signals, os.Interrupt)
	defer signal.Stop(signals)
	defer close(done)
	go func() {
		select {
		case <-signals:
			restore()
			os.Exit(130)
		case <-done:
		}
	}()
	return read()
}
