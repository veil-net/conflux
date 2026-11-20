//go:build !windows

package ui

import (
	"os"

	"golang.org/x/sys/unix"
)

// echoesNewline: noEcho sets ECHONL, so the newline typed is echoed though nothing else is.
const echoesNewline = true

// openTerminal is the process's controlling terminal, whatever stdin is.
func openTerminal() (*os.File, error) { return os.OpenFile("/dev/tty", os.O_RDWR, 0) }

// noEcho turns the terminal's echo off, all but the newline's, with its line editing and its
// signals on, and returns what puts the terminal back as it was.
func noEcho(fd uintptr) (func(), error) {
	was, err := unix.IoctlGetTermios(int(fd), ioctlReadTermios)
	if err != nil {
		return nil, err
	}

	quiet := *was
	quiet.Lflag &^= unix.ECHO
	quiet.Lflag |= unix.ICANON | unix.ISIG | unix.ECHONL

	if err := unix.IoctlSetTermios(int(fd), ioctlWriteTermios, &quiet); err != nil {
		return nil, err
	}

	return func() { _ = unix.IoctlSetTermios(int(fd), ioctlWriteTermios, was) }, nil
}
