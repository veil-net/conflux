//go:build !windows

package ui

import (
	"os"

	"golang.org/x/sys/unix"
)

// echoesNewline: noEcho keeps ECHONL, so the newline typed is echoed when nothing else is.
const echoesNewline = true

// openTerminal is the process's controlling terminal, whatever stdin is.
func openTerminal() (*os.File, error) { return os.OpenFile("/dev/tty", os.O_RDWR, 0) }

// noEcho turns the terminal's echo off, keeping its line editing and its signals, and returns
// what turns it back on.
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
