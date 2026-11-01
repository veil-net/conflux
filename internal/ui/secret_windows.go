package ui

import (
	"os"

	"golang.org/x/sys/windows"
)

// echoesNewline: a console with its echo off echoes no newline either.
const echoesNewline = false

// openTerminal is the console's input, whatever stdin is.
func openTerminal() (*os.File, error) { return os.OpenFile("CONIN$", os.O_RDWR, 0) }

// noEcho turns the console's echo off, keeping its line input and Ctrl-C, and returns what
// turns it back on.
func noEcho(fd uintptr) (func(), error) {
	h := windows.Handle(fd)

	var was uint32
	if err := windows.GetConsoleMode(h, &was); err != nil {
		return nil, err
	}

	quiet := was&^windows.ENABLE_ECHO_INPUT | windows.ENABLE_LINE_INPUT | windows.ENABLE_PROCESSED_INPUT
	if err := windows.SetConsoleMode(h, quiet); err != nil {
		return nil, err
	}

	return func() { _ = windows.SetConsoleMode(h, was) }, nil
}
