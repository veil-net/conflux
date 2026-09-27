package ui

import "golang.org/x/sys/windows"

// isTerminal reports whether the handle is a console, which is what a person types at.
func isTerminal(fd uintptr) bool {
	var mode uint32

	return windows.GetConsoleMode(windows.Handle(fd), &mode) == nil
}
