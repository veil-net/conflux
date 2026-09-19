//go:build windows

package ui

import "golang.org/x/sys/windows"

// isTerminal asks the console driver, which is the Windows form of the same
// question: GetConsoleMode succeeds on a console handle and fails on everything
// else, a redirected file, a pipe and NUL among them.
//
// A console conflux was not given -- a mintty or an MSYS2 shell, which hand a named
// pipe to the program and draw the terminal themselves -- reads as no terminal, and
// a refusal naming the two flags is the right answer there anyway: the prompt could
// not have been answered.
func isTerminal(fd uintptr) bool {
	var mode uint32

	return windows.GetConsoleMode(windows.Handle(fd), &mode) == nil
}
