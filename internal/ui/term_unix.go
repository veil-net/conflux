//go:build !windows

package ui

import "golang.org/x/sys/unix"

// isTerminal asks the line discipline, which only a terminal has. A mode check would
// also pass /dev/null, which is a character device and answers every prompt with EOF.
func isTerminal(fd uintptr) bool {
	_, err := unix.IoctlGetTermios(int(fd), ioctlReadTermios)

	return err == nil
}
