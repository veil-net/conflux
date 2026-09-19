//go:build unix

package ui

import "golang.org/x/sys/unix"

// isTerminal asks the terminal driver, which is the only thing that knows.
//
// A descriptor that answers the termios get-attributes ioctl is a terminal and
// nothing else is: a pipe, a regular file and /dev/null all come back ENOTTY. The
// ioctl has two spellings and neither is portable, so the constant comes from the
// build-tagged file for this platform's line.
func isTerminal(fd uintptr) bool {
	_, err := unix.IoctlGetTermios(int(fd), ioctlReadTermios)

	return err == nil
}
