//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package ui

import "golang.org/x/sys/unix"

// The BSDs, macOS among them, spell the termios get-attributes ioctl TIOCGETA.
const ioctlReadTermios = unix.TIOCGETA
