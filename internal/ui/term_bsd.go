//go:build darwin || freebsd || openbsd

package ui

import "golang.org/x/sys/unix"

const ioctlReadTermios = unix.TIOCGETA
