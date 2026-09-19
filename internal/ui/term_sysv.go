//go:build aix || linux || solaris || zos

package ui

import "golang.org/x/sys/unix"

// Linux and the System V line spell it TCGETS.
const ioctlReadTermios = unix.TCGETS
