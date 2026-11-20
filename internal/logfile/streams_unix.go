//go:build unix

package logfile

import (
	"os"

	"golang.org/x/sys/unix"
)

// standardStreams places f over the process's standard output and error, where the runtime
// writes a panic. x/sys/unix's Dup2 is dup3 with no flags on Linux, whose newer ports have no
// dup2.
func standardStreams(f *os.File) {
	_ = unix.Dup2(int(f.Fd()), 1)
	_ = unix.Dup2(int(f.Fd()), 2)
}

// unplace is nothing here: a file the standard streams name can be renamed, and they follow it
// to .1 until the log is placed over them again.
func unplace() {}
