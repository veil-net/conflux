//go:build unix && !linux

package logfile

import (
	"os"

	"golang.org/x/sys/unix"
)

func standardStreams(f *os.File) {
	_ = unix.Dup2(int(f.Fd()), 1)
	_ = unix.Dup2(int(f.Fd()), 2)
}

// unplace is nothing here: a file the standard streams name can be renamed, and they follow it
// to .1 until the log is placed over them again.
func unplace() {}
