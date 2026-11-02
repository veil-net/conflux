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
