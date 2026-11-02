package logfile

import (
	"os"

	"golang.org/x/sys/unix"
)

func standardStreams(f *os.File) {
	_ = unix.Dup3(int(f.Fd()), 1, 0)
	_ = unix.Dup3(int(f.Fd()), 2, 0)
}
