//go:build !windows

package config

import (
	"fmt"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// ReadUntrusted reads a file in a directory another account can write -- anchord's own
// anchor directory, which belongs to the account it runs as -- without trusting the name:
// never through a symlink, never blocking on a FIFO, only a regular file with no second
// name, and no more than max bytes. So root reading it cannot be turned into root reading,
// or waiting on, whatever the account pointed the name at.
func ReadUntrusted(path string, max int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}

	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.Mode().IsRegular() || !ok || st.Nlink != 1 || fi.Size() > max {
		return nil, fmt.Errorf("%s is not a file conflux reads", path)
	}

	return io.ReadAll(io.LimitReader(f, max))
}
