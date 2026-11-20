//go:build !windows

package config

import (
	"fmt"
	"io"
	"os"

	"github.com/veil-net/conflux/internal/paths"
)

// ReadUntrusted reads a file in a directory another account can write -- anchord's own
// anchor directory, which belongs to the account it runs as -- without trusting the name:
// never through a symlink, never blocking on a FIFO, only a regular file with no second
// name, and no more than max bytes. So root reading it cannot be turned into root reading,
// or waiting on, whatever the account pointed the name at.
func ReadUntrusted(path string, max int64) ([]byte, error) {
	f, err := os.OpenFile(path, paths.OpenUntrusted, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}

	if !paths.PlainFile(fi, max) {
		return nil, fmt.Errorf("%s is not a file conflux reads", path)
	}

	return io.ReadAll(io.LimitReader(f, max))
}
