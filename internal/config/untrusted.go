package config

import (
	"fmt"
	"io"
	"os"

	"github.com/veil-net/conflux/internal/paths"
)

// ReadUntrusted reads a file in a directory another account can write -- anchord's own
// anchor directory, which belongs to the account it runs as -- without trusting the name:
// opened as paths.OpenUntrusted opens it, never through a symlink (on Windows, any reparse
// point) and never blocking on a FIFO, and read only as paths.PlainFile allows, a regular
// file -- on Unix with no second name -- of no more than max bytes. So root (SYSTEM) reading
// it cannot be turned into reading, or waiting on, whatever the account pointed the name at.
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
