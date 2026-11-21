package paths

import (
	"fmt"
	"io"
	"os"
)

// ReadUntrusted reads a file in a directory another account can write -- anchord's own anchor
// directory, which belongs to the account it runs as -- without trusting the name: opened as
// OpenUntrusted opens it, never through a symlink (on Windows, any reparse point) and never blocking
// on a FIFO, and read only as readUntrusted reads it. So root (SYSTEM) reading it cannot be turned
// into reading, or waiting on, whatever the account pointed the name at.
func ReadUntrusted(path string, max int64) ([]byte, error) {
	f, err := os.OpenFile(path, OpenUntrusted, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return readUntrusted(f, path, max)
}

// readUntrusted is what f, opened as OpenUntrusted opens the file at path, holds, read only where it
// is a plain file (PlainFile) -- on Unix with no second name -- of no more than max bytes.
func readUntrusted(f *os.File, path string, max int64) ([]byte, error) {
	if fi, err := f.Stat(); err != nil || !PlainFile(fi, max) {
		return nil, fmt.Errorf("%s is not a plain file of at most %d bytes, so conflux does not read it", path, max)
	}

	b, err := io.ReadAll(io.LimitReader(f, max))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	return b, nil
}
