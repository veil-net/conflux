package config

import (
	"fmt"
	"io"
	"os"
)

// ReadUntrusted reads a file in a directory another account can write -- anchord's own
// anchor directory, which belongs to the account it runs as -- without trusting the name:
// opened as OpenUntrusted says, and read only when Untrusted takes it, it has no second name,
// and it is no more than max bytes. So the supervisor or an administrator reading it cannot
// be turned into reading, or waiting on, whatever the account pointed the name at.
func ReadUntrusted(path string, max int64) ([]byte, error) {
	f, err := os.OpenFile(path, OpenUntrusted, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}

	if !Untrusted(fi, max) || !oneName(f) {
		return nil, fmt.Errorf("%s is not a file conflux reads", path)
	}

	return io.ReadAll(io.LimitReader(f, max))
}
