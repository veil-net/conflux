package config

import (
	"fmt"
	"io"
	"os"
)

// ReadUntrusted reads a file in a directory anchord's own account can write, refusing
// anything but a regular file of no more than max bytes.
func ReadUntrusted(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}

	if !fi.Mode().IsRegular() || fi.Size() > max {
		return nil, fmt.Errorf("%s is not a file conflux reads", path)
	}

	return io.ReadAll(io.LimitReader(f, max))
}
